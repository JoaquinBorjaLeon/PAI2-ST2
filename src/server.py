"""
Servidor SSL/TLS 1.3 - PAI2: Comunicación Segura
Universidad Pública - Sistema de Registro, Autenticación y Mensajería

Requisitos cubiertos:
  - Canal seguro SSL/TLS 1.3 con Cipher Suites robustos
  - Registro e inicio de sesión de usuarios
  - Almacenamiento seguro de credenciales (PBKDF2-HMAC-SHA256 + salt)
  - Protección contra fuerza bruta en login
  - Envío de mensajes (máx. 144 caracteres) con persistencia
  - Soporte para ~300 conexiones concurrentes (ThreadPoolExecutor)
  - Base de datos SQLite con integridad referencial
  - Usuarios pre-registrados
"""

import socket
import ssl
import threading
import sqlite3
import json
import argparse
import hashlib
import hmac
import os
import struct
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# ============================================================
# CONFIGURACIÓN
# ============================================================
HOST = '0.0.0.0'
PORT = 8443
CERTFILE = 'cert.pem'
KEYFILE = 'key.pem'
DB_FILE = 'pai2.db'
MAX_WORKERS = 300           # Soporte para ~300 empleados concurrentes
MAX_LOGIN_ATTEMPTS = 5      # Intentos máximos antes de bloqueo
LOCKOUT_SECONDS = 300       # 5 minutos de bloqueo por fuerza bruta
MAX_MESSAGE_LENGTH = 144    # Longitud máxima de mensaje
PBKDF2_ITERATIONS = 100000  # Iteraciones para derivación de clave
PLAIN_PORT = 8080           # Puerto alternativo para benchmark sin TLS

TLS13_CIPHERS = [
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_AES_128_GCM_SHA256',
]

# Lock para operaciones de base de datos (thread-safety con SQLite)
db_lock = threading.Lock()


# ============================================================
# PROTOCOLO DE COMUNICACIÓN (prefijo de longitud + JSON)
# ============================================================
def send_msg(sock, data):
    """Envía un mensaje JSON con prefijo de longitud (4 bytes big-endian)."""
    json_data = json.dumps(data).encode('utf-8')
    length_prefix = struct.pack('!I', len(json_data))
    sock.sendall(length_prefix + json_data)


def recv_msg(sock):
    """Recibe un mensaje JSON con prefijo de longitud."""
    raw_length = _recv_exact(sock, 4)
    if not raw_length:
        return None
    length = struct.unpack('!I', raw_length)[0]
    raw_data = _recv_exact(sock, length)
    if not raw_data:
        return None
    return json.loads(raw_data.decode('utf-8'))


def _recv_exact(sock, n):
    """Recibe exactamente n bytes del socket."""
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


# ============================================================
# BASE DE DATOS
# ============================================================
def get_db():
    """Crea una nueva conexión a la base de datos con WAL y FK."""
    conn = sqlite3.connect(DB_FILE)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row
    return conn


def init_database():
    """Inicializa tablas y carga usuarios pre-registrados."""
    conn = get_db()
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            message_text TEXT NOT NULL CHECK(length(message_text) <= 144),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            username TEXT PRIMARY KEY,
            failed_count INTEGER DEFAULT 0,
            last_attempt TIMESTAMP
        )
    ''')

    # Usuarios pre-registrados (acceden sin necesidad de registrarse)
    preregistered = [
        ('admin',    '1234'),
        ('usuario1', '1234'),
        ('usuario2', '1234'),
        ('usuario3', '1234'),
        ('usuario4', '1234'),
        ('usuario5', '1234'),
    ]
    for uname, pwd in preregistered:
        salt = os.urandom(32).hex()
        pw_hash = hashlib.pbkdf2_hmac(
            'sha256', pwd.encode('utf-8'),
            bytes.fromhex(salt), PBKDF2_ITERATIONS
        ).hex()
        try:
            c.execute(
                'INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)',
                (uname, pw_hash, salt)
            )
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    conn.close()
    print("[*] Base de datos inicializada.")


# ============================================================
# SEGURIDAD: hashing y protección contra fuerza bruta
# ============================================================
def hash_password(password, salt=None):
    """PBKDF2-HMAC-SHA256 con salt aleatorio de 32 bytes."""
    if salt is None:
        salt = os.urandom(32).hex()
    pw_hash = hashlib.pbkdf2_hmac(
        'sha256', password.encode('utf-8'),
        bytes.fromhex(salt), PBKDF2_ITERATIONS
    ).hex()
    return pw_hash, salt


def verify_password(password, stored_hash, salt):
    """Verificación en tiempo constante para evitar ataques de timing."""
    pw_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(pw_hash, stored_hash)


def check_brute_force(username):
    """Devuelve (permitido, mensaje_error)."""
    with db_lock:
        conn = get_db()
        row = conn.execute(
            'SELECT failed_count, last_attempt FROM login_attempts WHERE username = ?',
            (username,)
        ).fetchone()
        conn.close()

    if row and row['failed_count'] >= MAX_LOGIN_ATTEMPTS:
        last = datetime.fromisoformat(row['last_attempt'])
        elapsed = (datetime.now() - last).total_seconds()
        if elapsed < LOCKOUT_SECONDS:
            remaining = int(LOCKOUT_SECONDS - elapsed)
            return False, f"Cuenta bloqueada por intentos fallidos. Reintente en {remaining}s."
        else:
            _reset_attempts(username)
    return True, ""


def _record_failed(username):
    now = datetime.now().isoformat()
    with db_lock:
        conn = get_db()
        conn.execute('''
            INSERT INTO login_attempts (username, failed_count, last_attempt)
            VALUES (?, 1, ?)
            ON CONFLICT(username) DO UPDATE SET
                failed_count = failed_count + 1,
                last_attempt = ?
        ''', (username, now, now))
        conn.commit()
        conn.close()


def _reset_attempts(username):
    with db_lock:
        conn = get_db()
        conn.execute('DELETE FROM login_attempts WHERE username = ?', (username,))
        conn.commit()
        conn.close()


# ============================================================
# MANEJADORES DE ACCIONES
# ============================================================
def handle_register(req):
    username = req.get('username', '').strip()
    password = req.get('password', '').strip()

    if not username or not password:
        return {"status": "error", "message": "Nombre de usuario y contraseña son obligatorios."}

    pw_hash, salt = hash_password(password)
    with db_lock:
        conn = get_db()
        try:
            conn.execute(
                'INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)',
                (username, pw_hash, salt)
            )
            conn.commit()
            print(f"[+] Usuario registrado: {username}")
            return {"status": "ok", "message": "Usuario registrado exitosamente."}
        except sqlite3.IntegrityError:
            return {"status": "error", "message": "El nombre de usuario ya está registrado."}
        finally:
            conn.close()


def handle_login(req):
    """Retorna (respuesta, username|None, user_id|None)."""
    username = req.get('username', '').strip()
    password = req.get('password', '').strip()

    if not username or not password:
        return {"status": "error", "message": "Nombre de usuario y contraseña son obligatorios."}, None, None

    allowed, msg = check_brute_force(username)
    if not allowed:
        return {"status": "error", "message": msg}, None, None

    with db_lock:
        conn = get_db()
        user = conn.execute(
            'SELECT id, password_hash, salt FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()

    if user is None:
        return {"status": "error", "message": "Credenciales incorrectas."}, None, None

    if not verify_password(password, user['password_hash'], user['salt']):
        _record_failed(username)
        return {"status": "error", "message": "Credenciales incorrectas."}, None, None

    _reset_attempts(username)
    print(f"[+] Login exitoso: {username}")
    return {"status": "ok", "message": "Inicio de sesión exitoso."}, username, user['id']


def handle_send_message(req, username, user_id):
    if not username:
        return {"status": "error", "message": "Debe iniciar sesión para enviar mensajes."}

    text = req.get('message', '').strip()
    if not text:
        return {"status": "error", "message": "El mensaje no puede estar vacío."}
    if len(text) > MAX_MESSAGE_LENGTH:
        return {"status": "error", "message": f"El mensaje no puede superar {MAX_MESSAGE_LENGTH} caracteres."}

    with db_lock:
        conn = get_db()
        conn.execute(
            'INSERT INTO messages (user_id, message_text) VALUES (?, ?)',
            (user_id, text)
        )
        total = conn.execute(
            'SELECT COUNT(*) AS n FROM messages WHERE user_id = ?', (user_id,)
        ).fetchone()['n']
        conn.commit()
        conn.close()

    print(f"[MSG] {username}: {text}")
    return {
        "status": "ok",
        "message": f"Mensaje enviado y recibido correctamente. Total mensajes enviados: {total}"
    }


def handle_logout(username):
    if username:
        print(f"[-] Sesión cerrada: {username}")
        return {"status": "ok", "message": f"Sesión de '{username}' cerrada correctamente."}
    return {"status": "error", "message": "No hay sesión activa."}


def handle_stats(req, username, user_id):
    if not username:
        return {"status": "error", "message": "Debe iniciar sesión."}
    with db_lock:
        conn = get_db()
        rows = conn.execute('''
            SELECT DATE(created_at) AS fecha, COUNT(*) AS cantidad
            FROM messages WHERE user_id = ?
            GROUP BY DATE(created_at)
            ORDER BY fecha DESC
        ''', (user_id,)).fetchall()
        total = conn.execute(
            'SELECT COUNT(*) AS n FROM messages WHERE user_id = ?', (user_id,)
        ).fetchone()['n']
        conn.close()

    detail = "\n".join(f"  {r['fecha']}: {r['cantidad']} mensaje(s)" for r in rows) if rows else "  Sin mensajes."
    return {
        "status": "ok",
        "message": f"Total mensajes: {total}\nHistorial por fecha:\n{detail}"
    }


# ============================================================
# MANEJO DE CONEXIÓN POR CLIENTE
# ============================================================
def handle_client(conn, addr):
    print(f"[*] Conexión con: {addr}")
    user = None
    uid = None

    try:
        while True:
            request = recv_msg(conn)
            if request is None:
                break

            action = request.get('action', '')

            if action == 'register':
                response = handle_register(request)
            elif action == 'login':
                if user:
                    response = {"status": "error", "message": "Ya hay una sesión activa. Cierre sesión primero."}
                else:
                    response, user, uid = handle_login(request)
            elif action == 'send_message':
                response = handle_send_message(request, user, uid)
            elif action == 'logout':
                response = handle_logout(user)
                user, uid = None, None
            elif action == 'stats':
                response = handle_stats(request, user, uid)
            else:
                response = {"status": "error", "message": "Acción no reconocida."}

            send_msg(conn, response)

    except (ConnectionResetError, BrokenPipeError, ssl.SSLError) as e:
        print(f"[!] Conexión perdida {addr}: {e}")
    except Exception as e:
        print(f"[!] Error {addr}: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass
        if user:
            print(f"[-] {user} desconectado ({addr})")
        print(f"[*] Conexión cerrada: {addr}")


def _create_tls_context():
    """Construye un contexto TLS 1.3 endurecido para el servidor."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    # Desactivar compresión TLS reduce superficie ante ataques tipo CRIME.
    if hasattr(ssl, 'OP_NO_COMPRESSION'):
        ctx.options |= ssl.OP_NO_COMPRESSION

    # En OpenSSL recientes, se puede fijar explícitamente el conjunto TLS 1.3.
    if hasattr(ctx, 'set_ciphersuites'):
        try:
            ctx.set_ciphersuites(':'.join(TLS13_CIPHERS))
        except (ssl.SSLError, ValueError) as e:
            print(f"[!] Aviso: no se pudo fijar ciphersuites TLS 1.3 explícitas: {e}")

    return ctx


def _create_listen_socket(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(MAX_WORKERS)
    return server_socket


def _run_accept_loop(server_socket, tls_ctx=None):
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        try:
            while True:
                client_sock, addr = server_socket.accept()
                if tls_ctx is None:
                    print(f"[+] TCP desde {addr} | Transporte: PLAINTEXT")
                    pool.submit(handle_client, client_sock, addr)
                    continue

                try:
                    ssl_conn = tls_ctx.wrap_socket(client_sock, server_side=True)
                    negotiated_version = ssl_conn.version()
                    ci = ssl_conn.cipher()
                    print(f"[+] SSL desde {addr} | Cipher: {ci[0]} | Proto: {negotiated_version}")
                    pool.submit(handle_client, ssl_conn, addr)
                except ssl.SSLError as e:
                    print(f"[!] Handshake SSL fallido {addr}: {e}")
                    client_sock.close()
        except KeyboardInterrupt:
            print("\n[*] Servidor detenido.")
        finally:
            server_socket.close()


# ============================================================
# INICIO DEL SERVIDOR
# ============================================================
def start_ssl_server(host=HOST, port=PORT):
    init_database()

    # Contexto SSL: TLS 1.3 endurecido
    ctx = _create_tls_context()

    try:
        ctx.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)
    except FileNotFoundError:
        print("[!] No se encontraron cert.pem / key.pem.")
        print("[!] Ejecute primero:  python generar_certificados.py")
        return
    except ssl.SSLError as e:
        print(f"[!] Error SSL al cargar certificados: {e}")
        return

    server_socket = _create_listen_socket(host, port)

    # Mostrar información del servidor
    print("=" * 60)
    print("  SERVIDOR SSL/TLS 1.3 — PAI2")
    print("=" * 60)
    print(f"  Host:        {host}:{port}")
    print(f"  Max conexiones concurrentes: {MAX_WORKERS}")
    print(f"  Base de datos: {DB_FILE}")
    print(f"  Cipher Suites TLS 1.3:")
    for c in ctx.get_ciphers():
        if 'TLSv1.3' in c.get('protocol', ''):
            print(f"    - {c['name']}")
    print("=" * 60)

    _run_accept_loop(server_socket, tls_ctx=ctx)


def start_plain_server(host=HOST, port=PLAIN_PORT):
    """Servidor en texto plano solo para benchmark comparativo (sin TLS)."""
    init_database()
    server_socket = _create_listen_socket(host, port)

    print("=" * 60)
    print("  SERVIDOR TCP SIN TLS (SOLO BENCHMARK)")
    print("=" * 60)
    print(f"  Host:        {host}:{port}")
    print(f"  Max conexiones concurrentes: {MAX_WORKERS}")
    print(f"  Base de datos: {DB_FILE}")
    print("=" * 60)

    _run_accept_loop(server_socket, tls_ctx=None)


def _parse_args():
    parser = argparse.ArgumentParser(
        description='Servidor PAI2 con soporte TLS 1.3 y modo benchmark sin TLS.'
    )
    parser.add_argument('--plain', action='store_true', help='Inicia transporte sin TLS (solo benchmark).')
    parser.add_argument('--host', default=HOST, help='Host de escucha.')
    parser.add_argument('--port', type=int, default=None, help='Puerto de escucha.')
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    if args.plain:
        start_plain_server(host=args.host, port=args.port or PLAIN_PORT)
    else:
        start_ssl_server(host=args.host, port=args.port or PORT)

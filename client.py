"""
Cliente SSL/TLS 1.3 - PAI2: Comunicación Segura
Universidad Pública - Sistema de Registro, Autenticación y Mensajería

Funcionalidades:
  - Conexión segura TLS 1.3 con verificación de certificado del servidor
  - Registro de nuevos usuarios
  - Inicio y cierre de sesión
  - Envío de mensajes de texto (máx. 144 caracteres)
  - Consulta de estadísticas de mensajes
"""

import socket
import ssl
import json
import struct
import sys
import getpass


# ============================================================
# CONFIGURACIÓN
# ============================================================
SERVER_HOST = 'localhost'
SERVER_PORT = 8443
CA_CERT = 'cert.pem'  # Certificado del servidor (CA) para verificación


# ============================================================
# PROTOCOLO DE COMUNICACIÓN (debe coincidir con el servidor)
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
# INTERFAZ DE USUARIO
# ============================================================
def show_menu(logged_in):
    print()
    print("=" * 50)
    print("  SISTEMA DE COMUNICACION SEGURA - PAI2")
    print("=" * 50)
    if not logged_in:
        print("  1. Registrarse")
        print("  2. Iniciar sesion")
    else:
        print("  3. Enviar mensaje")
        print("  4. Ver estadisticas de mensajes")
        print("  5. Cerrar sesion")
    print("  0. Salir")
    print("=" * 50)


def print_response(response):
    """Muestra la respuesta del servidor con formato."""
    if response is None:
        print("\n  [!] Sin respuesta del servidor.")
        return
    icon = "[OK]" if response['status'] == 'ok' else "[ERROR]"
    # Manejar mensajes multilínea
    lines = response['message'].split('\n')
    print(f"\n  {icon} {lines[0]}")
    for line in lines[1:]:
        print(f"        {line}")


# ============================================================
# LÓGICA PRINCIPAL DEL CLIENTE
# ============================================================
def connect_to_ssl_server():
    # Configurar contexto SSL: forzar TLS 1.3 únicamente
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
    ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3

    # Cargar certificado CA para verificar el servidor
    try:
        ssl_context.load_verify_locations(CA_CERT)
        ssl_context.check_hostname = False  # Self-signed: CN puede no coincidir
        ssl_context.verify_mode = ssl.CERT_REQUIRED
    except FileNotFoundError:
        print(f"[!] Certificado CA no encontrado: {CA_CERT}")
        print("[!] Conectando sin verificacion de certificado (solo para pruebas).")
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

    # Crear socket y conexión SSL
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        ssl_socket = ssl_context.wrap_socket(raw_socket, server_hostname=SERVER_HOST)
        ssl_socket.connect((SERVER_HOST, SERVER_PORT))
    except ConnectionRefusedError:
        print(f"[!] No se pudo conectar al servidor en {SERVER_HOST}:{SERVER_PORT}")
        print("[!] Asegurese de que el servidor este ejecutandose.")
        return
    except ssl.SSLError as e:
        print(f"[!] Error en handshake SSL: {e}")
        return

    # Mostrar información de la conexión segura
    cipher_info = ssl_socket.cipher()
    print()
    print("=" * 50)
    print("  CONEXION SEGURA ESTABLECIDA")
    print("=" * 50)
    print(f"  Servidor:    {SERVER_HOST}:{SERVER_PORT}")
    print(f"  Protocolo:   {cipher_info[1]}")
    print(f"  Cipher:      {cipher_info[0]}")
    print(f"  Bits cifrado:{cipher_info[2]}")
    print("=" * 50)

    logged_in = False

    try:
        while True:
            show_menu(logged_in)
            choice = input("  Seleccione una opcion: ").strip()

            if choice == '0':
                # Cerrar sesión si está activa antes de salir
                if logged_in:
                    send_msg(ssl_socket, {"action": "logout"})
                    resp = recv_msg(ssl_socket)
                    if resp:
                        print_response(resp)
                print("\n  Hasta luego!")
                break

            elif choice == '1' and not logged_in:
                # === REGISTRO ===
                username = input("  Nombre de usuario: ").strip()
                password = getpass.getpass("  Contrasena: ")

                send_msg(ssl_socket, {
                    "action": "register",
                    "username": username,
                    "password": password
                })
                print_response(recv_msg(ssl_socket))

            elif choice == '2' and not logged_in:
                # === INICIO DE SESIÓN ===
                username = input("  Nombre de usuario: ").strip()
                password = getpass.getpass("  Contrasena: ")

                send_msg(ssl_socket, {
                    "action": "login",
                    "username": username,
                    "password": password
                })
                resp = recv_msg(ssl_socket)
                if resp and resp['status'] == 'ok':
                    logged_in = True
                print_response(resp)

            elif choice == '3' and logged_in:
                # === ENVIAR MENSAJE ===
                message = input("  Mensaje (max. 144 caracteres): ").strip()
                send_msg(ssl_socket, {
                    "action": "send_message",
                    "message": message
                })
                print_response(recv_msg(ssl_socket))

            elif choice == '4' and logged_in:
                # === ESTADÍSTICAS ===
                send_msg(ssl_socket, {"action": "stats"})
                print_response(recv_msg(ssl_socket))

            elif choice == '5' and logged_in:
                # === CERRAR SESIÓN ===
                send_msg(ssl_socket, {"action": "logout"})
                resp = recv_msg(ssl_socket)
                if resp and resp['status'] == 'ok':
                    logged_in = False
                print_response(resp)

            else:
                print("\n  [!] Opcion no valida.")

    except (ConnectionResetError, BrokenPipeError):
        print("\n[!] Se perdio la conexion con el servidor.")
    except KeyboardInterrupt:
        print("\n\n  Conexion interrumpida.")
    finally:
        try:
            ssl_socket.close()
        except Exception:
            pass


if __name__ == "__main__":
    connect_to_ssl_server()

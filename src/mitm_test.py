"""
Prueba activa MitM controlada para PAI2.

Objetivo:
- Simular un servidor TLS malicioso con un certificado no confiable.
- Verificar que un cliente configurado como el de PAI2 lo rechaza.

Resultado esperado:
- PASS: el cliente falla con SSLCertVerificationError.
- FAIL: el cliente logra conectar al servidor malicioso.
"""

import argparse
import datetime
import ipaddress
import os
import socket
import ssl
import tempfile
import threading
import time


def _generate_rogue_cert(cert_path, key_path):
    """Genera un certificado autofirmado malicioso para la prueba MitM."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError as exc:
        raise RuntimeError(
            "Falta dependencia 'cryptography'. Instala con: pip install cryptography"
        ) from exc

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MITM-Test"),
        x509.NameAttribute(NameOID.COMMON_NAME, "rogue.local"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=7))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("rogue.local"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def _run_rogue_server(host, port, cert_path, key_path, stop_event):
    """Servidor TLS malicioso minimo para desencadenar el handshake."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(5)
    srv.settimeout(0.25)

    try:
        while not stop_event.is_set():
            try:
                client_sock, _addr = srv.accept()
            except socket.timeout:
                continue

            try:
                tls_sock = ctx.wrap_socket(client_sock, server_side=True)
                # Si por alguna razon conecta, cerrar inmediatamente.
                tls_sock.close()
            except ssl.SSLError:
                try:
                    client_sock.close()
                except Exception:
                    pass
    finally:
        srv.close()


def _attempt_client_connection(host, port, ca_cert_path):
    """Intenta conectar como cliente PAI2 (TLS 1.3 + validacion estricta)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(ca_cert_path)

    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(4.0)
    wrapped = ctx.wrap_socket(raw, server_hostname="localhost")
    wrapped.connect((host, port))
    wrapped.close()


def run_mitm_test(host, port, trusted_ca_cert):
    with tempfile.TemporaryDirectory() as tmp:
        rogue_cert = os.path.join(tmp, "rogue_cert.pem")
        rogue_key = os.path.join(tmp, "rogue_key.pem")
        _generate_rogue_cert(rogue_cert, rogue_key)

        stop_event = threading.Event()
        server_thread = threading.Thread(
            target=_run_rogue_server,
            args=(host, port, rogue_cert, rogue_key, stop_event),
            daemon=True,
        )
        server_thread.start()

        time.sleep(0.2)

        print("[TEST] Lanzando intento de conexion a servidor malicioso...")
        print(f"[TEST] Host/Puerto atacante: {host}:{port}")
        print(f"[TEST] Certificado de confianza del cliente: {trusted_ca_cert}")

        try:
            _attempt_client_connection(host, port, trusted_ca_cert)
            print("[FAIL] El cliente conecto al servidor malicioso. MitM no bloqueado.")
            return 1
        except ssl.SSLCertVerificationError as exc:
            print("[PASS] MitM bloqueado: verificacion de certificado fallo como se esperaba.")
            print(f"[PASS] Detalle: {exc}")
            return 0
        except ssl.SSLError as exc:
            print("[PASS] MitM bloqueado: handshake TLS no fue valido para el cliente.")
            print(f"[PASS] Detalle: {exc}")
            return 0
        except Exception as exc:
            print(f"[WARN] Resultado no concluyente por error inesperado: {exc}")
            return 2
        finally:
            stop_event.set()
            server_thread.join(timeout=1.0)


def main():
    parser = argparse.ArgumentParser(
        description="Prueba activa MitM controlada para PAI2"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--trusted-ca", default="cert.pem")
    args = parser.parse_args()

    code = run_mitm_test(args.host, args.port, args.trusted_ca)
    raise SystemExit(code)


if __name__ == "__main__":
    main()

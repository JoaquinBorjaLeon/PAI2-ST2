"""
Generador de Certificados SSL Autofirmados - PAI2
Genera cert.pem y key.pem necesarios para el servidor y cliente.
Usa RSA 4096 bits con SAN para localhost/127.0.0.1.

Dependencias: pip install cryptography
"""

import os
import datetime


def generate_certificates():
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import ipaddress

    certfile = 'cert.pem'
    keyfile = 'key.pem'

    if os.path.exists(certfile) and os.path.exists(keyfile):
        resp = input("Los certificados ya existen. Desea regenerarlos? (s/n): ").strip().lower()
        if resp != 's':
            print("Operacion cancelada.")
            return

    print("Generando certificados SSL autofirmados (RSA 4096 bits)...")

    # Generar clave privada RSA 4096 bits
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    # Construir el certificado autofirmado
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PAI2-Universidad"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    # Guardar clave privada
    with open(keyfile, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    # Guardar certificado
    with open(certfile, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[OK] Certificado generado: {certfile}")
    print(f"[OK] Clave privada generada: {keyfile}")
    print(f"[OK] Valido por 365 dias")
    print(f"[OK] Algoritmo: RSA 4096 bits, SHA-256")
    print(f"[OK] SAN: DNS:localhost, IP:127.0.0.1")
    print(f"[OK] Organizacion: PAI2-Universidad, Pais: ES")


if __name__ == "__main__":
    generate_certificates()

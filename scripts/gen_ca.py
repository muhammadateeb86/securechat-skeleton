# scripts/gen_ca.py
"""Create a Root CA (RSA 4096) and save to certs/ca.key and certs/ca.crt (PEM)."""
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import cryptography.x509 as x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from pathlib import Path

CERT_DIR = Path("certs")
CERT_DIR.mkdir(exist_ok=True)

def main():
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST SecureChat CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"SecureChat Root CA"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    with open(CERT_DIR / "ca.key", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(CERT_DIR / "ca.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print("Wrote certs/ca.key and certs/ca.crt")

if __name__ == "__main__":
    main()

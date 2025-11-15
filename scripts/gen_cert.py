# scripts/gen_cert.py
"""Issue RSA X.509 certs (2048) signed by root CA. Usage:
python scripts/gen_cert.py --cn server --out certs/server
"""
import argparse
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import cryptography.x509 as x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from pathlib import Path

CERT_DIR = Path("certs")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--cn", required=True)
    p.add_argument("--out", required=True, help="prefix e.g. certs/server")
    args = p.parse_args()

    ca_key_path = CERT_DIR / "ca.key"
    ca_crt_path = CERT_DIR / "ca.crt"
    if not ca_key_path.exists() or not ca_crt_path.exists():
        raise SystemExit("Run scripts/gen_ca.py first to create ca.key and ca.crt")

    with open(ca_key_path, "rb") as f:
        ca_priv = serialization.load_pem_private_key(f.read(), password=None)
    with open(ca_crt_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, args.cn),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_priv, hashes.SHA256())
    )
    with open(args.out + ".key", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(args.out + ".crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"Wrote {args.out}.key and {args.out}.crt")

if __name__ == "__main__":
    main()

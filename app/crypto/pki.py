# crypto/pki.py
"""X.509 certificate helpers (verify chain, fingerprint)."""
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import time

def load_cert(pem_bytes: bytes):
    return x509.load_pem_x509_certificate(pem_bytes)

def verify_cert_against_ca(cert_pem: bytes, ca_cert_pem: bytes) -> (bool, str):
    try:
        cert = load_cert(cert_pem)
        ca = load_cert(ca_cert_pem)
        # issuer check
        if cert.issuer != ca.subject:
            return False, "issuer_mismatch"
        # validity
        now = time.time()
        if cert.not_valid_before.timestamp() > now or cert.not_valid_after.timestamp() < now:
            return False, "expired_or_not_yet_valid"
        # signature verification
        ca_pub = ca.public_key()
        ca_pub.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
        return True, "ok"
    except Exception as e:
        return False, f"verify_failed:{e}"

def cert_fingerprint_sha256(cert_pem: bytes) -> str:
    cert = load_cert(cert_pem)
    h = cert.fingerprint(hashes.SHA256())
    return h.hex()

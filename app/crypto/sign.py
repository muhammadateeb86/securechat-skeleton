# crypto/sign.py
"""RSA sign / verify helpers using cryptography."""
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

def rsa_sign_pem(private_pem: bytes, data: bytes) -> bytes:
    priv = serialization.load_pem_private_key(private_pem, password=None)
    sig = priv.sign(data, padding.PKCS1v15(), hashes.SHA256())
    return sig

def rsa_verify_pem(public_pem: bytes, data: bytes, sig: bytes) -> bool:
    pub = serialization.load_pem_public_key(public_pem)
    try:
        pub.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False

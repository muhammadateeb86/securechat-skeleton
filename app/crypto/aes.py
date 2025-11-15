# crypto/aes.py
"""AES-128 ECB + PKCS7 helpers using cryptography."""
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

backend = default_backend()

def pkcs7_pad(b: bytes, block=16) -> bytes:
    p = padding.PKCS7(block * 8).padder()
    return p.update(b) + p.finalize()

def pkcs7_unpad(b: bytes, block=16) -> bytes:
    u = padding.PKCS7(block * 8).unpadder()
    return u.update(b) + u.finalize()

def aes_ecb_encrypt(key16: bytes, plaintext: bytes) -> bytes:
    assert len(key16) == 16
    cipher = Cipher(algorithms.AES(key16), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    pt = pkcs7_pad(plaintext, 16)
    return encryptor.update(pt) + encryptor.finalize()

def aes_ecb_decrypt(key16: bytes, ciphertext: bytes) -> bytes:
    assert len(key16) == 16
    cipher = Cipher(algorithms.AES(key16), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return pkcs7_unpad(padded, 16)

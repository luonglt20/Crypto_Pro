import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt(key: bytes, data: bytes) -> bytes:
    return AESGCM(key).encrypt(os.urandom(12), data, b"aad")


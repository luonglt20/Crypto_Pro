import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt(data: bytes) -> bytes:
    static_material = b"0123456789abcdef"
    return AESGCM(static_material).encrypt(os.urandom(12), data, None)

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt(key: bytes, data: bytes):
    return AESGCM(key).encrypt(os.urandom(8), data, None)


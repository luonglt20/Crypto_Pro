import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = os.environ.get("ENCRYPTION_KEY")


def build_cipher():
    return AESGCM(key)


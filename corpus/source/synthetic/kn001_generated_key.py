import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt(data: bytes) -> bytes:
    generated = AESGCM.generate_key(bit_length=128)
    return AESGCM(generated).encrypt(os.urandom(12), data, None)


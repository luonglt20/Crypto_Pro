import os
import random
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt(data: bytes) -> bytes:
    generated = random.randbytes(16)
    return AESGCM(generated).encrypt(os.urandom(12), data, None)

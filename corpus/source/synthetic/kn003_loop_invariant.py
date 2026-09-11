import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_all(key: bytes, messages: list[bytes]) -> list[bytes]:
    cipher = AESGCM(key)
    nonce = os.urandom(12)
    result = []
    for message in messages:
        result.append(cipher.encrypt(nonce, message, None))
    return result


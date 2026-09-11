import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt(data: bytes, aad: bytes) -> tuple[bytes, bytes, bytes]:
    generated = AESGCM.generate_key(bit_length=128)
    nonce = os.urandom(12)
    ciphertext = AESGCM(generated).encrypt(nonce, data, aad)
    return generated, nonce, ciphertext


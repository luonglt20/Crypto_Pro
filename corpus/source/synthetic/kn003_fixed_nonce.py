from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt(key: bytes, data: bytes) -> bytes:
    nonce = b"\x00" * 12
    return AESGCM(key).encrypt(nonce, data, None)


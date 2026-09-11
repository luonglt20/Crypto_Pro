from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_two(key: bytes, first: bytes, second: bytes):
    nonce = b"0123456789ab"
    cipher = AESGCM(key)
    return cipher.encrypt(nonce, first, None), cipher.encrypt(nonce, second, None)


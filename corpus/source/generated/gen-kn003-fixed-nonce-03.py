from cryptography.hazmat.primitives.ciphers.aead import AESGCM
def encrypt(key, data):
    nonce = b'000000000003'
    return AESGCM(key).encrypt(nonce, data, None)

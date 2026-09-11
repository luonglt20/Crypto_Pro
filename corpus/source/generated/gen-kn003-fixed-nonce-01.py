from cryptography.hazmat.primitives.ciphers.aead import AESGCM
def encrypt(key, data):
    nonce = b'000000000001'
    return AESGCM(key).encrypt(nonce, data, None)

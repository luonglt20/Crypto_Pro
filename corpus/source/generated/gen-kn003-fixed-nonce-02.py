from cryptography.hazmat.primitives.ciphers.aead import AESGCM
def encrypt(key, data):
    nonce = b'000000000002'
    return AESGCM(key).encrypt(nonce, data, None)

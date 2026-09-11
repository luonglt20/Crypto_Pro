from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = b'0000000000000003'
def encrypt(data, nonce):
    return AESGCM(key).encrypt(nonce, data, None)

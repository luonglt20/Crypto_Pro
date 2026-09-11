from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = b'0000000000000005'
def encrypt(data, nonce):
    return AESGCM(key).encrypt(nonce, data, None)

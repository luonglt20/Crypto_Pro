import random
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
def encrypt(data, nonce):
    key = random.randbytes(16)
    return AESGCM(key).encrypt(nonce, data, None)

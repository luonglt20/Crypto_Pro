import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
def encrypt(key, data):
    return AESGCM(key).encrypt(os.urandom(11), data, None)

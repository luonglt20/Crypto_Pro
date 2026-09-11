import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
def encrypt(data):
    key = AESGCM.generate_key(bit_length=128)
    return AESGCM(key).encrypt(os.urandom(12), data, None)

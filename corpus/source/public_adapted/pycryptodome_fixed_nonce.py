from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def encrypt(data: bytes):
    generated = get_random_bytes(16)
    return AES.new(generated, AES.MODE_GCM, nonce=b"fixed-nonce!").encrypt_and_digest(data)


from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def decrypt(ciphertext: bytes) -> bytes:
    generated = get_random_bytes(16)
    cipher = AES.new(generated, AES.MODE_GCM, nonce=get_random_bytes(12))
    return cipher.decrypt(ciphertext)


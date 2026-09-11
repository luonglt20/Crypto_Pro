from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def round_trip(data: bytes):
    generated = get_random_bytes(16)
    cipher = AES.new(generated, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    verifier = AES.new(generated, AES.MODE_GCM, nonce=cipher.nonce)
    return verifier.decrypt_and_verify(ciphertext, tag)


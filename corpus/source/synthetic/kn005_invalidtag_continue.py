from cryptography.exceptions import InvalidTag


def unsafe_decrypt(cipher, nonce: bytes, ciphertext: bytes) -> bytes:
    plaintext = b""
    try:
        plaintext = cipher.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        print("invalid tag")
    return plaintext


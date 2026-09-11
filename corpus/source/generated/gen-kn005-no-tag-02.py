from Crypto.Cipher import AES
def decrypt(key, nonce, ciphertext):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt(ciphertext)

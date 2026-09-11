def sign_message(signer, message: bytes):
    return signer.sign(message, k=1)


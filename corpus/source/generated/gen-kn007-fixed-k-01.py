def sign(signer, digest):
    return signer.sign(digest, k=1)

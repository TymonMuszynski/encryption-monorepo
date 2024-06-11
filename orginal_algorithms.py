from lib import cbc_decrypt, cbc_encrypt, ctr_encrypt, ctr_decrypt, ecb_encrypt, ecb_decrypt

if __name__ == "__main__":
    key = b"1111111111111111" #TODO
    plaintext = b"dabrol"  # TODO
    nonce = b"ABJ3k6lq"
    iv = b"JEODB34DOlgSHuRP"
    nonce = nonce + b'\x00' * (len(key) - len(nonce))

    ciphertext = cbc_encrypt(plaintext, key, iv)
    print("Ciphertext:", ciphertext)

    decrypted_plaintext = cbc_decrypt(ciphertext, key, iv)
    print("Decrypted plaintext:", decrypted_plaintext)

    ciphertext = ctr_encrypt(plaintext, key, nonce)
    print("Ciphertext:", ciphertext)

    decrypted_plaintext = ctr_decrypt(ciphertext, key, nonce)
    print("Decrypted plaintext:", decrypted_plaintext)

    ciphertext = ecb_encrypt(plaintext, key)
    print("Ciphertext:", ciphertext)

    decrypted_plaintext = ecb_decrypt(ciphertext, key)
    print("Decrypted plaintext:", decrypted_plaintext)
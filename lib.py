from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes

def pad(data, block_size):
    padding_length = block_size - len(data) % block_size
    padding = bytes([padding_length] * padding_length)
    return data + padding

def unpad(data):
    padding_length = data[-1]
    if padding_length == 0 or padding_length > len(data):
        raise ValueError("Niepoprawne wypełnienie")
    if any(byte != padding_length for byte in data[-padding_length:]):
        raise ValueError("Niepoprawne wypełnienie")
    return data[:-padding_length]

def increment_counter(counter):
    counter_int = int.from_bytes(counter, byteorder='big') + 1
    return counter_int.to_bytes(len(counter), byteorder='big')

def encrypt_block(block, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(block) + encryptor.finalize()

def encrypt_block_xor(block, key):
    if len(block) != len(key):
        raise ValueError("Block and key must be of equal length")
    encrypted_block = bytes([block[i] ^ key[i] for i in range(len(block))])
    return encrypted_block

# od Kamila
def decrypt_block_xor(block, key):
    if len(block) != len(key):
        raise ValueError("Block and key must be of equal length")
    decrypted_block = bytes([block[i] ^ key[i] for i in range(len(block))])
    return decrypted_block
def ctr_encrypt(plaintext, key, nonce):
    block_size = len(key)
    ciphertext = b""
    counter = nonce + b'\x00' * (block_size - len(nonce))  # Uzupełnienie do długości bloku
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i+block_size]
        keystream_block = encrypt_block(counter, key)
        encrypted_block = bytes([block[j] ^ keystream_block[j] for j in range(len(block))])
        ciphertext += encrypted_block
        counter = increment_counter(counter)
    return ciphertext

def ctr_decrypt(ciphertext, key, nonce):
    return ctr_encrypt(ciphertext, key, nonce)  # Szyfrowanie i deszyfrowanie w CTR są takie same

#ECB
def ecb_encrypt(plaintext, key):
    block_size = 16  # AES block size is 16 bytes
    plaintext = pad(plaintext, block_size)
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

def ecb_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(plaintext)
    return plaintext
#CBC
def ecb_encrypt(plaintext, key):
    block_size = 16  # AES block size is 16 bytes
    plaintext = pad(plaintext, block_size)
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

#CBC
def cbc_encrypt(plaintext, key, iv):
    block_size = len(key)
    plaintext = pad(plaintext, block_size)
    ciphertext = b""
    previous_block = iv
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        xor_block = bytes([block[j] ^ previous_block[j] for j in range(block_size)])
        encrypted_block = encrypt_block_xor(xor_block, key)
        ciphertext += encrypted_block
        previous_block = encrypted_block
    return ciphertext

def cbc_decrypt(ciphertext, key, iv):
    block_size = len(key)
    plaintext = b""
    previous_block = iv
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]
        decrypted_block = decrypt_block_xor(block, key)
        xor_block = bytes([decrypted_block[j] ^ previous_block[j] for j in range(block_size)])
        plaintext += xor_block
        previous_block = block
    plaintext = unpad(plaintext)
    return plaintext
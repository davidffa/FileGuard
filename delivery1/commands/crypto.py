from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


def encrypt_aes256_cbc(plaintext: bytes, secret_key: bytes, iv: bytes) -> bytes:
    algorithm = algorithms.AES256(secret_key)

    padder = PKCS7(algorithm.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithm, modes.CBC(iv))
    encryptor = cipher.encryptor()

    return encryptor.update(padded_data) + encryptor.finalize()
    

def decrypt_aes256_cbc(secret_key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    algorithm = algorithms.AES256(secret_key)
    cipher = Cipher(algorithm, modes.CBC(iv))
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = PKCS7(algorithm.block_size).unpadder()

    return unpadder.update(padded_data) + unpadder.finalize()


def sha256_digest(data: bytes) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)

    return digest.finalize().hex()

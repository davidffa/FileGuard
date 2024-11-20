from typing import Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
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

def derive_ec_priv_key(password: str, salt: bytes) -> ec.EllipticCurvePrivateKey:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )

    key = kdf.derive(bytes(password, "utf8"))

    return ec.derive_private_key(int.from_bytes(key, "big"), ec.SECP256R1())

def generate_ec_keypair() -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    priv_key = ec.generate_private_key(ec.SECP256R1())
    pub_key = priv_key.public_key()

    return (priv_key, pub_key)

def sign_ec_dsa(priv_key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    return priv_key.sign(data, ec.ECDSA(hashes.SHA256()))

def serialize_pub_key(pub_key: ec.EllipticCurvePublicKey) -> bytes:
    return pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_pub_key(pub_key: bytes) -> ec.EllipticCurvePublicKey:
    key = serialization.load_pem_public_key(pub_key)

    assert isinstance(key, ec.EllipticCurvePublicKey)

    return key

def ecdh_shared_key(priv_key: ec.EllipticCurvePrivateKey, pub_key: ec.EllipticCurvePublicKey, key_size: int) -> bytes:
    shared_key = priv_key.exchange(ec.ECDH(), pub_key)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=key_size,
        salt=None,
        info=b'secret keys'
    ).derive(shared_key)

    return derived_key


def compute_hmac(data: bytes, mac_key: bytes) -> bytes:
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(data)

    return h.finalize()

def verify_hmac(data: bytes, mac: bytes, mac_key: bytes) -> bool:
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(data)

    try:
        h.verify(mac)
        return True
    except InvalidSignature:
        return False

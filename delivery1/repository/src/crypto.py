from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.padding import PKCS7


def pbkdf2(password: str, length: int, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=480000
    )

    return kdf.derive(bytes(password, "utf8"))

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

def serialize_pub_key(pub_key: ec.EllipticCurvePublicKey) -> bytes:
    return pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def verify_ecdsa(pub_key: ec.EllipticCurvePublicKey, data: bytes, signature: bytes) -> bool:
    try:
        pub_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False

def load_pub_key(pub_key: bytes) -> ec.EllipticCurvePublicKey:
    key = serialization.load_pem_public_key(pub_key)

    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise Exception("Pub key must be EC public key type")

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

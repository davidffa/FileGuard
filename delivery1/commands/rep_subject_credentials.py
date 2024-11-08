#!/usr/bin/env python3

import os
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def main():
    if len(sys.argv) < 3:
        usage()

    password = sys.argv[1]
    credentials_file = sys.argv[2]

    salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )

    key = kdf.derive(bytes(password, "utf8"))

    private_key = ec.derive_private_key(int.from_bytes(key), ec.SECP256R1())

    public_key = private_key.public_key()

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(credentials_file, "wb") as f:
        f.write(salt + public_key_pem)

def usage():
    print(f"Usage: {sys.argv[0]} <password> <credentials file>")
    sys.exit(1)

if __name__ == "__main__":
    main()

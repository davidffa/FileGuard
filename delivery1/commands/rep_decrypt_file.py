#!/usr/bin/env python3

import json
import sys

from crypto import decrypt_aes256_cbc, sha256_digest


def main():
    if len(sys.argv) < 3:
        usage()

    filepath = sys.argv[1]
    metadata_file = sys.argv[2]

    with open(metadata_file, "rb") as f:
        metadata = f.read()

    size = int.from_bytes(metadata[0:2], "big")
    json_metadata = json.loads(metadata[2:size+2])

    if json_metadata["crypto_alg"] != "AES256_CBC":
        print(f"Unsupported crypto algorithm in the metadata")
        sys.exit(1)

    if json_metadata["digest_alg"] != "SHA256":
        print(f"Unsupported digest algorithm in the metadata")
        sys.exit(1)

    secret_key = metadata[2+size:2+size+32]
    iv = metadata[2+size+32:]

    with open(filepath, "rb") as f:
        ciphertext = f.read()

    plaintext = decrypt_aes256_cbc(secret_key, iv, ciphertext)

    file_handle = json_metadata["file_handle"]

    if file_handle != sha256_digest(plaintext):
        print(f"Integrity verification failed!")
        sys.exit(1)

    sys.stdout.buffer.write(plaintext)
    sys.stdout.buffer.flush()

def usage():
    print(f"Usage: {sys.argv[0]} <encrypted file> <encryption metadata>")
    sys.exit(1)

if __name__ == "__main__":
    main()

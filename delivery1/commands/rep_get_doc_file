#!/usr/bin/env python3

import json
import logging
import sys

import requests
from common import (decrypt_body, encrypt_body, load_session, parse_args,
                    parse_env, update_session_sequence)

from crypto import decrypt_aes256_cbc, sha256_digest

logging.basicConfig(format="%(levelname)s\t- %(message)s")
logger = logging.getLogger()
logger.setLevel(logging.INFO)

 # This commands requires a DOC_READ permission.
def main():
    state = parse_env({})
    positional_args = ["session_file", "document_name"]
    optional_args = ["file"]
    state = parse_args(state, positional_args, optional_args)

    if 'REP_ADDRESS' not in state:
        logger.error("Must define Repository Address")
        sys.exit(-1)

    if 'REP_PUB_KEY' not in state:
        logger.error("Must set the Repository Public Key")
        sys.exit(-1)

    session_file = state["session_file"]
    file = state["file"]

    session_id, seq, secret_key, mac_key = load_session(session_file)
    
    headers = {
        "sessionid": session_id
    }

    body = {
        "document_name": state["document_name"]
    }


    body = encrypt_body(json.dumps(body).encode("utf8"), seq, secret_key, mac_key)

    req = requests.get(f'http://{state["REP_ADDRESS"]}/document_metadata', headers=headers, data=body)

    update_session_sequence(session_file)

    if req.status_code == 200:
        metadata = decrypt_body(req.content, secret_key, mac_key)
    else:
        if req.headers["content-type"] == "application/octet-stream":
            logger.error(json.loads(decrypt_body(req.content, secret_key, mac_key)))
        else:
            logger.error(req.json())

        sys.exit(-1)

    # Decrypt

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

    file_handle = json_metadata["file_handle"]
    req = requests.get(f'http://{state["REP_ADDRESS"]}/files/{file_handle}')

    if req.status_code == 200:
        ciphertext = req.content
    else:
        logger.error(req.json())
        sys.exit(-1)

    plaintext = decrypt_aes256_cbc(secret_key, iv, ciphertext)

    if file_handle != sha256_digest(plaintext):
        print(f"Integrity verification failed!")
        sys.exit(1)

    if file != None : 
        with open(file, 'wb') as f:
            f.write(plaintext)
    else:
        sys.stdout.buffer.write(plaintext)
        sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()

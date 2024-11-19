#!/usr/bin/env python3

import base64
import logging
import os
import sys

import requests
from common import parse_args, parse_env
from crypto import encrypt_aes256_cbc, sha256_digest

logging.basicConfig(format="%(levelname)s\t- %(message)s")
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def main():
    state = parse_env({})
    positional_args = ["session_file", "document_name", "file"]
    state = parse_args(state, positional_args)

    if 'REP_ADDRESS' not in state:
        logger.error("Must define Repository Address")
        sys.exit(-1)

    if 'REP_PUB_KEY' not in state:
        logger.error("Must set the Repository Public Key")
        sys.exit(-1)

    session_file = state["session_file"]

    with open(session_file, "rb") as f:
        session = base64.b64encode(f.read())

    file_path = state["file"]

    if not os.path.isfile(file_path):
        logger.error("Invalid file")
        sys.exit(1)

    with open(file_path, "rb") as f:
        plaintext = f.read()

    file_handle = sha256_digest(plaintext)

    secret_key = os.urandom(32)
    iv = os.urandom(16)

    ciphertext = encrypt_aes256_cbc(plaintext, secret_key, iv)

    body = {
        "document_name": state["document_name"],
        "file_handle": file_handle,
        "crypto_alg": "AES256_CBC",
        "digest_alg": "SHA256",
    }
      
    headers = {
        "session": session
    }

    req = requests.post(f'http://{state["REP_ADDRESS"]}/document', headers=headers, data=body, files=dict(file=ciphertext, secret_key=secret_key, iv=iv))

    if req.status_code == 201:
        logger.info("Document created")
        logger.info(req.json())
    else:
        logger.error(req.json())
        sys.exit(-1)

if __name__ == "__main__":
    main()

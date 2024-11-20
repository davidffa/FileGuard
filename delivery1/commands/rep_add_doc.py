#!/usr/bin/env python3

import json
import logging
import os
import sys

import requests
from common import (decrypt_body, encrypt_body, load_session, parse_args,
                    parse_env, update_session_sequence)
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

    session_id, seq, secret_key, mac_key = load_session(session_file)

    file_path = state["file"]

    if not os.path.isfile(file_path):
        logger.error("Invalid file")
        sys.exit(1)

    with open(file_path, "rb") as f:
        plaintext = f.read()

    file_handle = sha256_digest(plaintext)

    file_secret_key = os.urandom(32)
    iv = os.urandom(16)

    cipheredfile = encrypt_aes256_cbc(plaintext, file_secret_key, iv)

    body = {
        "document_name": state["document_name"],
        "file_handle": file_handle,
        "crypto_alg": "AES256_CBC",
        "digest_alg": "SHA256",
    }
      
    headers = {
        "sessionid": session_id
    }

    cipherbody = encrypt_body(json.dumps(body).encode("utf8"), seq, secret_key, mac_key)
    cipher_file_sk = encrypt_body(file_secret_key, seq, secret_key, mac_key)

    req = requests.post(f'http://{state["REP_ADDRESS"]}/document', headers=headers, files=dict(data=cipherbody, file=cipheredfile, secret_key=cipher_file_sk, iv=iv))

    update_session_sequence(session_file)

    if req.status_code == 201:
        logger.info("Document created")
    else:
        if req.headers["content-type"] == "application/octet-stream":
            res = json.loads(decrypt_body(req.content, secret_key, mac_key))
            logger.error(res)
        else:
            logger.error(req.json())
        sys.exit(-1)

if __name__ == "__main__":
    main()

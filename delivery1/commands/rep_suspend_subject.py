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
    positional_args = ["session_file", "username"]
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

    username = state["username"]

    body = {
        "username": username
    }
      
    headers = {
        "session": session
    }

    req = requests.post(f'http://{state["REP_ADDRESS"]}/suspend', headers=headers, data=body)

    if req.status_code == 201:
        logger.info("Subject suspended")
        logger.info(req.json())
    else:
        logger.error(req.json())
        sys.exit(-1)

if __name__ == "__main__":
    main()
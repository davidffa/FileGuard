#!/usr/bin/env python3

import base64
import logging
import sys

import requests
from common import parse_args, parse_env

logging.basicConfig(format="%(levelname)s\t- %(message)s")
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def main():
    state = parse_env({})
    positional_args = ["session_file", "username", "name", "email", "credentials_file"]
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

    credentials_file = state["credentials_file"]

    with open(credentials_file, "rb") as f:
        pub_key = f.read()
        pub_key = pub_key[16:].decode()

    state["pub_key"] = pub_key

    headers = {
        "session": session
    }

    body = {
        "username": state["username"],
        "name": state["name"],
        "email": state["email"],
        "pub_key" : state["pub_key"]
    }
      
    req = requests.post(f'http://{state["REP_ADDRESS"]}/subject/create', headers=headers, data=body)

    if req.status_code == 201:
        logger.info("Subject created")
        logger.info(req.json())
    else:
        logger.error(req.json())
        sys.exit(-1)

if __name__ == "__main__":
    main()

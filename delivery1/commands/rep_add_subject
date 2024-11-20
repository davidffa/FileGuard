#!/usr/bin/env python3

import base64
import json
import logging
import sys

import requests
from common import (decrypt_body, encrypt_body, load_session, parse_args,
                    parse_env, update_session_sequence)

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

    session_id, seq, secret_key, mac_key = load_session(session_file)

    credentials_file = state["credentials_file"]

    with open(credentials_file, "rb") as f:
        pub_key = f.read()
        pub_key = pub_key[16:].decode()

    state["pub_key"] = pub_key

    headers = {
        "sessionid": session_id
    }

    body = {
        "username": state["username"],
        "name": state["name"],
        "email": state["email"],
        "pub_key" : state["pub_key"]
    }

    body = encrypt_body(json.dumps(body).encode("utf8"), seq, secret_key, mac_key)
      
    req = requests.post(f'http://{state["REP_ADDRESS"]}/subject/create', headers=headers, data=body)
    update_session_sequence(session_file)

    if req.status_code == 201:
        logger.info("Subject created")
    else:
        if req.headers["content-type"] == "application/octet-stream":
            logger.error(json.loads(decrypt_body(req.content, secret_key, mac_key)))
        else:
            logger.error(req.json())
        sys.exit(-1)

if __name__ == "__main__":
    main()

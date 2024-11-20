#!/usr/bin/env python3

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
    positional_args = ["session_file", "document_name"]
    state = parse_args(state, positional_args)

    if 'REP_ADDRESS' not in state:
        logger.error("Must define Repository Address")
        sys.exit(-1)

    if 'REP_PUB_KEY' not in state:
        logger.error("Must set the Repository Public Key")
        sys.exit(-1)

    session_file = state["session_file"]

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
        logger.info("Document metadata retrieved")
        with open(state["document_name"], 'wb') as f:
            f.write(decrypt_body(req.content, secret_key, mac_key))

        logger.info(f"File '{state["document_name"]}' downloaded successfully")
       
    else:
        if req.headers["content-type"] == "application/octet-stream":
            logger.error(json.loads(decrypt_body(req.content, secret_key, mac_key)))
        else:
            logger.error(req.json())

if __name__ == "__main__":
    main()

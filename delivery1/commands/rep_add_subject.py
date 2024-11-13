#!/usr/bin/env python3

import logging
import sys

import requests
from common import parse_args, parse_env

logging.basicConfig(format="%(levelname)s\t- %(message)s")
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def main():
    state = parse_env({})
    positional_args = ["session file", "username", "name", "email", "credentials file"]
    state = parse_args(state, positional_args)
    state = state[2:4]

    if 'REP_ADDRESS' not in state:
        logger.error("Must define Repository Address")
        sys.exit(-1)

    if 'REP_PUB_KEY' not in state:
        logger.error("Must set the Repository Public Key")
        sys.exit(-1)


    

    credentials_file = state["credentials file"]
    with open(credentials_file, "rb") as f:
        credentials = f.read()
        salt=credentials[0:16]
    
    with open(credentials_file, "r") as f:
        pub_key = f.read()
        pub_key = pub_key[16:].encode()

    if not salt:
        logger.error("Salt not found in credentials file")
        sys.exit(-1)

    state["pub key"] = pub_key

    session_file = state["session file"]
    with open(session_file, "r") as f:
        session = f.read()

    state["org_name"] = org_name
    body = {
        "username": state["username"],
        "name": state["name"],
        "email": state["email"],
        "pub key" : state["pub key"],
        "org_name": state["org_name"]
    }
      
    req = requests.post(f'http://{state['REP_ADDRESS']}/subject/create', json=body)

    if req.status_code == 201:
        logger.info("Subject created")
        logger.info(req.json())
    else:
        logger.error(req.json())
        sys.exit(-1)

if __name__ == "__main__":
    main()

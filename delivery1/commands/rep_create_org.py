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
    positional_args = ["organization", "username", "name", "email", "pub_key_file"]
    state = parse_args(state, positional_args)

    if 'REP_ADDRESS' not in state:
        logger.error("Must define Repository Address")
        sys.exit(-1)

    if 'REP_PUB_KEY' not in state:
        logger.error("Must set the Repository Public Key")
        sys.exit(-1)


    pub_key_file = state["pub_key_file"]

    with open(pub_key_file, "r") as f:
        pub_key = f.read()

    body = {
        "organization": state["organization"],
        "username": state["username"],
        "name": state["name"],
        "email": state["email"],
        "pub_key": pub_key
    }
      
    req = requests.post(f'http://{state['REP_ADDRESS']}/organization/create', json=body)

    if req.status_code == 201:
        logger.info("Organization created")
        logger.info(req.json())
    else:
        logger.error(req.json())
        sys.exit(-1)

if __name__ == "__main__":
    main()

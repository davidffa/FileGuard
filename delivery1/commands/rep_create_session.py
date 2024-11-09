#!/usr/bin/env python3

import logging
import sys

import requests
from common import parse_args, parse_env

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logging.basicConfig(format="%(levelname)s\t- %(message)s")
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def main():
    state = parse_env({})
    positional_args = ["organization", "username", "password", "credentials_file", "session_file"]
    state = parse_args(state, positional_args)

    if 'REP_ADDRESS' not in state:
        logger.error("Must define Repository Address")
        sys.exit(-1)

    if 'REP_PUB_KEY' not in state:
        logger.error("Must set the Repository Public Key")
        sys.exit(-1)

      
    credentials_file = state["credentials_file"]
    session_file = state["session_file"]
    password = state["password"]

    with open(credentials_file, "rb") as f:
        credentials = f.read()
        salt=credentials[0:16]
    
    with open(credentials_file, "r") as f:
        real_pub_key = f.read()
        real_pub_key = real_pub_key[16:].encode()

    print(salt)
    print(real_pub_key)

    if not salt:
        logger.error("Salt not found in credentials file")
        sys.exit(-1)
    
    
    body = {
        "organization": state["organization"],
        "username": state["username"],
    }
      
    req = requests.post(f'http://{state["REP_ADDRESS"]}/organization/create/session', json=body)

    if req.status_code == 201:
        logger.info("Session created")
        logger.info(req.json())
        with open(session_file, "w") as f:
            f.write("Organization: "+req.json()["Organization"] + "\n")
            f.write(req.json()["Session"] + "\n")
    
    else:
        logger.error(req.json())
        sys.exit(-1)


    


    

if __name__ == "__main__":
    main()

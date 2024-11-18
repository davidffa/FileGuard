#!/usr/bin/env python3

import logging
import sys
import requests
import base64
from common import parse_args, parse_env
from crypto import encrypt_aes256_cbc, sha256_digest

logging.basicConfig(format="%(levelname)s\t- %(message)s")
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def main():
    state = parse_env({})
    positional_args = ["session_file"]
    optional_args = ["username"]
    state = parse_args(state, positional_args, optional_args)

    
    if 'REP_ADDRESS' not in state:
        logger.error("Must define Repository Address")
        sys.exit(-1)

    if 'REP_PUB_KEY' not in state:
        logger.error("Must set the Repository Public Key")
        sys.exit(-1)

    session_file = state["session_file"]
    subject = state["username"]
    

    with open(session_file, "rb") as f:
        session = base64.b64encode(f.read())

    headers = {
        "session": session
    }

      
    req = requests.get(f'http://{state["REP_ADDRESS"]}/organization/subjects', headers=headers)

    if req.status_code == 200:
        
        data= req.json()
        if subject is not None and subject in data:
            logger.info(f"{subject}: {data[subject]}")
        else:
            logger.info(f"Subjects list on current Organization:")
            for subject in data:
                logger.info(f"{subject}: {data[subject]}")
        
    else:
        logger.error(req.json())
        sys.exit(-1)

if __name__ == "__main__":
    main()
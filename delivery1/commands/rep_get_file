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
    positional_args = ["file_handle"]
    optional_args = ["file"]
    state = parse_args(state, positional_args, optional_args)

    if 'REP_ADDRESS' not in state:
        logger.error("Must define Repository Address")
        sys.exit(-1)

    if 'REP_PUB_KEY' not in state:
        logger.error("Must set the Repository Public Key")
        sys.exit(-1)

    file_handle = state["file_handle"]
    file = state["file"]


    req = requests.get(f'http://{state["REP_ADDRESS"]}/files/{file_handle}')

    if req.status_code == 200:
        logger.info("File given with success")
        if file != None : 
            with open(file, 'wb') as f:
                f.write(req.content)
        else:
            sys.stdout.buffer.write(req.content)
    else:
        logger.error(req.json())
        sys.exit(-1)

if __name__ == "__main__":
    main()

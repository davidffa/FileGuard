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
    positional_args = []
    state = parse_args(state, positional_args)

    if 'REP_ADDRESS' not in state:
        logger.error("Must define Repository Address")
        sys.exit(-1)

    if 'REP_PUB_KEY' not in state:
        logger.error("Must set the Repository Public Key")
        sys.exit(-1)

      
    req = requests.get(f'http://{state["REP_ADDRESS"]}/organization/list')

    if req.status_code == 200:
        logger.info("Organizations List:")
        for org in req.json():
            logger.info(org)
        
    else:
        logger.error(req.json())
        sys.exit(-1)

if __name__ == "__main__":
    main()

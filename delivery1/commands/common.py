import argparse
import logging
import os
import sys

from crypto import (compute_hmac, decrypt_aes256_cbc, encrypt_aes256_cbc,
                    verify_hmac)

logging.basicConfig(format="%(levelname)s\t- %(message)s")
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def parse_env(state):
    if 'REP_ADDRESS' in os.environ:
        state['REP_ADDRESS'] = os.getenv('REP_ADDRESS')
        logger.debug('Setting REP_ADDRESS from Environment to: ' + state['REP_ADDRESS'])

    if 'REP_PUB_KEY' in os.environ:
        rep_pub_key = os.getenv('REP_PUB_KEY')
        logger.debug('Loading REP_PUB_KEY fron: ' + state['REP_PUB_KEY'])
        if rep_pub_key is not None and os.path.exists(rep_pub_key):
            with open(rep_pub_key, 'r') as f:
                state['REP_PUB_KEY'] = f.read()
                logger.debug('Loaded REP_PUB_KEY from Environment')
    return state

def parse_args(state, positional_args, optional_args=[]):
    parser = argparse.ArgumentParser()

    parser.add_argument("-k", '--key', nargs=1, help="Path to the key file")
    parser.add_argument("-r", '--repo', nargs=1, help="Address:Port of the repository")
    parser.add_argument("-v", '--verbose', help="Increase verbosity", action="store_true")

    for arg in positional_args:
        parser.add_argument(arg)

    for arg in optional_args:
        parser.add_argument(arg, nargs='?', default=None)

    args = parser.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.info('Setting log level to DEBUG')

    if args.key:
        if not os.path.exists(args.key[0]) or not os.path.isfile(args.key[0]):
            logger.error(f'Key file not found or invalid: {args.key[0]}')
            sys.exit(-1)

        with open(args.key[0], 'r') as f:
            state['REP_PUB_KEY'] = f.read()
            logger.info('Overriding REP_PUB_KEY from command line')

    if args.repo:
        state['REP_ADDRESS'] = args.repo[0]
        logger.info('Overriding REP_ADDRESS from command line')

    for arg in positional_args:
        state[arg] = getattr(args, arg)

    for arg in optional_args:
        state[arg] = getattr(args, arg)

    return state

def encrypt_body(body: bytes, secret_key: bytes, mac_key: bytes) -> bytes:
    iv = os.urandom(16)
    cipherbody = iv + encrypt_aes256_cbc(body, secret_key, iv)
    mac = compute_hmac(cipherbody, mac_key)

    return cipherbody + mac

def decrypt_body(data: bytes, secret_key: bytes, mac_key: bytes) -> bytes:
    if len(data) < 16 + 32:
        raise Exception("Message is too short")

    iv = data[:16]
    cipherbody = data[16:-32]
    mac = data[-32:]

    if not verify_hmac(iv + cipherbody, mac, mac_key):
        raise Exception("Integrity verification failed")

    return decrypt_aes256_cbc(secret_key, iv, cipherbody)

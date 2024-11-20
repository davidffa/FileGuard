import argparse
import json
import logging
import os
import sys
from typing import Tuple

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

def load_session(session_file: str) -> Tuple[str, int, bytes, bytes]:
    """
    Loads the session file
    Returns a tuple with (session_id, sequence number, secret key, mac key)
    """
    logger.info("Loading session...")

    with open(session_file, "rb") as f:
        data = f.read()

    json_size = int.from_bytes(data[:2], "big")
    json_data = json.loads(data[2:2+json_size])
    seq = int.from_bytes(data[2+json_size:2+json_size+4], "big")
    secret_key = data[2+json_size+4:2+json_size+4+32]
    mac_key = data[2+json_size+4+32:2+json_size+4+64]

    logger.info(f"Session file loaded. Session ID = {json_data['id']} Sequence number = {seq}")
    
    return json_data["id"], seq, secret_key, mac_key

def update_session_sequence(session_file: str):
    with open(session_file, "rb") as f:
        data = f.read()

    # Increment sequence number
    seq = int.from_bytes(data[-64-4:-64]) + 1

    new_data = data[:-64-4:] + seq.to_bytes(4, "big") + data[-64:]

    with open(session_file, "wb") as f:
        f.write(new_data)

def encrypt_body(body: bytes, seq: int, secret_key: bytes, mac_key: bytes) -> bytes:
    iv = os.urandom(16)
    cipherbody = iv + encrypt_aes256_cbc(body, secret_key, iv) + seq.to_bytes(4, "big")
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

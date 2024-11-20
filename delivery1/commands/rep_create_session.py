#!/usr/bin/env python3

import base64
import logging
import sys

import requests
from common import decrypt_body, parse_args, parse_env
from crypto import (derive_ec_priv_key, ecdh_shared_key, generate_ec_keypair,
                    load_pub_key, serialize_pub_key, sign_ec_dsa)

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
    
    if not salt:
        logger.error("Salt not found in credentials file")
        sys.exit(-1)

    priv_key = derive_ec_priv_key(password, salt)

    ephemeral_priv_key, ephemeral_pub_key = generate_ec_keypair()

    serialized_pub_key = serialize_pub_key(ephemeral_pub_key)

    body = {
        "organization": state["organization"],
        "username": state["username"],
        "ephemeral_pub_key": serialized_pub_key.decode("utf8"),
    }

    signature = sign_ec_dsa(priv_key, bytes(state["organization"], "utf8") + bytes(state["username"], "utf8") + serialized_pub_key)

    body["signature"] = base64.b64encode(signature).decode("utf8")

    req = requests.post(f'http://{state["REP_ADDRESS"]}/organization/create/session', json=body)

    if req.status_code == 201:
        server_pub_key = load_pub_key(state["REP_PUB_KEY"].encode("utf8"))

        # Key size of 64 (32 for symmetric cryptography and 32 for MAC encryption)
        key = ecdh_shared_key(ephemeral_priv_key, server_pub_key, 64) 

        secret_key = key[:32]
        mac_key = key[32:]

        try:
            response = decrypt_body(req.content, secret_key, mac_key)
        except Exception as e:
            logger.error(f"An error ocurred when parsing the server response")
            logger.error(e)
            sys.exit(1)

        with open(session_file, "wb") as f:
            json_size = len(response).to_bytes(2, "big")
            f.write(json_size + response)
            seq = 0
            f.write(seq.to_bytes(4, "big"))
            f.write(secret_key + mac_key)

        logger.info("Session created")
    else:
        logger.error(req.json())
        sys.exit(-1)

if __name__ == "__main__":
    main()

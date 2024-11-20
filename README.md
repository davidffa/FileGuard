[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/n4Xu0y1X)
[![Open in Visual Studio Code](https://classroom.github.com/assets/open-in-vscode-2e0aaae1b6195c2367325f4f02e2d04e9abb55f0b24a779b69b11b9e10269abc.svg)](https://classroom.github.com/online_ide?assignment_repo_id=16739588&assignment_repo_type=AssignmentRepo)
# sio_2425_project

# Group members
- David Amorim - 112610
- Francisca Silva - 112841
- Guilherme Amaral - 113207

# Project Specifications (Delivery 1)
For the first delivery of the project the following methods and strategies where implemented.
## Repository
From the server side, persistence of documents, organizations and subjects was implemented using PostgreSQL as a database. The files and metadata are saved on disk.
Sessions are not persistent, which means, in case of server restart, all previous sessions stop being valid.
The server master_key is derived from a password asked by the server once it starts (in case of using our docker compose file, the password is pre-defined). This master_key will be used to create the repository public_key, that should be known by each client.
## Security and Integrity of Communications between Client-Server
To garantee the confidentiality and integrity between client-server, inside and outside a session, we did the following steps when executing the rep_create_session.py command:
 - We start by generating an ephemeral EC key pair on the client side.
 - We construct a JSON object with the organization name, the subject's username, and the generated EC public key.
 - Using the private key derived from the password (using PBKDF2 to derive an EC private key), we sign the contents of the JSON object created above.
 - We send the JSON content and the signature to the server in plaintext.
 - Since the server already has the public key derived from the password stored in its database (it would have been sent previously, either during rep_create_org or rep_add_subject), it validates the JSON content against the signature using this public key.
 - If the validation is successful, the server accepts the request and derives a shared secret using ECDH (one part will be used for symmetric encryption, and the other part will be used for MACs).
 - The server responds with a session_id encrypted symmetrically using the derived key.
 - The client, already having the server's public key, derives the shared secret via ECDH.
 - The client decrypts the server's response content using the first part of the shared secret (after validating the MAC).
 - The client stores the keys and the session_id in the session file, and the server stores them in memory (in a Python dictionary...).
  From now on, all information shared between commands that require a session can be encrypted with the shared secret, using the keys stored by both sides, along with a MAC to garantee integrity and authentication.
## Local Commands Implemented 
```console
rep_subject_credentials <password> <credentials file>
rep_decrypt_file <encrypted file> <encryption metadata>
```
## Anonymous Commands Implemented
```console
rep_create_org <organization> <username> <name> <email> <public key file>
rep_list_orgs
rep_create_session <organization> <username> <password> <credentials file> <session file>
rep_get_file <file handle> [file]
```
## Authenticated Commands Implemented
```console
rep_list_subjects <session file> [username]
rep_list_docs <session file> [-s username] [-d nt/ot/et date]
```
## Authorized Commands Implemented
```console
rep_add_subject <session file> <username> <name> <email> <credentials file>
rep_suspend_subject <session file> <username>
rep_activate_subject <session file> <username>
rep_add_doc <session file> <document name> <file>
rep_get_doc_metadata <session file> <document name>
rep_get_doc_file <session file> <document name> [file]
rep_delete_doc <session file> <document name>
```

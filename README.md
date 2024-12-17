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
From the server side, persistence of documents, organizations and subjects were implemented using PostgreSQL as a database. The files and metadata are saved on disk.
Sessions are not persistent, which means, in case of server restart, all previous sessions stop being valid.
The server master_key is derived from a password asked by the server once it starts (in case of using our docker compose file, the password is pre-defined). This master_key will be used to create the repository public_key, that should be known by each client and will be stored with the name repo_key.pub when the repository is started for the first time. This master_key also will be used to derive a symmetric key, that will be used to encrypt the document's metadata locally.

> [!IMPORTANT]  
> The implementation of session creation changed slightly in the delivery 2, see in the delivery 2 part the new implementation

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

## Ciphering of client <-> server communications in sessioned commands

We load the session file and get the session_id, the sequence number, the secret key and mac key.
In every sessioned request, we send the header `sessionid: SESSION UUID VALUE`.
In client -> server request we send the body
```
IV + encrypted json + sequence number (4 bytes big endian) + MAC(IV+ encrypted json + seq number)
```
In server -> client response we send
```
IV + encrypted json + MAC(IV + encrypted json)
```

In every request, the server validates the request body with the MAC. If that verification passes, the server gets the sequence number provided by the client and compares with its own (in the session context stored in the server's memory). If they match, the server continues processing the request, **preventing replay attacks**

After every sessioned request, the client increments its sequence number and updates the session file

## Session file
The current session file structure is:
```
| json size (2 bytes big endian) | json with { "session_id": "uuid", "expires_at": "timestamp", } | sequence number (4 bytes big endian) | 32 bytes secret key for encryption | 32 bytes secret key for MAC calculation |
```

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

# Project Specifications (Delivery 2)

For the second delivery, we implemented a role-based authorization system. For the documents' ACLs, we have decided to set all the permissions for the roles that the user has in the current session to a newly added document by that subject.

## Secure Communications

In the first delivery, we only implemented secure communications for session-based API endpoints. For this delivery we also implemented secure communications for the remaining API routes (rep_get_file, rep_list_orgs and rep_create_org). We now also encrypt the body when we create a session client->server interaction.

## Sessions

Now, the create session flow is the following:

- We start by generating an ephemeral EC key pair on the client side.
- We construct a JSON object with the organization name and the subject's username.
- Using the private key derived from the password (using PBKDF2 to derive an EC private key), we sign the ephemeral pub key and the contents of the JSON object created above.
- The client, already having the server's public key, derives a 64 byte shared secret via ECDH.
- The first 32 bytes of the shared secret is the symmetric key and the last 32 bytes is used for HMAC.
- We construct the packet `|json_size|json|signature|`.
- We encrypt that packet with AES256_CBC with the derived symmetric key. Lets call this encrypted packet ciphered_body.
- We construct the final packet `|eph_pub_key_size|eph_pub_key|ciphered_body|` and send it to the server.
- The server extracts the ephemeral public key, derives the same shared secret as the client, and uses the symmetric key to decrypt the `ciphered_body`.
- Since the server already has the public key derived from the password stored in its database (it would have been sent previously, either during rep_create_org or rep_add_subject), it validates the ephemeral public key and the JSON content against the signature using this public key.
- If the validation is successful, the server accepts the request and sends a encrypted packet containing the generated session id (UUID) and a HMAC calculated for the encrypted body.
- The client, after validating the MAC, decrypts the server's response content using the first part of the shared secret.
- The client stores the keys and the session_id in the session file, and the server stores them in memory, so if the server goes down, all sessions are automatically invalidated.

From now on, all information shared between commands that require a session can be encrypted with the shared secret, using the keys stored by both sides, along with a sequence number (incremented every sessioned request) and a MAC to garantee integrity and authentication.

### Authentication
As the ephemeral pub key and json body containing the organization and subject name are signed with the subject's private key, the server can authenticate the subject. This authentication is transitive, because in the subsequent requests in a session, the server identifies a subject by a session_id, and even if someone stoles the session_id, that would be useless, because they must also know the ephemeral private key and the current message sequence number, in order to communicate with the server using that session.

## Permissions

For ACLs we decided to use bitfields to store the permissions as an integer in the database.

## Doc ACL

When creating a document, we decided to give all documents related permissions (DOC_READ; DOC_ACL; DOC_DELETE) to all the roles that the uploader subject has in its current session.

## Features

All the requested commands were implemented.

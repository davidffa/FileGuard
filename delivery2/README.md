# Group members
- David Amorim - 112610
- Francisca Silva - 112841
- Guilherme Amaral - 113207

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

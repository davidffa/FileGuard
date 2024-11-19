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

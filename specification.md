# Project Specification
The goal of this project is to develop a Repository for documents for organizations that can be securely shared among several people. Each group would have to implement the Repository service, which must use an interface compatible with a set of commands provided in this guide.

## High-level functionalities
## Documents and files
Each document stored in the Repository contains a file (the fundamental information container) and metadata (auxiliary information about the file). Files are always provided by the clients, and stored in a encrypted format.

The metadata is stored in plaintext, and is mostly publicly available; the only exception are the items relatively to the file encryption.

The public metadata must include the following elements:

- document_handle: Document handle for efficient referencing
- name: Document name for name-handle resolution
- create_date: Creation date
- creator: Reference to the subject that created the file
- file_handle: Handle of its file (for uniform file referencing)
- acl: Access control list (ACL)
- deleter: Reference to the subject that deleted the file
The non-public (or restricted) metadata must include the following elements:

- alg: Description of the cryptographic procedures used to protect the file (with encryption and integrity control)
- key: Key used to encrypt the file.
The ACL can specify, for each a given role, the following permissions:

- DOC_ACL: Modify the Access Control List
- DOC_READ: Read the file content
- DOC_DELETE: Delete the associated file content
The delete operation does not destroy information, it just clears the file_handle. Upon a delete operation, the file’s contents remain available to those that know their file_handle and encryption key. The metadata of deleted documents must register the subject that deleted it using the deleter field.

A DOC_ACL access right allows a role holder to add or remove access rights for other roles. At least one role must keep this right for each document, in order to allow an ACL to be updated.

A DOC_READ access right allows a role holder to read the encrypted file contents and to decrypt them upon recovering the encryption key.

A DOC_DELETE access right allows a role holder to clear the file_handle in a document metadata.

Documents’ metadata must be stored in a physical storage (e.g. a database or a file system), which is different from the one used to store the related files. The keys used to encrypt documents’ files must be stored encrypted by the Repository.

Files can be publicly accessible given their file_handle, while the document’s metadata, given its sensitivity, must have a controlled access.

## Organizations
Documents are associated to organizations. The Repository maintains a list of known organizations, and each organization has its own list of documents. Organizations can be universally listed, as well as the public metadata of their documents.

Each organization has an ACL for governing who manages it (a Manager subject). When an organization is created, it is the subject that created it that has full control over the organization’s ACL. This is done by having a Manager role (see below), which is available to this first subject.

Relatively to the management of an organization, there are the following permissions relatively to its ACL:

- ROLE_ACL: Modify the ACL. At least one role must have this permission.
- SUBJECT_NEW: Add a new subject, allowing a role to add a new subject to the organization.
- SUBJECT_DOWN: Suspend a subject, allowing a role to suspend the association of a subject with the organization, while not removing its profile.
- SUBJECT_UP: Reactivate a subject, allowing a role to put an end on a subject’s suspension.
- DOC_NEW: Add a new document, allowing a role to add a new document to the organization’s repository.
Any subject from an organization can list its subjects and if they are suspended (down) or active (up).

## Subjects
Subjects are people or applications that interact with the Repository, associated to one or more organizations. All subjects hold one or more key pairs, and their public keys are available in the Repository. When subjects are associated to one organization, they choose an existing or new public key for that context.

Each subject must have a set of well-defined identity attributes in their association profile. We will consider 4:

- username;
- full_name;
- email;
- public_key.

## Sessions
In order to interact with the Repository, subjects make use of sessions. A session is a security context between the Repository and a subject. Each session must have an identifier and one or more keys. The identifier is used to identify interactions within the session, while the keys are some data items used for actually securing the interactions.

A session always implicitly refers to one specific Repository organization. A session is created upon a login operation in that organization, performed with the credentials that the organization maintains about the subject. It is possible for a subject to maintain simultaneous sessions with different organizations in the Repository.

The session keys must be used to enforce the confidentiality (when necessary) and the integrity (correctness and freshness) of messages exchanged during a session. Different keys can be used for the different protections, if deemed necessary.

Sessions must be robust to the following attacks:

- **Eavesdropping:** a passive attacker cannot have access to the content being exchanged. Therefore, the contents must be kept confidential.
- **Impersonation:** an active attacker cannot be able to pose as a victim subject or the Repository. Therefore, authentication of sessions (login) and interactions should be implemented.
- **Manipulation:** an active attacker cannot manipulate data exchanged within a session. Therefore, there must be integrity controls.
- **Replay:** an attacker cannot be able to replay and interaction that took place within a session. Therefore, the software must be able to detect out of order or past messages.
Sessions have a lifetime defined by the Repository, and should be deleted upon a period of inactivity.

## Roles
Subjects are associated with roles, and their rights in the organization stem from the roles they assume. This means that all documents’ ACLs must link access rights to roles, and not to subjects.

Note that here we are mixing two concepts. Roles are usually used when the granularity of per data protection with an ACL is not useful (e.g. when accessing a database for a given operation) and roles have permissions in their definition. However, we can use roles in the standard way and still use them as subjects in document’s ACLs. In this sense, they act as groups of subjects in normal ACLs.

By default, subjects have no default role upon logging in into a session. They need to explicitly ask for a role they are bound to, and can do so for more than one role per session. They can also release a role during the session. The set of roles associated to each session is stored by the Repository, in the context of each active session.

Each organization can have a variable set of roles, which regulate the manipulation of the Repository for that organization.

Each role as a name, a set of permissions and a list of subjects. It is possible, for any subject of an organization, to perform role-subject reviews (to query which users have a role and which roles a subject can assume) and permission-role reviews (to query which roles have a permission and which permissions a role has) of its organization. Subjects not belonging to an organization cannot do these operations.

Relatively to the management of roles, there are the following permissions:

- ROLE_NEW: Add a new role, allowing a role to add a new role to the organization that the requesting subject belongs to.
- ROLE_DOWN: Suspend a role, allowing a role to suspend a role from being assumed by subjects of an organization.
- ROLE_UP: Reactivate a role, allowing a role to put an end on a role’s suspension.
- ROLE_MOD: Update a role, allowing a role to add/remove a subject to/from an existing role or add/remove a permission to/from an existing role.

The set of roles is open, but the following role must exist:

- Managers: This is, by default, the role that has the full set of permissions on an organization.
This role is created by default when an organization is created by a subject, and that subject initially belongs to it. However, this relationship can change over time.

The manipulation of roles and subjects is liberal (everything is regulated by the discretionary permissions given) with two exceptions:

- The Managers can never be suspended.
- The Managers role must have at any time an active subject (not suspended).

## Fundamental Repository operations

## Upload a new document
A subject logs-in to the Repository, within one organization, selects one of its roles with a permission to add a new document.

A random encryption key (file key) is generated by the uploader, and is used to encrypt the document’s file. The subject then uploads the document with:

- the encrypted file;
- some of its metadata (name, file handle, encryption key and cryptographic descriptions, ACL).
The file_handle should be a digest (cryptographic hash) of the original file contents, a value that the Repository must verify.

## Download a document
A subject logs-in in to the Repository, within one organization, and selects one of its roles with a permission to read a given document. Then it gets confidentially the document’s metadata (namely, file handle, encryption algorithms alg and encryption key), fetches the encrypted file using the file handle, decrypts it and verifies if its contents are correct (using again the file_handle).

## Delete a document
A subject logs-in in to the Repository, within one organization, and selects one of its roles with a permission to delete a given document. Then it deletes the document’s and receives, confidentially and for its own future record, the file_handle, the encryption algorithms alg and the encryption key.

## Mandatory API
In this session we list the interface (API) of the Repository that can be used by client applications to deal with it. The parameters of each API endpoint are defined in each implementation.

## Anonymous API
The anonymous API is formed by a set of endpoints that can be used without a session.

- Create organization
- List organizations
- Create session
- Download file (note that for this you need to know the file handle)

## Authenticated API
The authenticated API is formed by a set of endpoints that require a session, but not a role.

- Assume session role
- Release session role
- List session roles
- List subjects (of my organization)
- List roles (from my organization)
- List the subjects in one of my organization’s roles
- List the roles of one of my organization’s subjects
- List the permissions in one of my organization’s roles
- List the roles that have a given permission
- List documents (with filtering options, such as dates or creators).

## Authorized API
The authorized API is formed by a set of endpoints that require a session and at least a role bound to it. The effect of the commends is reflected on in the organization to which the subject has a session to.

- Add subject
- Change subject status (suspend/reactivate)
- Add role
- Change role status (suspend/activate)
- Add/remove subject to role
- Add/remove permission to role
- Upload a document
- Download a document metadata
- Delete a document
- Change document ACL

## Security guidelines
The Repository must have a well-known public key that client applications can use for confidentiality and source authentication. This key must be used to protect anonymous client-Repository interactions that require some security protection (not all of them require).

Authenticated and authorized APIs must always use session keys for adding confidentiality to sensitive items and add integrity control and source authentication.

The Repository should use some kind of master key, possibly derived from a password, to protect the confidentiality of file’s keys.

You cannot use any existing technology for the protection of communications, such as SSL/TLS, SSH or any other.

## Implementation guidelines
For facilitating the authentication of subjects, you can use elliptic cryptography (EC) key pairs for subjects and for the Repository. EC private keys can be very easily produced deterministically from passwords.

Implement one console application (a command) for each API function.

Each command that produces a useful persistent result (e.g. a session key upon a login, a file_handle and a file key upon getting a document metadata, etc.) should be able to save that into a state file, in order to be used by other commands.

The exact command syntax is provided below and must be respected to conduct evaluation tests. All commands should follow the UNIX semantics of returning 0 in case of success, a positive value in case of input errors, and a negative value in case of errors reported by the Repository.

Since the Repository’s public key, stored in a file, must be used in some commands, you can use the environment variable REP_PUB_KEY to indicate its path. However, each command has the possibility to override this default setting using the -k file option.

Also for the Internet address of the Repository, it must be indicated in all the commands that interact with the Repository. You can use the environment variable REP_ADDRESS to indicate its IP address and port number. However, each command has the possibility to override this default setting using the -r IP:port option.

If using python, the following snippet may help:

```py
import os
import sys
import argparse
import logging
import json
import requests

logging.basicConfig(format='%(levelname)s\t- %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def load_state():
    state = {}
    state_dir = os.path.join(os.path.expanduser('~'), '.sio')
    state_file = os.path.join(state_dir, 'state.json')

    logger.debug('State folder: ' + state_dir)
    logger.debug('State file: ' + state_file)

    if os.path.exists(state_file):
        logger.debug('Loading state')
        with open(state_file,'r') as f:
            state = json.loads(f.read())

    if state is None:
        state = {}

    return state

def parse_env(state):
    if 'REP_ADDRESS' in os.environ:
        state['REP_ADDRESS'] = os.getenv('REP_ADDRESS')
        logger.debug('Setting REP_ADDRESS from Environment to: ' + state['REP_ADDRESS'])

    if 'REP_PUB_KEY' in os.environ:
        rep_pub_key = os.getenv('REP_PUB_KEY')
        logger.debug('Loading REP_PUB_KEY fron: ' + state['REP_PUB_KEY'])
        if os.path.exists(rep_pub_key):
            with open(rep_pub_key, 'r') as f:
                state['REP_PUB_KEY'] = f.read()
                logger.debug('Loaded REP_PUB_KEY from Environment')
    return state

def parse_args(state):
    parser = argparse.ArgumentParser()

    parser.add_argument("-k", '--key', nargs=1, help="Path to the key file")
    parser.add_argument("-r", '--repo', nargs=1, help="Address:Port of the repository")
    parser.add_argument("-v", '--verbose', help="Increase verbosity", action="store_true")
    parser.add_argument("-c", "--command", help="Command to execute")
    parser.add_argument('arg0', nargs='?', default=None)
    parser.add_argument('arg1', nargs='?', default=None)
    parser.add_argument('arg2', nargs='?', default=None)
    parser.add_argument('arg3', nargs='?', default=None)
    parser.add_argument('arg4', nargs='?', default=None)
    parser.add_argument('arg5', nargs='?', default=None)

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
    
    if args.command:
        logger.info("Command: " + args.command)
       
    return state, {'command': args.command, 'arg0': args.arg0, 'arg1': args.arg1, 'arg2': args.arg2, 'arg3': args.arg3, 'arg4': args.arg4, 'arg5': args.arg5}

def save(state):
    state_dir = os.path.join(os.path.expanduser('~'), '.sio')
    state_file = os.path.join(state_dir, 'state.json')

    if not os.path.exists(state_dir):
      logger.debug('Creating state folder')
      os.mkdir(state_dir)

    with open(state_file, 'w') as f:
        f.write(json.dumps(state, indent=4))


state = load_state()
state = parse_env(state)
state, args = parse_args(state)

if 'REP_ADDRESS' not in state:
  logger.error("Must define Repository Address")
  sys.exit(-1)

if 'REP_PUB_KEY' not in state:
  logger.error("Must set the Repository Public Key")
  sys.exit(-1)
  
""" Do something """
logger.debug("Arguments: " + str(args))



#rep_create_org <organization> <username> <name> <email> <public key file>
def rep_create_org(org, username, name, email, pubkey):
    print("rep_create_org: org=%s, username=%s, name=%s, email=%s, pubkey=%s" % (org, username, name, email, pubkey))
    
def rep_list_org():
    print("rep_list_org")

print("Program name:", args["command"])


if args["command"]  == "rep_create_org":
    rep_create_org(args["arg0"], args["arg1"], args["arg2"], args["arg3"], args["arg4"])

elif args["command"] == "rep_list_orgs":
    rep_list_org()
else:
  logger.error("Invalid command")
```

In order to have files with the individual commands, you can create multiple bash scripts. This will allow you to have one client and multiple files, one with each command. The following is an example for a file named rep_create_org, implementing the call to the client.py with the correct command:

```py
#!/bin/bash

# rep_create_org <organization> <username> <name> <email> <public key file>
python3 ./client.py rep_create_org $1 $2 $3 $4 $5
```

This file can be called as:

```console
./rep_create_org orgname username name email pubkeyfile
```

The base server would be:

```py
from flask import Flask
import json

app = Flask(__name__)

organizations = {}

@app.route("/organization/list")
def org_list():
    return json.dumps(organizations)

##@app.route("/organization/create")
##...
```

## Commands
This section lists the name an arguments of all the commands that need to be implemented.

## Local commands
These commands work without any interaction with the Repository.

```console
rep_subject_credentials <password> <credentials file>
```
This command does not interact with the Repository and creates a key pair for a subject, storing it in a credentials file. This credentials file acts as a secure key vault. You can either create a file with a private/public key pair, and encrypt the private component with the password (e.g. if using RSA), or you can use directly the password to generate a private key and store the public key in a file for verification (e.g. if using ECC).

Should be implemented in the first delivery.

```console
rep_decrypt_file <encrypted file> <encryption metadata>
```
This command sends to the stdout the contents of an encrypted file upon decryption (and integrity control) with the encryption metadata, that must contain the algorithms used to encrypt its contents and the encryption key.

Should be implemented in the first delivery.

Commands that use the anonymous API
```console
rep_create_org <organization> <username> <name> <email> <public key file>
```
This command creates an organization in a Repository and defines its first subject.

Should be implemented in the first delivery.

```console
rep_list_orgs
```
This command lists all organizations defined in a Repository. Should be implemented in the first delivery.

Should be implemented in the first delivery.

```console
rep_create_session <organization> <username> <password> <credentials file> <session file>
```
This command creates a session for a username belonging to an organization, and stores the session context in a file.

Should be implemented in the first delivery.

```console
rep_get_file <file handle> [file]
```
This command downloads a file given its handle. The file contents are written to stdout or to the file referred in the optional last argument.

Should be implemented in the first delivery.

## Commands that use the authenticated API
All these commands use as first parameter a file with the session key.

```console
rep_assume_role <session file> <role>
```
This command requests the given role for the session

Should be implemented in the second delivery.

```console
rep_drop_role <session file> <role>
```
This command releases the given role for the session

Should be implemented in the second delivery.

```console
rep_list_roles <session file> <role>
```
This command lists the current session roles

Should be implemented in the second delivery.

```console
rep_list_subjects <session file> [username]
```
This command lists the subjects of the organization with which I have currently a session. The listing should show the status of all the subjects (active or suspended). This command accepts an extra command to show only one subject.

Should be implemented in the first delivery.

```console
rep_list_role_subjects <session file> <role>
```
This command lists the subjects of a role of the organization with which I have currently a session.

Should be implemented in the second delivery.

```console
rep_list_subject_roles <session file> <username>
```
This command lists the roles of a subject of the organization with which I have currently a session.

Should be implemented in the second delivery.

```console
rep_list_role_permissions <session file> <role>
```
This command lists the permissions of a role of the organization with which I have currently a session.

Should be implemented in the second delivery.

```console
rep_list_permission_roles <session file> <permission>
```
This command lists the roles of the organization with which I have currently a session that have a given permission. Use the names previously referred for the permission rights.<br>

As roles can be used in documents’ ACLs to associate subjects to permissions, this command should also list the roles per document that have the given permission. Note: permissions for documents are different from the other organization permissions.

Should be implemented in the second delivery.

```console
rep_list_docs <session file> [-s username] [-d nt/ot/et date]
```
This command lists the documents of the organization with which I have currently a session, possibly filtered by a subject that created them and by a date (newer than, older than, equal to), expressed in the DD-MM-YYYY format.

Should be implemented in the first delivery.

## Commands that use the authorized API
All these commands use as first parameter a file with the session key. For that session, the subject must have added one or more roles.

```console
rep_add_subject <session file> <username> <name> <email> <credentials file>
```
This command adds a new subject to the organization with which I have currently a session. By default the subject is created in the active status. This commands requires a SUBJECT_NEW permission.

Should be implemented in the first delivery.

```console
rep_suspend_subject <session file> <username>
rep_activate_subject <session file> <username>
```
These commands change the status of a subject in the organization with which I have currently a session. These commands require a SUBJECT_DOWN and SUBJECT_UP permission, respectively.

Should be implemented in the first delivery.

```console
rep_add_role <session file> <role>
```
This command adds a role to the organization with which I have currently a session. This commands requires a ROLE_NEW permission.

Should be implemented in the second delivery.

```console
rep_suspend_role <session file> <role>
rep_reactivate_role <session file> <role>
```
These commands change the status of a role in the organization with which I have currently a session. These commands require a ROLE_DOWN and ROLE_UP permission, respectively.

Should be implemented in the second delivery.

```console
rep_add_permission <session file> <role> <username>
rep_remove_permission <session file> <role> <username>
rep_add_permission <session file> <role> <permission>
rep_remove_permission <session file> <role> <permission>
```
These commands change the properties of a role in the organization with which I have currently a session, by adding a subject, removing a subject, adding a permission or removing a permission, respectively. Use the names previously referred for the permission rights. These commands require a ROLE_MOD permission.

Should be implemented in the second delivery.

```console
rep_add_doc <session file> <document name> <file>
```
This command adds a document with a given name to the organization with which I have currently a session. The document’s contents is provided as parameter with a file name. This commands requires a DOC_NEW permission.

Should be implemented in the first delivery.

```console
rep_get_doc_metadata <session file> <document name>
```
This command fetches the metadata of a document with a given name to the organization with which I have currently a session. The output of this command is useful for getting the clear text contents of a document’s file. This commands requires a DOC_READ permission.

Should be implemented in the first delivery.

```console
rep_get_doc_file <session file> <document name> [file]
```
This command is a combination of rep_get_doc_metadata with rep_get_file and rep_decrypt_file. The file contents are written to stdout or to the file referred in the optional last argument. This commands requires a DOC_READ permission.

Should be implemented in the first delivery.

```console
rep_delete_doc <session file> <document name>
```
This command clears file_handle in the metadata of a document with a given name on the organization with which I have currently a session. The output of this command is the file_handle that ceased to exist in the document’s metadata. This commands requires a DOC_DELETE permission.

Should be implemented in the first delivery.

```console
rep_acl_doc <session file> <document name> [+/-] <role> <permission>
```
This command changes the ACL of a document by adding (+) or removing (-) a permission for a given role. Use the names previously referred for the permission rights. This commands requires a DOC_ACL permission.

Should be implemented in the second delivery.

## Delivery and grading
Students must join a group of 3 elements and create a repository using github classroom. The enrollment link is available in the elearning platform.

The following deadlines should be considered:

NOTE: These are the deadlines for delivery. Students can prepare the work in advance. This is especially relevant for the last delivery.

Delivery 1: Nov 20th, 23:59

The repository should have a folder named delivery1 with:

a basic README.MD identifying the students, and the features implemented
implementation of the basic operation of the repository, without authentication and role management
test commands for all the features implemented
grading will focus on the features implemented
will award 30% of the practical grade
Delivery 2: Dec 17th, 23:59

The repository should have a folder named delivery2 with:

a basic README.MD identifying the students, and the features implemented
implementation of the full specification provided in this page
test commands for all the features implemented
grading will focus on the features implemented
will award 30% of the practical grade
Delivery 3: Dec 30th, 23:59 & defense in January 2nd-9th

The repository should have a folder named delivery3 with:

a report describing the features implemented and the decisions made by the group
an analysis of the software, under the scope of one chapter (V2, V3, V4 or V6) L3 of the ASVS
the analysis should focus on only one chapter
the chapter to be considered must be one of V2, V3, V4 or V6
for each control, students should describe if it is applicable or not, justifying the decision
if applicable, evidences should be provided to support the assessment
Regarding the grading:

grading will be based on the documentation provided, and the defense
the defense will be used to discuss the results, decisions and possible improvements
will award 40% of the practical grade

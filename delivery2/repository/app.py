import base64
import json
import os
import uuid
from argparse import ArgumentParser
from datetime import datetime
from functools import wraps

from cryptography.hazmat.primitives.asymmetric import ec
from flask import Response, g, jsonify, request
from src import create_app, db
from src.crypto import *
from src.models import Document, Organization, Role, Subject
from src.util import *

app = create_app()
master_key = bytes()
private_key = None

sessions = {}

def requires_session(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "sessionid" not in request.headers:
            res = { "message": "Please provide a session_id header" }
            return json.dumps(res), 401

        session_id = request.headers["sessionid"]

        if session_id not in sessions:
            res = { "message": "Invalid session" }
            return json.dumps(res), 400

        session = sessions[session_id]

        if datetime.now() > session.expires_at:
            del sessions[session_id]
            res = { "message": "Session expired" }
            return json.dumps(res), 400

        g.session = session
        g.org_id = session.org_id
        g.subject_id = session.subject_id

        data = request.data

        if len(data) == 0:
            if "data" not in request.files:
                res = { "message": "Message is too short" }
                return json.dumps(res), 400

            data = request.files["data"].read()

        # Must at least have the seq + MAC
        if len(data) < 4 + 32:
            res = { "message": "Message is too short" }
            return json.dumps(res), 400

        seq = int.from_bytes(data[-32 - 4:-32], "big")
        mac = data[-32:]

        if not verify_hmac(data[:-32], mac, session.mac_key):
            res = { "message": "Request body integrity check failed" }
            return json.dumps(res), 400

        if seq != session.seq:
            res = { "message": "Sequence number mismatch" }
            return json.dumps(res), 400

        # If we actually have a request body
        if len(data) > 32 + 4:
            iv = data[:16]
            ciphertext = data[16:-32 - 4]
            plaintext = decrypt_aes256_cbc(session.secret_key, iv, ciphertext)
            g.json = json.loads(plaintext)

        session.seq += 1

        return f(*args, **kwargs)

    return decorated

def encrypt_body(body: bytes, secret_key: bytes, mac_key: bytes) -> bytes:
    iv = os.urandom(16)

    data = iv + encrypt_aes256_cbc(body, secret_key, iv)
    mac = compute_hmac(data, mac_key)

    return data + mac

@app.route("/organization/list")
def org_list():
    return jsonify(Organization.query.all())

@app.route("/organization/create", methods=["POST"])
def create_org():
    if private_key is None:
        print("Something went wrong... We dont have our private key!")
        return "{}", 500

    data = request.data

    key_size = int.from_bytes(data[:2], "big")

    ephemeral_pub_key = load_pub_key(data[2:2+key_size])
    secret_key = ecdh_shared_key(private_key, ephemeral_pub_key, 32)
    iv = data[2+key_size:2+key_size+16]
    ciphertext = data[2+key_size+16:]

    body = json.loads(decrypt_aes256_cbc(secret_key, iv, ciphertext))

    existing_org = Organization.query.filter_by(name=body["organization"]).first()

    if existing_org is not None:
        res = { "message": "Organization already exists" }
        iv = os.urandom(16)

        return Response(
            iv + encrypt_aes256_cbc(json.dumps(res).encode("utf8"), secret_key, iv),
            content_type="application/octet-stream",
            status=400
        )

    org_name = body["organization"]
    username = body["username"]
    name = body["name"]
    email = body["email"]
    pub_key = body["pub_key"]

    org = Organization(name=org_name)
    db.session.add(org)
    db.session.flush()

    manager_role= Role(name="Manager", permissions=Org_ACL.ALL, org_id=org.id)
    db.session.add(manager_role)
    db.session.commit()

    subject = Subject(username=username, name=name, email=email, pub_key=pub_key, org_id=org.id)
    subject.roles.append(manager_role)
    db.session.add(subject)
    db.session.commit()

    signature = sign_ecdsa(private_key, json.dumps(body).encode("utf8"))

    return Response(
        signature,
        content_type="application/octet-stream",
        status=201
    )

@app.route("/document", methods=["POST"])
@requires_session
def add_doc():
    secret_key = g.session.secret_key
    mac_key = g.session.mac_key

    if "file" not in request.files:
        res = { "message": "Please provide a file" }
        return Response(
            encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
            content_type="application/octet-stream",
            status=400
        )

    org_id = g.org_id
    subject_id = g.subject_id

    encrypted_file = request.files["file"].read()
    cipher_file_secret_key = request.files["secret_key"].read()
    doc_iv = request.files["iv"].read()

    file_name = g.json["document_name"]
    file_handle = g.json["file_handle"]
    crypto_alg = g.json["crypto_alg"]
    digest_alg = g.json["digest_alg"]

    existent_doc = Document.query.filter_by(org_id=org_id, name=file_name).first()

    if existent_doc is not None:
        res = { "message": "A document with that name already exists" }
        return Response(
            encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
            content_type="application/octet-stream",
            status=400
        )

    if crypto_alg != "AES256_CBC":
        res = { "message": "Encryption algorithm not supported" }
        return Response(
            encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
            content_type="application/octet-stream",
            status=400
        )

    if digest_alg != "SHA256":
        res = { "message": "Digest algorithm not supported" }
        return Response(
            encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
            content_type="application/octet-stream",
            status=400
        )

    mac_file_sk = cipher_file_secret_key[-32:]

    if not verify_hmac(cipher_file_secret_key[:-32], mac_file_sk, mac_key):
        res = { "message": "MAC verification failed for the file secret key" }
        return Response(
            encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
            content_type="application/octet-stream",
            status=400
        )

    file_secret_key = decrypt_aes256_cbc(secret_key, cipher_file_secret_key[:16], cipher_file_secret_key[16:-36])

    decrypted_file = decrypt_aes256_cbc(file_secret_key, doc_iv, encrypted_file)

    if file_handle != sha256_digest(decrypted_file):
        res = { "message": "File integrity verification failed" }
        return Response(
            encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
            content_type="application/octet-stream",
            status=400
        )

    if not os.path.exists("./documents"):
        os.makedirs("./documents")

    with open(f"./documents/{file_handle}.bin", "wb") as f:
        f.write(encrypted_file)

    with open(f"./documents/{file_handle}-metadata.bin", "wb") as f:
        data = bytes(json.dumps({ "crypto_alg": "AES256_CBC", "digest_alg": "SHA256" }), "utf8")
        data_len = len(data)

        metadata = data_len.to_bytes(2, "big") + data + file_secret_key + doc_iv
        metadata_iv = os.urandom(16)

        f.write(metadata_iv + encrypt_aes256_cbc(metadata, master_key, metadata_iv))

    doc = Document(name=file_name, creator_id=subject_id, file_handle=file_handle, org_id=org_id)

    db.session.add(doc)
    db.session.commit()

    res = jsonify(doc)

    return Response(
        encrypt_body(json.dumps(res.json).encode("utf8"), secret_key, mac_key),
        content_type="application/octet-stream",
        status=201
    )


@app.route("/organization/create/session", methods=["POST"])
def create_session():
    if request.json is None:
        res = { "message": "Empty request body" }
        return json.dumps(res), 400

    org_name = request.json["organization"]
    username = request.json["username"]
    
    organization = Organization.query.filter_by(name=org_name).first()

    if organization is None:
        res = { "message": "Organization does not exist" }
        return json.dumps(res), 400

    subject = next((sub for sub in organization.subjects if sub.username == username), None)
    
    if subject is None:
        res = { "message": "Subject does not exist" }
        return json.dumps(res), 400

    serialized_pub_key = request.json["ephemeral_pub_key"].encode("utf8")
    ephemeral_pub_key = load_pub_key(serialized_pub_key)
    subject_pub_key = load_pub_key(subject.pub_key.encode("utf8"))
    signature = base64.b64decode(request.json["signature"])

    if not verify_ecdsa(subject_pub_key, bytes(org_name, "utf8") + bytes(username, "utf8") + serialized_pub_key, signature):
        res = { "message": "Could not verify the signature" }
        return json.dumps(res), 400

    if private_key is None:
        print("Something went wrong... We dont have our private key!")
        return "{}", 500

    keys = ecdh_shared_key(private_key, ephemeral_pub_key, 64)

    session_id = uuid.uuid4().hex
    session = SessionContext(
        session_id,
        organization.id,
        subject.id,
        secret_key=keys[:32],
        mac_key=keys[32:]
    )

    sessions[session_id] = session
    data = bytes(json.dumps(session.get_info()), "utf8")

    cipherbody = encrypt_body(data, keys[:32], keys[32:])

    return Response(
        cipherbody, 
        mimetype="application/octet-stream",
        status=201
    )

@app.route("/organization/subjects", methods=["GET"])
@requires_session
def get_subjects():
    secret_key = g.session.secret_key
    mac_key = g.session.mac_key
    org_id = g.org_id

    organization = Organization.query.get(org_id)
    data= {}
    if organization is None:
        res = { "message": "Organization not found" }
        return Response(
            encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
            content_type="application/octet-stream",
            status=404
        )

    else:
        for subject in organization.subjects:
            data[subject.username] = {
                "suspended": subject.suspended
            }
        return Response(
            encrypt_body(json.dumps(data).encode("utf8"), secret_key, mac_key),
            content_type="application/octet-stream",
            status=200
        )
            
@app.route("/document_metadata", methods=['GET'])   
@requires_session
def get_doc_metadata():
    secret_key = g.session.secret_key
    mac_key = g.session.mac_key

    org_id = g.org_id
    subject_id = g.subject_id
    doc_name = g.json["document_name"]

    organization = db.session.get(Organization, org_id)

    if organization is None:
        res = { "message": "Organization not found" }
        return Response(
            encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
            content_type="application/octet-stream",
            status=404
        )

    document = Document.query.filter_by(org_id=org_id, name=doc_name).first()

    if document is None or document.file_handle is None:
        res = { "message": "Document not found" }
        return Response(
            encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
            content_type="application/octet-stream",
            status=404
        )

    file_handle = document.file_handle

    with open(f"./documents/{file_handle}-metadata.bin", "rb") as f:
        encrypted_metadata = f.read()
        metadata_iv = encrypted_metadata[:16]
        encrypted_metadata = encrypted_metadata[16:]

        data = decrypt_aes256_cbc(master_key, metadata_iv, encrypted_metadata)

    data_size = int.from_bytes(data[0:2], "big")

    json_data = json.loads(data[2:data_size+2])

    json_data["file_handle"] = document.file_handle
    json_data["creator"] = str(document.creator_id)
    json_data["create_date"] = document.create_date.isoformat()
    # ACL ?
    json_data["deleter"] = document.deleter

    new_data = json.dumps(json_data).encode("utf8")

    new_size = len(new_data).to_bytes(2, "big")

    return Response(
        encrypt_body(new_size + new_data + data[2+data_size:], secret_key, mac_key),
        content_type="application/octet-stream",
        status=200
    )

@app.route("/suspend", methods=["PUT"])
@requires_session
def put_suspension():
    secret_key = g.session.secret_key
    mac_key = g.session.mac_key

    org_id = g.org_id
    
    subject_name= g.json["username"]

    organization = Organization.query.get(org_id)
    
    if organization is None:
        res = { "message": "Organization not found" }
        return Response(
            encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
            content_type="application/octet-stream",
            status=404
        )
    
    for subject in organization.subjects:
        if subject.username == subject_name:
            subject.suspended = True
            db.session.commit()
            res= { "message": "Subject suspended" }
            return Response(
                encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
                content_type="application/octet-stream",
                status=201
            )
        
    res = { "message": "Subject not found" }
    return Response(
        encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
        content_type="application/octet-stream",
        status=404
    )

@app.route("/activate", methods=["PUT"])
@requires_session
def put_activation():
    secret_key = g.session.secret_key
    mac_key = g.session.mac_key
    
    org_id = g.org_id

    subject_name = g.json["username"]

    organization = Organization.query.get(org_id)

    if organization is None:
        res = { "message": "Organization not found" }
        return Response(
            encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
            content_type="application/octet-stream",
            status=404
        )
    for subject in organization.subjects:   
        if subject.username == subject_name:
            subject.suspended = False
            db.session.commit()
            res= { "message": "Subject activated" }
            return Response(
                encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
                content_type="application/octet-stream",
                status=201
            )
    res = { "message": "Subject not found" }
    return Response(
        encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
        content_type="application/octet-stream",
        status=404
    )

@app.route('/files/<file_handle>', methods=["GET"])
def get_file(file_handle):
    if os.path.isfile(f"./documents/{file_handle}.bin") : 
        with open(f"./documents/{file_handle}.bin", 'rb') as f:
            return Response(
                f.read(),
                mimetype="application/octet-stream"
            )

    return "", 404


@app.route("/subject/create", methods=["POST"])
@requires_session
def create_subject():
    secret_key = g.session.secret_key
    mac_key = g.session.mac_key
    
    username = g.json["username"]
    name = g.json["name"]
    email = g.json["email"]
    pub_key = g.json["pub_key"]
    org_id = g.org_id

    #TODO So podemos adicionar um sujeito se tivermos a permissão SUBJECT_NEW
     
    organization = Organization.query.get(org_id)
    
    if organization is None:
        res = {"message" : "Organization not found" }
        return Response(
            encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
            content_type="application/octet-stream",
            status=404
        )
    
    subject = next((sub for sub in organization.subjects if sub.username == username), None)

    if subject is not None :
        res = {"message" : "Subject already exists in this organization" }
        return Response(
            encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
            content_type="application/octet-stream",
            status=400
        )
    
    subject = Subject(username = username, name = name, email = email, pub_key= pub_key, org_id = org_id)
    organization.subjects.append(subject)
    db.session.commit()

    return "", 201

@app.route("/documents/list", methods=["GET"])
@requires_session
def list_docs():
    secret_key = g.session.secret_key
    mac_key = g.session.mac_key

    org_id = g.org_id

    username = g.json["username"]
    comparator = g.json["date_opt"]
    date = g.json["date"]

    organization = Organization.query.get(org_id)

    if organization is None:
        res = { "message": "Organization does not exist" }
        return Response(
            encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
            content_type="application/octet-stream",
            status=404
        )

    documents = organization.documents

    if username is not None:
        user = next((sub for sub in organization.subjects if sub.username == username), None)

        if user is None:
            res = { "message": "User does not exist" }
            return Response(
                encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
                content_type="application/octet-stream",
                status=400
            )

        documents = list(filter(lambda x: x.creator_id == user.id, documents))

    if date is not None and comparator is not None:
        date = datetime.strptime(date, "%d-%m-%Y").date()

        if comparator == "nt":
            documents = list(filter(lambda x: x.create_date.date() > date, documents))
        elif comparator == "ot":
            documents = list(filter(lambda x: x.create_date.date() < date, documents))
        elif comparator == "et":
            documents = list(filter(lambda x: x.create_date.date() == date, documents))

    res = jsonify(documents)

    return Response(
        encrypt_body(json.dumps(res.json).encode("utf8"), secret_key, mac_key),
        content_type="application/octet-stream",
        status=200
    )

@app.route("/document/delete", methods=["PUT"])
@requires_session
def delete_doc():
    #TODO This commands requires a DOC_DELETE permission.
    secret_key = g.session.secret_key
    mac_key = g.session.mac_key
    
    org_id = g.org_id
    subject_id = g.subject_id

    document_name = g.json["document_name"]
    
    document = Document.query.filter_by(org_id=org_id, name=document_name).first()
    if document is None or document.file_handle is None:
        res = { "message": "A document with that name doesn't exist" }
        return Response(
            encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
            content_type="application/octet-stream",
            status=400
        )

    file_handle = document.file_handle
    with open(f"./documents/{file_handle}-metadata.bin", "rb") as f:
        encrypted_metadata = f.read()
        metadata_iv = encrypted_metadata[:16]
        encrypted_metadata = encrypted_metadata[16:]

        data = decrypt_aes256_cbc(master_key, metadata_iv, encrypted_metadata)

    data_size = int.from_bytes(data[0:2], "big")

    json_data = json.loads(data[2:data_size+2])

    json_data["file_handle"] = file_handle
    new_data = json.dumps(json_data).encode("utf8")
    new_size = len(new_data).to_bytes(2, "big")

    document.file_handle = None  
    document.deleter = subject_id  

    db.session.commit()

    return Response(
        encrypt_body(new_size + new_data + data[2+data_size:], secret_key, mac_key),
        content_type="application/octet-stream",
        status=200
    )

@app.route("/organization/roles", methods=["GET"])
@requires_session
def get_roles():
    secret_key = g.session.secret_key
    mac_key = g.session.mac_key
    assumed_roles = g.session.roles

    org_id = g.org_id

    organization = Organization.query.get(org_id)

    if organization is None:
        res = { "message": "Organization does not exist" }
        return Response(
            encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
            content_type="application/octet-stream",
            status=404
        )

    roles = list(filter(lambda r: r.id in assumed_roles, organization.roles))

    return Response(
        encrypt_body(json.dumps(jsonify(roles).json).encode("utf8"), secret_key, mac_key),
        content_type="application/octet-stream",
        status=200
    )

@app.route("/organization/roles", methods=["POST"])
@requires_session
def create_role():
    secret_key = g.session.secret_key
    mac_key = g.session.mac_key
    assumed_roles = g.session.roles

    org_id = g.org_id

    organization = Organization.query.get(org_id)

    if organization is None:
        res = { "message": "Organization does not exist" }
        return Response(
            encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
            content_type="application/octet-stream",
            status=404
        )

    has_perm = any([role for role in organization.roles if role.id in assumed_roles and has_permission(role.permissions, Org_ACL.ROLE_NEW)])

    if not has_perm:
        res = { "message": "Your active roles don't allow role creation!" }
        return Response(
            encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
            content_type="application/octet-stream",
            status=403
        )

    role = Role(name=g.json["role"], permissions=0, org_id=organization.id)
    db.session.add(role)
    db.session.commit()

    return Response(
        encrypt_body(json.dumps(jsonify(role).json).encode("utf8"), secret_key, mac_key),
        content_type="application/octet-stream",
        status=201
    )

@app.route("/organization/roles/permissions", methods=["PATCH"])
@requires_session
def modify_role():
    secret_key = g.session.secret_key
    mac_key = g.session.mac_key
    assumed_roles = g.session.roles

    org_id = g.org_id

    organization = Organization.query.get(org_id)

    if organization is None:
        res = { "message": "Organization does not exist" }
        return Response(
            encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
            content_type="application/octet-stream",
            status=404
        )

    has_perm = any([role for role in organization.roles if role.id in assumed_roles and has_permission(role.permissions, Org_ACL.ROLE_MOD)])

    if not has_perm:
        res = { "message": "Your active roles don't allow role modification!" }
        return Response(
            encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
            content_type="application/octet-stream",
            status=403
        )

    role = g.json["role"]

    role = next((r for r in organization.roles if r.name == role), None)

    if not role:
        res = { "message": "Role not found" }
        return Response(
            encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
            content_type="application/octet-stream",
            status=404
        )

    op = g.json["op"]

    if op not in ["add", "remove"]:
        res = { "message": "Unknown operation" }
        return Response(
            encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
            content_type="application/octet-stream",
            status=400
        )

    user_perm = g.json["user_perm"]

    if hasattr(Org_ACL, user_perm):
        if op == "add":
            role.permissions = add_permission(role.permissions, Org_ACL[user_perm])
        else:
            role.permissions = remove_permission(role.permissions, Org_ACL[user_perm])
    else:
        subject = next((sub for sub in organization.subjects if sub.username == user_perm), None)

        if not subject:
            res = { "message": "User not found" }
            return Response(
                encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
                content_type="application/octet-stream",
                status=404
            )

        if op == "add":
            if role not in subject.roles:
                subject.roles.append(role)
        else:
            if role in subject.roles:
                if role.name == "Manager" and len([sub for sub in role.subjects if not sub.suspended]) == 1:
                    res = { "message": "The manager role must have at least 1 active subject" }
                    return Response(
                        encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
                        content_type="application/octet-stream",
                        status=400
                    )

                subject.roles.remove(role)

    db.session.commit()

    res = { "message": "Operation completed" }
    return Response(
        encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
        content_type="application/octet-stream",
        status=200
    )

@app.route("/organization/subjects/role", methods=["GET"])
@requires_session
def get_role_subjects():
    secret_key = g.session.secret_key
    mac_key = g.session.mac_key

    org_id = g.org_id

    organization = Organization.query.get(org_id)

    if organization is None:
        res = { "message": "Organization does not exist" }
        return Response(
            encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
            content_type="application/octet-stream",
            status=404
        )

    role_name = g.json["role"]
    role = next((rol for rol in organization.roles if rol.name == role_name), None) 

    if role is None:
        res = { "message": "Role does not exist" }
        return Response(
            encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
            content_type="application/octet-stream",
            status=404
        )

    subjects=[sub.username for sub in role.subjects]

    return Response(
        encrypt_body(json.dumps(jsonify(subjects).json).encode("utf8"), secret_key, mac_key),
        content_type="application/octet-stream",
        status=200
    )

@app.route("/organization/subject/roles", methods=["GET"])
@requires_session
def get_roles_subject():
    secret_key = g.session.secret_key
    mac_key = g.session.mac_key
    assumed_roles = g.session.roles

    org_id = g.org_id

    organization = Organization.query.get(org_id)

    if organization is None:
        res = { "message": "Organization does not exist" }
        return Response(
            encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
            content_type="application/octet-stream",
            status=404
        )

    username=g.json["username"]
    roles=[]
    subject = next((sub for sub in organization.subjects if sub.username == username), None)

    if subject is None:
        res = { "message": "Subject does not exist" }
        return json.dumps(res), 400

    for rol in subject.roles:
        roles.append(rol.name)

    return Response(
        encrypt_body(json.dumps(jsonify(roles).json).encode("utf8"), secret_key, mac_key),
        content_type="application/octet-stream",
        status=200
    )

@app.route("/session/roles/assume", methods=["PATCH"])
@requires_session
def assume_role():
    secret_key = g.session.secret_key
    mac_key = g.session.mac_key
    assumed_roles = g.session.roles

    org_id = g.org_id
    subject_id = g.subject_id

    organization = Organization.query.get(org_id)
    session = g.session

    if organization is None:
        res = { "message": "Organization does not exist" }
        return Response(
            encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
            content_type="application/octet-stream",
            status=404
        )

    role = g.json["role"]

    subject = Subject.query.get(subject_id)

    role = next((r for r in subject.roles if r.name ==role), None)

    if role == None:
        res = {"message":"Role doesn't exist or you don't have permission to assume it"}
        return Response(
            encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
            content_type="application/octet-stream",
            status=400
        )
    
    if role.suspended:
        res = {"message":"Role is suspended"}
        return Response(
            encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
            content_type="application/octet-stream",
            status=400
        )

    session.assume_role(role.id)
    res = {}
    return Response(
        encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
        content_type="application/octet-stream",
        status=200
    )

@app.route("/session/roles/drop", methods=["PATCH"])
@requires_session
def drop_role():
    secret_key = g.session.secret_key
    mac_key = g.session.mac_key
    assumed_roles = g.session.roles

    org_id = g.org_id
    subject_id = g.subject_id

    organization = Organization.query.get(org_id)
    session = g.session

    if organization is None:
        res = { "message": "Organization does not exist" }
        return Response(
            encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
            content_type="application/octet-stream",
            status=404
        )

    role = g.json["role"]

    role = next((r for r in organization.roles if r.name ==role), None)

    if role is None:
        res = {"message":"Role doesn't exist"}

        return Response(
            encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
            content_type="application/octet-stream",
            status=400
        )

    if role.id not in assumed_roles:
        res = {"message":"This role was not assumed"}
        return Response(
            encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
            content_type="application/octet-stream",
            status=400
        )

    session.drop_role(role.id)
    res = {}
    return Response(
        encrypt_body(json.dumps(res).encode("utf8"), secret_key, mac_key),
        content_type="application/octet-stream",
        status=200
    )



if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("master_password")
    args = parser.parse_args()

    if os.path.isfile("./salt.bin"):
        with open("./salt.bin", "rb") as f:
            salt = f.read()
    else:
        salt = os.urandom(16)
        
        with open("./salt.bin", "wb") as f:
            f.write(salt)
    
    master_key = pbkdf2(args.master_password, 32, salt)
    private_key = ec.derive_private_key(int.from_bytes(master_key, "big"), ec.SECP256R1())
    public_key = serialize_pub_key(private_key.public_key())

    with open("repo_key.pub", "wb") as f:
        f.write(public_key)

    app.run(host="0.0.0.0", port=8000, debug=True)
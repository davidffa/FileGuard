import base64
import json
import os
from datetime import datetime
from functools import wraps
from uuid import uuid4

from flask import Flask, g, request
from src.crypto import decrypt_aes256_cbc, sha256_digest
from src.structures import Document, Organization, Session, Subject

app = Flask(__name__)

organizations = {}

def requires_session(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "session" not in request.headers:
            res = { "message": "Please provide a session header" }
            return json.dumps(res), 401

        session = json.loads(base64.b64decode(request.headers["session"]))

        g.organization = session["organization"]
        g.subject = session["subject"]

        return f(*args, **kwargs)

    return decorated

@app.route("/organization/list")
def org_list():
    data= []
    for org in organizations:
        data.append(organizations[org].get_org_info())
    return json.dumps(data), 200

@app.route("/organization/create", methods=["POST"])
def create_org():
    if request.json is None:
        res = { "message": "Empty request body" }
        return json.dumps(res), 400


    if request.json["organization"] in organizations:
        res = { "message": "Organization already exists" }
        return json.dumps(res), 400

    org_name = request.json["organization"]
    username = request.json["username"]
    name = request.json["name"]
    email = request.json["email"]
    pub_key = request.json["pub_key"]

    subject = Subject(username, name, email, pub_key)
    organizations[org_name] = Organization(org_name, subject)


    return "{}", 201

@app.route("/document", methods=["POST"])
@requires_session
def add_doc():
    if "file" not in request.files:
        res = { "message": "Please provide a file" }
        return json.dumps(res), 400

    encrypted_file = request.files["file"].read()
    secret_key = request.files["secret_key"].read()
    iv = request.files["iv"].read()

    file_name = request.form["document_name"]
    file_handle = request.form["file_handle"]
    crypto_alg = request.form["crypto_alg"]
    digest_alg = request.form["digest_alg"]

    if crypto_alg != "AES256_CBC":
        res = { "message": "Encryption algorithm not supported" }
        return json.dumps(res), 400

    if digest_alg != "SHA256":
        res = { "message": "Digest algorithm not supported" }
        return json.dumps(res), 400

    decrypted_file = decrypt_aes256_cbc(secret_key, iv, encrypted_file)

    if file_handle != sha256_digest(decrypted_file):
        res = { "message": "File integrity verification failed" }
        return json.dumps(res), 400

    if not os.path.exists("./documents"):
        os.makedirs("./documents")

    with open(f"./documents/{file_handle}.bin", "wb") as f:
        f.write(encrypted_file)

    # Other metadata would be written in the main json
    with open(f"./documents/{file_handle}-metadata.bin", "wb") as f:
        # TODO: Encrypt this metadata
        data = bytes(json.dumps({ "crypto_alg": "AES256_CBC", "digest_alg": "SHA256" }), "utf8")
        data_len = len(data)
        f.write(data_len.to_bytes(2, "big"))
        f.write(data)
        f.write(secret_key)
        f.write(iv)

    org_name = g.organization
    subject = g.subject

    metadata = {
        "document_handle": uuid4().hex,
        "name": file_name,
        "create_date": str(datetime.now()),
        "creator": subject,
        "file_handle": file_handle,
        "acl": [],
        "deleter": None,
    }

    doc = Document(file_name, metadata)

    organizations[org_name].docs.append(doc)

    return json.dumps(metadata), 201

@app.route("/organization/create/session", methods=["POST"])
def create_session():
    
    if request.json is None:
        res = { "message": "Empty request body" }
        return json.dumps(res), 400

    org_name = request.json["organization"]
    username = request.json["username"]

    if org_name not in organizations:
        res = { "message": "Organization does not exist" }
        return json.dumps(res), 400
    
    if username not in organizations[org_name].get_subjects():
        res = { "message": "Subject does not exist" }
        return json.dumps(res), 400
    
    org= organizations[org_name]
    subject= org.find_subject(username)
    new_session= Session(subject, 3600, org)
    data= new_session.get_info()
    return json.dumps(data), 201

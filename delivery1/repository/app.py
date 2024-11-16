import base64
import json
import os
from argparse import ArgumentParser
from functools import wraps

from flask import Response, g, jsonify, request
from src import create_app, db
from src.crypto import (decrypt_aes256_cbc, encrypt_aes256_cbc, pbkdf2,
                        sha256_digest)
from src.models import Document, Organization, Subject
from src.util import Session

app = create_app()
master_key = bytes()

def requires_session(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "session" not in request.headers:
            res = { "message": "Please provide a session header" }
            return json.dumps(res), 401

        session = json.loads(base64.b64decode(request.headers["session"]))

        g.org_id = session["org_id"]
        g.subject_id = session["subject_id"]

        return f(*args, **kwargs)

    return decorated

@app.route("/organization/list")
def org_list():
    return jsonify(Organization.query.all())

@app.route("/organization/create", methods=["POST"])
def create_org():
    if request.json is None:
        res = { "message": "Empty request body" }
        return json.dumps(res), 400

    existing_org = Organization.query.filter_by(name=request.json["organization"]).first()

    if existing_org is not None:
        res = { "message": "Organization already exists" }
        return json.dumps(res), 400

    org_name = request.json["organization"]
    username = request.json["username"]
    name = request.json["name"]
    email = request.json["email"]
    pub_key = request.json["pub_key"]

    org = Organization(name=org_name)
    db.session.add(org)
    db.session.flush()

    subject = Subject(username=username, name=name, email=email, pub_key=pub_key, org_id=org.id)
    db.session.add(subject)
    db.session.commit()

    return "{}", 201

@app.route("/document", methods=["POST"])
@requires_session
def add_doc():
    if "file" not in request.files:
        res = { "message": "Please provide a file" }
        return json.dumps(res), 400

    org_id = g.org_id
    subject_id = g.subject_id

    encrypted_file = request.files["file"].read()
    secret_key = request.files["secret_key"].read()
    doc_iv = request.files["iv"].read()

    file_name = request.form["document_name"]
    file_handle = request.form["file_handle"]
    crypto_alg = request.form["crypto_alg"]
    digest_alg = request.form["digest_alg"]

    existent_doc = Document.query.filter_by(org_id=org_id, name=file_name).first()

    if existent_doc is not None:
        res = { "message": "A document with that name already exists" }
        return json.dumps(res), 400

    if crypto_alg != "AES256_CBC":
        res = { "message": "Encryption algorithm not supported" }
        return json.dumps(res), 400

    if digest_alg != "SHA256":
        res = { "message": "Digest algorithm not supported" }
        return json.dumps(res), 400

    decrypted_file = decrypt_aes256_cbc(secret_key, doc_iv, encrypted_file)

    if file_handle != sha256_digest(decrypted_file):
        res = { "message": "File integrity verification failed" }
        return json.dumps(res), 400

    if not os.path.exists("./documents"):
        os.makedirs("./documents")

    with open(f"./documents/{file_handle}.bin", "wb") as f:
        f.write(encrypted_file)

    with open(f"./documents/{file_handle}-metadata.bin", "wb") as f:
        data = bytes(json.dumps({ "crypto_alg": "AES256_CBC", "digest_alg": "SHA256" }), "utf8")
        data_len = len(data)

        metadata = data_len.to_bytes(2, "big") + data + secret_key + doc_iv
        metadata_iv = os.urandom(16)

        f.write(metadata_iv + encrypt_aes256_cbc(metadata, master_key, metadata_iv))

    doc = Document(name=file_name, creator_id=subject_id, file_handle=file_handle, org_id=org_id)

    db.session.add(doc)
    db.session.commit()

    return jsonify(doc), 201

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
    
    session = Session(str(organization.id), str(subject.id))
    data = session.get_info()
    return json.dumps(data), 201

@app.route("/document_metadata", methods=['GET'])   
@requires_session
def get_doc_metadata():
    org_id = g.org_id
    subject_id = g.subject_id
    doc_name = request.args.get("document_name")

    organization = db.session.get(Organization, org_id)

    if organization is None:
        res = { "message": "Organization not found" }
        return json.dumps(res), 404

    document = Document.query.filter_by(org_id=org_id, name=doc_name).first()

    if document is None:
        res = { "message": "Document not found" }
        return json.dumps(res), 404

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
        new_size + new_data + data[2+data_size:],
        mimetype="application/octet-stream",
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

    app.run(host="0.0.0.0", port=8000, debug=True)

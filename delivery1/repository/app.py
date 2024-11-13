import base64
import json
import os
from functools import wraps

from flask import Response, g, jsonify, request

from . import create_app, db
from .crypto import decrypt_aes256_cbc, sha256_digest
from .models import Document, Organization, Subject
from .util import Session

app = create_app()

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

    org_id = g.org_id
    subject_id = g.subject_id

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

    organization = Organization.query.get(org_id)

    if organization is None:
        res = { "message": "Organization not found" }
        return json.dumps(res), 404

    document = next((doc for doc in organization.documents if doc.name == doc_name), None)

    if document is None:
        res = { "message": "Document not found" }
        return json.dumps(res), 404

    file_handle = document.file_handle

    with open(f"./documents/{file_handle}-metadata.bin", "rb") as f:
        data = f.read()

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
    app.run(port=8000, debug=True)

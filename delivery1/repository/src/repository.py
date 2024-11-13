import json

from flask import Flask, request
from src.structures import Organization, Subject

app = Flask(__name__)

organizations = {}
subjects = {}

@app.route("/organization/list")
def org_list():
    return json.dumps(organizations)

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

@app.route("/subject/create", methods=["POST"])
def create_subject():
    #<session file> <username> <name> <email> <credentials file>
    if request.json is None:
        res = { "message": "Empty request body" }
        return json.dumps(res), 400


    if request.json["subject"] in subjects:
        res = { "message": "Subject already exists" }
        return json.dumps(res), 400


    username = request.json["username"]
    name = request.json["name"]
    email = request.json["email"]

    # Public key vem das credentials file
    pub_key = request.json["pub key"]

    # Nome da organização para adicionar sujeito vem da session file
    org_name = request.json["org_name"]

    # So podemos adicionar um sujeito se tivermos a permissão SUBJECT_NEW
    # By default the subject is created in the active status. 


    subject = Subject(username, name, email, pub_key)
    organizations[org_name] = Organization(org_name, subject)


    return "{}", 201

import json

from flask import Flask, request
from src.structures import Organization, Subject

app = Flask(__name__)

organizations = {}

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

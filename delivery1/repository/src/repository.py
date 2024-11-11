import json

from flask import Flask, request
from src.structures import Organization, Subject, Session


app = Flask(__name__)

organizations = {}

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

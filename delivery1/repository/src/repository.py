import json

from flask import Flask, Response, request
from src.structures import Organization, Subject

app = Flask(__name__)

organizations = {}

@app.route("/organization/list")
def org_list():
    return json.dumps(organizations)

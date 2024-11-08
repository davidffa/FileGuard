from datetime import datetime
import uuid
from src.consts import Permission_Organization
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class Document:
    def __init__(self, name, file, metadata):
        self.name = name
        self.metadata = metadata
        self.file = file

class Metadata:
    def __init__(self, doc_name, document_handle, creator, file_handle):
        self.doc_name = doc_name
        self.document_handle = document_handle
        self.creator = creator
        self.acl = []
        self.deleter= None
        self.create_date= datetime.now()
        #Os abaixo devem ser privados e de acesso restrito, são dados sensíveis
        self.alg= None
        self.key= None
        self.file_handle = file_handle

    def define_alg(self, alg):
        self.alg= alg

    def define_key(self, key):
        self.key= key
    
    def delete(self, deleter):
        self.deleter= deleter
        self.file_handle= None

class Organization:
    def __init__(self, name, subject):
        self.session_lifetime= 3600
        self.name = name
        self.docs = []
        self.sessions= []
        #Create manager role for first subject
        manager = Role('Manager')
        manager.add_subject(subject)

        for permission in Permission_Organization:
            manager.add_permission(permission)

        self.acl = [manager]
    
    def create_session(self, username):
        session= Session(username, self.session_lifetime)
        self.sessions.append(session)
        return session

    def get_org_info(self):
        manager= None
        for role in self.acl:
            if role.name == 'Manager':
                manager= role.subjects[0].username
        info= f"{self.name}, managed by: {manager}"
        return info
    
    def find_subject(self, username):
        for role in self.acl:
            for subject in role.subjects:
                if subject.username == username:
                    return subject
        return None
    
    def get_subjects(self):
        subjects= []
        for role in self.acl:
            for subject in role.subjects:
                subjects.append(subject.username)
        return subjects

    def __str__(self):
        return self.name
    



class Role:
    def __init__(self, name):
        self.name = name
        self.subjects = []
        self.permissions= []

    def add_subject(self, subject):
        self.subjects.append(subject)
    
    def add_permission(self, permission):
        self.permissions.append(permission)

    def check_permission(self, permission):
        return permission in self.permissions
    
    def __str__(self):
        return f"Role: {self.name}"
    

class Subject:
    def __init__(self, username, fullname, email, public_key):
        self.username = username
        self.fullname = fullname
        self.email = email
        self.pub_keys= [public_key]

    def add_pub_key(self, public_key):
        self.pub_keys.append(public_key)
    
    def __str__(self):
        return f"Subject: {self.username} ({self.fullname}) <{self.email}>"
        


class Session:
    def __init__(self, subject, lifetime):
        self.subject = subject
        self.keys= [self.create_key()]
        self.id= uuid.uuid4()
        self.lifetime= lifetime

    def create_key(self):
        key= ec.generate_private_key(ec.SECP256R1())
        return key.public_key()

    def add_key(self, key):
        self.keys.append(key)

    def get_info(self):
        return f"Session ID: {self.id}\n{self.subject}\nLifetime: {self.lifetime}"
            
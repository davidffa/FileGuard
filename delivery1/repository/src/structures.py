from datetime import datetime

from src.consts import Permission_Organization


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
        self.name = name
        self.docs = []
        #Create manager role for first subject
        manager = Role('Manager')
        manager.add_subject(subject)

        for permission in Permission_Organization:
            manager.add_permission(permission)

        self.acl = [manager]

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
        

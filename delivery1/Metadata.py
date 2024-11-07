import Permissions_Consts
import datetime

class Metadata:
    def __init__(self, doc_name, document_handle, creator, file_handle):
        self.doc_name = doc_name
        self.document_handle = document_handle
        self.creator = creator
        self.ACL = []
        self.deleter= None
        self.create_date= datetime.datetime.now()
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


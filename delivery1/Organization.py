
import Role
import Permissions_Consts

class Organization:
    def __init__(self, name, subject):
        self.name = name
        self.docs = []
        #Create manager role for first subject
        Manager = Role('Manager')
        Manager.add_subject(subject)
        for permission in Permissions_Consts.Permission_Organization:
            Manager.add_permission(permission)
        self.ACL = [Manager]


    def __str__(self):
        return f'{self.name} at {self.address}'

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
    
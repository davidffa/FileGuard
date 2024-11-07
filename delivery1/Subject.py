
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
        
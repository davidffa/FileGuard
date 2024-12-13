import uuid
from datetime import datetime, timedelta
from enum import IntEnum


class SessionContext:
    def __init__(self, session_id: str, org_id: uuid.UUID, subject_id: uuid.UUID, secret_key: bytes, mac_key: bytes):
        self.id = session_id
        self.org_id = org_id
        self.subject_id = subject_id
        self.expires_at = datetime.now() + timedelta(hours=1)
        self.seq = 0

        self.secret_key = secret_key
        self.mac_key = mac_key
        self.roles = set()

    def get_info(self):
        info = {
            "id": self.id,
            "expires_at": str(self.expires_at)
        }
        return info
    
    def assume_role(self, role_id):
        self.roles.add(role_id)

    def drop_role(self, role_id):
        self.roles.remove(role_id)

def has_permission(permissions: int, permission):
    return permissions & permission == permission

def add_permission(permissions: int, permission):
    return permissions | permission

def remove_permission(permissions: int, permission):
    return permissions & ~(permission)

class Doc_ACL(IntEnum):
    DOC_ACL = 1 << 0
    DOC_READ = 1 << 1
    DOC_DELETE = 1 << 2

    ALL = (DOC_ACL | DOC_READ | DOC_DELETE)

class Org_ACL(IntEnum):
    ROLE_ACL = 1 << 0
    SUBJECT_NEW = 1 << 1
    SUBJECT_DOWN = 1 << 2
    SUBJECT_UP = 1 << 3
    DOC_NEW = 1 << 4
    ROLE_NEW = 1 << 5
    ROLE_DOWN = 1 << 6
    ROLE_UP = 1 << 7
    ROLE_MOD = 1 << 8

    ALL = (ROLE_ACL | SUBJECT_NEW | SUBJECT_DOWN | SUBJECT_UP | DOC_NEW | ROLE_NEW | ROLE_DOWN | ROLE_UP | ROLE_MOD)

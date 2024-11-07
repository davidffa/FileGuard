from enum import Enum


class Permission_Organization(Enum):
    ROLE_ACL = 1
    SUBJECT_NEW = 2
    SUBJECT_DOWN = 3
    SUBJECT_UP = 4
    DOC_NEW = 5

class Permission_Document(Enum):
    DOC_ACL = 1
    DOC_READ = 2
    DOC_DELETE = 3


class Permission_Role(Enum):
    ROLE_NEW = 1
    ROLE_DOWN = 2
    ROLE_UP = 3
    ROLE_MOD = 4
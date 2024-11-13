import uuid


class Session:
    def __init__(self, org_id, subject_id):
        self.org_id = org_id
        self.subject_id = subject_id
        self.id = uuid.uuid4()
        self.lifetime = 3600

    def get_info(self):
        info = {
            "org_id": self.org_id,
            "subject_id": self.subject_id,
            "lifetime": self.lifetime
        }
        return info

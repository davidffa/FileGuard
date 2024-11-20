from datetime import datetime, timedelta


class SessionContext:
    def __init__(self, session_id: str, org_id: str, subject_id: str, secret_key: bytes, mac_key: bytes):
        self.id = session_id
        self.org_id = org_id
        self.subject_id = subject_id
        self.expires_at = datetime.now() + timedelta(hours=1)
        self.seq = 0

        self.secret_key = secret_key
        self.mac_key = mac_key

    def get_info(self):
        info = {
            "id": self.id,
            "expires_at": str(self.expires_at)
        }
        return info

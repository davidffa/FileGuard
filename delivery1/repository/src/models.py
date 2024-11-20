import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from sqlalchemy.dialects.postgresql import UUID

from . import db


@dataclass
class Organization(db.Model):
    __tablename__ = "organizations"

    name: str

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String(), nullable=False)

    subjects = db.relationship("Subject", backref="organization", lazy=True)
    documents = db.relationship("Document", backref="organization", lazy=True)


@dataclass
class Subject(db.Model):
    __tablename__ = "subjects"
    
    username: str
    name: str
    email: str
    pub_key: str

    org_id: UUID

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = db.Column(db.String(), nullable=False)
    name = db.Column(db.String(), nullable=False)
    email = db.Column(db.String(), nullable=False)
    pub_key = db.Column(db.String(), nullable=False)
    suspended = db.Column(db.Boolean(), default=False)

    org_id = db.Column(UUID(as_uuid=True), db.ForeignKey("organizations.id"), nullable=False)

    documents = db.relationship("Document", backref="subject", lazy=True)

@dataclass
class Document(db.Model):
    __tablename__ = "documents"

    name: str
    creator_id: UUID
    file_handle: str
    org_id: UUID
    deleter: Optional[str] = None

    document_handle = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String(), nullable=False)
    create_date = db.Column(db.DateTime(timezone=True), nullable=False, default=datetime.now)
    file_handle = db.Column(db.String(), nullable=True)
    # acl = ??
    deleter = db.Column(db.String())

    creator_id = db.Column(UUID(as_uuid=True), db.ForeignKey("subjects.id"), nullable=False)
    org_id = db.Column(UUID(as_uuid=True), db.ForeignKey("organizations.id"), nullable=False)

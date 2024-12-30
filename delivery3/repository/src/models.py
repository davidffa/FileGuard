import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from sqlalchemy.dialects.postgresql import UUID

from . import db


@dataclass
class SubjectRole(db.Model):
    __tablename__ = "subject_roles"
    
    subject_id = db.Column(UUID(as_uuid=True), db.ForeignKey("subjects.id"), primary_key=True)
    role_id = db.Column(UUID(as_uuid=True), db.ForeignKey("roles.id"), primary_key=True)

@dataclass
class Organization(db.Model):
    __tablename__ = "organizations"

    name: str

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String(), nullable=False)

    roles = db.relationship("Role", backref="organization", lazy=True)
    subjects = db.relationship("Subject", backref="organization", lazy=True)
    documents = db.relationship("Document", backref="organization", lazy=True)

@dataclass
class Role(db.Model):
    __tablename__ = "roles"

    name: str
    permissions: int
    org_id: UUID
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String(), nullable=False)
    permissions = db.Column(db.Integer(), nullable=False, default=0)
    suspended = db.Column(db.Boolean(), default=False)

    org_id = db.Column(UUID(as_uuid=True), db.ForeignKey("organizations.id"), nullable=False)
    subjects = db.relationship("Subject", secondary="subject_roles", back_populates="roles", lazy=True)
    role_docs = db.relationship("RoleDoc", backref="role", lazy=True)

@dataclass
class RoleDoc(db.Model):
    __tablename__ = "role_docs"

    role_id = db.Column(UUID(as_uuid=True), db.ForeignKey("roles.id"), primary_key=True)
    doc_id = db.Column(UUID(as_uuid=True), db.ForeignKey("documents.document_handle"), primary_key=True)

    permissions = db.Column(db.Integer(), nullable=False, default=0)

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
    roles = db.relationship("Role", secondary="subject_roles", back_populates="subjects", lazy=True)

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
    deleter = db.Column(db.String())

    roles = db.relationship("RoleDoc", backref="document", lazy=True)

    creator_id = db.Column(UUID(as_uuid=True), db.ForeignKey("subjects.id"), nullable=False)
    org_id = db.Column(UUID(as_uuid=True), db.ForeignKey("organizations.id"), nullable=False)

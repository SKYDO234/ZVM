from extensions import db
from .user import utcnow


class Node(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    url = db.Column(db.String(500), nullable=False)
    token_encrypted = db.Column(db.Text, nullable=False)
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)


class AgentInstance(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    spec = db.Column(db.JSON, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)


class AgentOperation(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    digest = db.Column(db.String(64), nullable=False)
    payload = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(16), default='queued', index=True)
    result = db.Column(db.JSON, nullable=True)
    error = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow)

"""Public SSH trust metadata and short-lived, cross-worker admission leases.

No password, private key, terminal contents, cookie or node token belongs here.
IDs deliberately aren't foreign keys: deleting an account/guest must revoke its
open sockets, not be blocked by ephemeral leases or old public fingerprints.
"""
from extensions import db
from .user import utcnow


class SSHHostKey(db.Model):
    instance_id = db.Column(db.String(36), primary_key=True)
    fingerprint = db.Column(db.String(64), nullable=False)
    algorithm = db.Column(db.String(40), nullable=False)
    trusted_at = db.Column(db.DateTime, default=utcnow, nullable=False)


class SSHLease(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    principal = db.Column(db.String(80), nullable=False, index=True)
    instance_id = db.Column(db.String(36), nullable=False)
    browser_session = db.Column(db.String(64), nullable=True, index=True)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)

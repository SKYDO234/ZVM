"""Guest control credentials and SSHX capabilities are encrypted separately from VPS specs."""
from extensions import db
from .user import utcnow


class GuestAccess(db.Model):
    instance_id = db.Column(db.String(36), db.ForeignKey('vps.id', ondelete='CASCADE'), primary_key=True)
    private_key_encrypted = db.Column(db.Text, nullable=False)
    host_fingerprint = db.Column(db.String(80), nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)


class SSHXSession(db.Model):
    instance_id = db.Column(db.String(36), db.ForeignKey('vps.id', ondelete='CASCADE'), primary_key=True)
    owner_id = db.Column(db.Integer, nullable=False)
    operation_id = db.Column(db.String(36), nullable=False)
    link_encrypted = db.Column(db.Text, nullable=True)
    state = db.Column(db.String(20), default='generated', nullable=False)
    verified_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)


class GuestLease(db.Model):
    """Short, cross-worker admission leases, not interactive terminal sessions."""
    id = db.Column(db.String(36), primary_key=True)
    principal = db.Column(db.String(80), index=True, nullable=False)
    instance_id = db.Column(db.String(36), index=True, nullable=False)
    expires_at = db.Column(db.DateTime, index=True, nullable=False)

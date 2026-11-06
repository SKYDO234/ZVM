import uuid
from extensions import db
from .user import utcnow


def identifier():
    return str(uuid.uuid4())


class VPS(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=identifier)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    owner = db.relationship('User')
    node_id = db.Column(db.Integer, db.ForeignKey('node.id'), nullable=True)
    node = db.relationship('Node')
    name = db.Column(db.String(63), nullable=False)
    engine = db.Column(db.String(12), nullable=False)
    os_id = db.Column(db.String(40), nullable=False)
    ram_mb = db.Column(db.Integer, nullable=False)
    vcpus = db.Column(db.Integer, nullable=False)
    disk_gb = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(32), nullable=True)
    ssh_port = db.Column(db.Integer, nullable=True)
    runtime = db.Column(db.JSON, default=dict, nullable=False)
    suspended = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    __table_args__ = (db.UniqueConstraint('owner_id', 'name'),)

    def spec(self):
        return {k: getattr(self, k) for k in ('id', 'owner_id', 'name', 'engine', 'os_id', 'ram_mb', 'vcpus', 'disk_gb', 'username', 'ssh_port')} | {'runtime': self.runtime}


class Job(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=identifier)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    instance_id = db.Column(db.String(36), nullable=False, index=True)
    node_id = db.Column(db.Integer, db.ForeignKey('node.id'))
    kind = db.Column(db.String(24), nullable=False)
    engine = db.Column(db.String(12), nullable=False)
    status = db.Column(db.String(16), default='queued', nullable=False, index=True)
    payload = db.Column(db.Text, nullable=True)  # authenticated encryption; cleared on completion
    ram_mb = db.Column(db.Integer, default=0)
    vcpus = db.Column(db.Integer, default=0)
    disk_gb = db.Column(db.Integer, default=0)
    message = db.Column(db.Text, default='Waiting for provisioning worker.')
    created_at = db.Column(db.DateTime, default=utcnow)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)


class ProvisionTicket(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=identifier)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    payload = db.Column(db.Text, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    consumed = db.Column(db.Boolean, default=False, nullable=False)


class Audit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    instance_id = db.Column(db.String(36), index=True)
    action = db.Column(db.String(80), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)


class Setting(db.Model):
    key = db.Column(db.String(80), primary_key=True)
    value = db.Column(db.JSON, nullable=False)


class OSImage(db.Model):
    id = db.Column(db.String(40), primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    username = db.Column(db.String(32), nullable=False)
    qemu_url = db.Column(db.Text, nullable=False)
    docker_image = db.Column(db.String(160), nullable=False)
    min_disk_gb = db.Column(db.Integer, default=8)
    sha256 = db.Column(db.String(64), nullable=True)
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    eol_warning = db.Column(db.String(200), nullable=True)
    verification = db.Column(db.String(16), default='unverified')
    verified_at = db.Column(db.DateTime, nullable=True)
    verification_message = db.Column(db.Text, nullable=True)


class AuthAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fingerprint = db.Column(db.String(64), index=True, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, index=True)

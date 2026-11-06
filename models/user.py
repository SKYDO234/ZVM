from datetime import datetime, timezone
import hashlib
from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash
from extensions import db


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), unique=True, nullable=False)
    name = db.Column(db.String(80), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(16), default='user', nullable=False)
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    session_version = db.Column(db.Integer, default=1, nullable=False)
    # Legacy column retained for existing databases: drives a reminder, not a navigation lock.
    must_change_password = db.Column(db.Boolean, default=False, server_default='0', nullable=False)
    plan_id = db.Column(db.Integer, db.ForeignKey('plan.id'))
    plan = db.relationship('Plan')
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    @property
    def is_active(self):
        return self.enabled

    @property
    def is_admin(self):
        return self.role == 'admin'

    def session_tag(self):
        # A deleted SQLite ID must never let an old cookie authenticate as a new account.
        # Password hashes have random salts, even if the new user picks the same password.
        return hashlib.sha256(self.password_hash.encode()).hexdigest()[:32]

    def get_id(self):
        return f'{self.id}:{self.session_version}:{self.session_tag()}'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

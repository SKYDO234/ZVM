"""Fresh authority checks during bounded guest-control operations."""
import secrets
import time

from engines import EngineError
from extensions import db
from models import AgentInstance, Node, User, VPS

class GuestAuthorityError(EngineError):
    pass


TARGET_FIELDS = ('id', 'owner_id', 'engine', 'username', 'ssh_port', 'ram_mb', 'vcpus', 'disk_gb')


def target(spec):
    return {key: spec.get(key) for key in TARGET_FIELDS}


class GuestGuard:
    def __init__(self, spec, user=None, node=None, agent=False):
        self.target = target(spec)
        self.user_id = user.id if user else None
        self.user_tag = user.get_id() if user else None
        self.node_id = node.id if node else None
        self.node_origin = node.url if node else None
        self.node_token = node.token_encrypted if node else None
        self.agent, self.last = agent, 0

    def __call__(self, force=False):
        if not force and time.monotonic() - self.last < 0.4:
            return
        db.session.rollback()
        if self.agent:
            instance = db.session.get(AgentInstance, self.target['id'], populate_existing=True)
            actual = instance.spec if instance else {}
        else:
            user = db.session.get(User, self.user_id, populate_existing=True)
            if not user or not user.enabled or not secrets.compare_digest(user.get_id(), self.user_tag):
                raise GuestAuthorityError('Panel authority changed. Sign in again before controlling SSHX.')
            instance = db.session.get(VPS, self.target['id'], populate_existing=True)
            if not instance or (instance.owner_id != user.id and not user.is_admin) or instance.suspended:
                raise GuestAuthorityError('Guest access was revoked, reassigned or suspended.')
            if instance.node_id != self.node_id:
                raise GuestAuthorityError('The VM node changed; no further guest commands are authorized.')
            if self.node_id:
                node = db.session.get(Node, self.node_id, populate_existing=True)
                if not node or not node.enabled or node.url != self.node_origin or node.token_encrypted != self.node_token:
                    raise GuestAuthorityError('The external node identity or credentials changed.')
            actual = instance.spec()
        if target(actual) != self.target:
            raise GuestAuthorityError('The managed guest identity or allocation changed. Reconcile it before continuing.')
        db.session.rollback()
        self.last = time.monotonic()

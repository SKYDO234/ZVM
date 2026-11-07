"""Continuously revalidate WebSSH authority; logout also revokes open sockets."""
import hashlib
import secrets
import time
from urllib.parse import urlsplit

from flask import abort, current_app, request, session
from flask_login import current_user

from extensions import db
from models import AgentInstance, Node, SSHLease, User, VPS
from models.user import utcnow
from services.webssh import SSHError, enabled, renew


def browser_session(create=False):
    # Reuse the existing random, session-bound CSRF seed. Adding a new cookie
    # field on the WebSSH GET races delayed dashboard/API cookie refreshes,
    # which can overwrite that field and cause intermittent upgrade 403s.
    # Retain bindings from previously opened terminals during rolling updates.
    value = session.get('webssh_session') or session.get('csrf_token')
    if not value and create:
        from flask_wtf.csrf import generate_csrf
        generate_csrf()
        value = session.get('csrf_token')
    return hashlib.sha256(value.encode()).hexdigest() if isinstance(value, str) else None


def revoke_browser_sessions():
    tag = browser_session()
    if tag:
        db.session.execute(db.delete(SSHLease).where(SSHLease.browser_session == tag))


def check_origin():
    """Browser sockets require an exact Origin, not a forwarded-host allowlist."""
    try:
        origin = urlsplit(request.headers.get('Origin', ''))
        host = urlsplit('//' + request.host)
        if (origin.scheme not in ('http', 'https') or origin.netloc.lower() != host.netloc.lower()
                or origin.username or origin.password or origin.path or origin.query or origin.fragment):
            abort(403)
        if origin.scheme != 'https' and origin.hostname not in ('127.0.0.1', 'localhost', '::1'):
            abort(403)
    except ValueError:
        abort(403)


def require_browser():
    if not current_user.is_authenticated:
        abort(401)
    check_origin()
    if browser_session() is None:
        abort(403)  # Visit the authenticated page; WS upgrades cannot set cookies.


class AccessGuard:
    """Refresh DB state, not request-local Flask-Login caches.

    Input checks are cached for at most 0.5s; idle streams check every 2s.
    HTTP logout deletes this browser's leases; password/session changes, disabled
    accounts, role/owner changes, VM suspension/deletion and node changes revoke
    existing terminals too. Heartbeats expire abandoned worker leases in 90s.
    """
    def __init__(self, lease, spec, user_tag=None, user_id=None, node=None, agent=False):
        self.lease = lease
        self.spec = {key: spec.get(key) for key in ('id', 'engine', 'username', 'ssh_port')}
        self.user_tag = user_tag
        self.user_id = user_id
        self.node_id = node.id if node else None
        self.node_origin = node.url if node else None
        self.node_token = node.token_encrypted if node else None
        self.agent = agent
        self.last_check = 0
        self.last_renew = time.monotonic()
        self.expires = time.monotonic() + current_app.permanent_session_lifetime.total_seconds()

    def __call__(self):
        enabled()
        now = time.monotonic()
        if now - self.last_check < 0.5:
            return
        # End read snapshots and expire identity-map values held by long requests.
        db.session.rollback()
        lease = db.session.get(SSHLease, self.lease, populate_existing=True)
        if not lease or lease.expires_at < utcnow() or now >= self.expires:
            raise SSHError('session_revoked', 'This WebSSH session was signed out, revoked or expired.')
        if self.agent:
            instance = db.session.get(AgentInstance, self.spec['id'], populate_existing=True)
            actual = instance.spec if instance else {}
        else:
            user = db.session.get(User, self.user_id, populate_existing=True)
            if not user or not user.enabled or not secrets.compare_digest(user.get_id(), self.user_tag):
                raise SSHError('session_revoked', 'Your panel session was revoked. Sign in again to open a new terminal.')
            instance = db.session.get(VPS, self.spec['id'], populate_existing=True)
            if not instance or (instance.owner_id != user.id and not user.is_admin):
                raise SSHError('access_revoked', 'You no longer have access to this VM.')
            if instance.suspended:
                raise SSHError('suspended', 'This VM is suspended. Its WebSSH connections have been closed.')
            if instance.node_id != self.node_id:
                raise SSHError('target_changed', 'The VM’s node changed. Reopen WebSSH from its details page.')
            if self.node_id:
                node = db.session.get(Node, self.node_id, populate_existing=True)
                if not node or not node.enabled or node.url != self.node_origin or node.token_encrypted != self.node_token:
                    raise SSHError('node_changed', 'The external node was disabled or its connection credentials changed. Reconnect after the operator verifies it.')
            actual = instance.spec()
        if any(actual.get(key) != value for key, value in self.spec.items()):
            raise SSHError('target_changed', 'The managed guest was removed or its SSH configuration changed. Reopen its WebSSH page.')
        if now - self.last_renew >= 15:
            renew(self.lease)
            self.last_renew = now
        else:
            db.session.rollback()
        self.last_check = now

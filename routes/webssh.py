"""Authenticated panel pages and a same-origin, CSRF-bound guest WebSocket."""
from urllib.parse import urlsplit
from flask import Blueprint, g, jsonify, render_template, url_for
from flask_login import current_user, login_required
from flask_wtf.csrf import validate_csrf
from sqlalchemy.exc import SQLAlchemyError
from simple_websocket import ConnectionClosed
from wtforms.validators import ValidationError

from engines import EngineError
from engines.node_engine import NodeEngine
from engines.qemu_engine import QemuEngine
from extensions import db, sock
from models import Audit, User, VPS
from routes.vps import owned
from services import node_webssh, webssh
from services.webssh_access import AccessGuard, browser_session, require_browser
from services.webssh_socket import BoundedSocket

bp = Blueprint('webssh', __name__)


@bp.get('/webssh')
@bp.get('/webssh/<ident>')
@login_required
def page(ident=None):
    instances = list(db.session.scalars(db.select(VPS).where(VPS.owner_id == current_user.id).order_by(VPS.created_at.desc())))
    vps = owned(ident) if ident else next((v for v in instances if v.engine == 'qemu'), instances[0] if instances else None)
    browser_session(create=True)
    reason = None
    if vps:
        try:
            webssh.validate_spec(vps.spec())
            if vps.suspended:
                raise webssh.SSHError('suspended', 'This VM is suspended. Ask your operator to restore access.')
            if vps.node:
                node_webssh.capability(NodeEngine(vps.node))
                if NodeEngine(vps.node).metrics(vps.spec()).get('status') != 'running':
                    raise EngineError('The external QEMU VM is not running. Start it and inspect its boot progress in Console.')
            else:
                QemuEngine().ssh_endpoint(vps.spec())
        except EngineError as exc:
            reason = str(exc)
    # Flask builds websocket routes as absolute ws:// URLs even when an HTTP
    # proxy terminates HTTPS. Give the browser a relative same-origin path.
    socket_path = urlsplit(url_for('webssh.socket', ident=vps.id)).path if vps else ''
    return render_template('webssh.html', instances=instances, vps=vps, unavailable=reason, socket_path=socket_path)


@bp.before_request
def protect_upgrade():
    from flask import request
    if request.endpoint != 'webssh.socket':
        return
    require_browser()
    vps = owned(request.view_args['ident'])
    try:
        webssh.validate_spec(vps.spec())
        if vps.suspended:
            raise webssh.SSHError('suspended', 'This VM is suspended.')
        # Reserve before upgrading: stalled credential messages cannot consume
        # every Gunicorn HTTP thread. The teardown releases every reservation.
        g.webssh_user_id = current_user.id
        g.webssh_user_tag = current_user.get_id()
        g.webssh_lease = webssh.admit(f'user:{current_user.id}', vps.id, browser_session())
    except EngineError as exc:
        return jsonify(error=str(exc)), 409


@bp.teardown_request
def cleanup_lease(_exc):
    lease = g.pop('webssh_lease', None)
    if lease:
        try:
            webssh.release(lease)
        except SQLAlchemyError:
            db.session.rollback()  # A crashed worker's lease expires independently.


def record(action, user_id, ident):
    messages = {'connected': 'Opened a verified guest SSH terminal.',
                'disconnected': 'WebSSH connection ended. No terminal contents were recorded.',
                'host_key_trusted': 'Explicitly trusted the guest SSH host fingerprint.',
                'host_key_prompt': 'Requested confirmation of the external guest SSH host fingerprint.'}
    db.session.rollback()
    # Account deletion must not block socket cleanup or insert a dangling FK.
    owner = db.session.get(User, user_id, populate_existing=True)
    db.session.add(Audit(user_id=owner.id if owner else None, instance_id=ident,
                         action='webssh.' + action, message=messages[action]))
    db.session.commit()


@sock.route('/api/webssh/<ident>', bp=bp)
def socket(ws, ident):
    ws = BoundedSocket(ws)
    first = {}
    user_id = g.webssh_user_id
    try:
        raw = ws.receive(timeout=8)
        if raw is None:
            raise webssh.SSHError('connect_timeout', 'Connection setup timed out. Reopen Connect and try again.')
        data = webssh.message(raw)
        raw = None
        try:
            validate_csrf(data.get('csrf_token'))
        except ValidationError:
            raise webssh.SSHError('csrf_failed', 'Security token missing or expired. Refresh this WebSSH page and reconnect.') from None
        first = webssh.connection_message(data, browser=True)
        data.clear()
        vps = owned(ident)
        spec = vps.spec()
        authority = AccessGuard(g.webssh_lease, spec, user_tag=g.webssh_user_tag, user_id=user_id, node=vps.node)
        def guard():
            ws.ensure_open()
            authority()
        guard()
        audit = lambda action: record(action, user_id, ident)
        if vps.node:
            node_webssh.capability(NodeEngine(vps.node))
            node_webssh.relay(ws, vps.node, spec, first, guard, audit)
        else:
            webssh.stream(ws, spec, first, guard, audit)
    except ConnectionClosed:
        pass
    except EngineError as exc:
        webssh.error(ws, exc)
    except SQLAlchemyError:
        db.session.rollback()
        webssh.error(ws, webssh.SSHError('service_unavailable', 'WebSSH storage or auditing is temporarily unavailable. Reconnect after the operator checks the service.'))
    except (ValueError, TypeError, KeyError):
        webssh.error(ws, webssh.SSHError('invalid_message', 'Invalid WebSSH connection message.'))
    finally:
        ws.finish()
        first.get('credentials', {}).clear()
        first.clear()
        try:
            record('disconnected', user_id, ident)
        except SQLAlchemyError:
            db.session.rollback()

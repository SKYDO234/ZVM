"""Owner/admin SSHX controls. No interactive terminal, websocket or arbitrary target."""
from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from sqlalchemy.exc import SQLAlchemyError

from engines import EngineError, UncertainError
from extensions import db
from models import GuestAccess, Job
from routes.vps import owned
from services import sshx
from services.guest_access import GuestGuard
from services.guest_ssh import admission, credentials, new_key
from services.provisioning import ACTIVE_JOBS, queue_action
from services.security import audit, encrypt, locked

bp = Blueprint('sshx', __name__, url_prefix='/vps')


def page_state(vps, metric):
    access = db.session.get(GuestAccess, vps.id)
    pending = db.session.scalar(db.select(Job).where(Job.instance_id == vps.id, Job.kind.in_(['sshx_generate', 'sshx_stop']),
                                                    Job.status.in_(ACTIVE_JOBS)).order_by(Job.created_at.desc()).limit(1))
    latest = db.session.scalar(db.select(Job).where(Job.instance_id == vps.id, Job.kind.in_(['sshx_generate', 'sshx_stop']))
                                .order_by(Job.created_at.desc()).limit(1))
    reason = None
    if not current_app.config['SSHX_ENABLED']:
        reason = 'SSHX is disabled by the operator.'
    elif current_app.config['TEST_MODE']:
        reason = 'SSHX is unavailable in test mode. No VM connection will be attempted.'
    elif vps.engine != 'qemu':
        reason = 'SSHX requires a managed QEMU VM; Docker instances have no managed SSH service.'
    elif vps.suspended:
        reason = 'This VM is suspended.'
    elif metric['status'] != 'running':
        reason = 'Start the VM and wait for its guest SSH service before generating SSHX.'
    elif not access:
        reason = 'Complete one-time enrollment using existing guest credentials. No reset or reinstall is needed.'
    elif vps.runtime.get('network_restricted', True):
        reason = 'Guest internet is restricted. Ask an administrator to enable outbound internet while the VM is stopped.'
    elif pending:
        reason = 'An SSHX task is pending or uncertain. Check its operation status before trying again.'
    try:
        visible = sshx.visible_session(vps) if access and metric['status'] == 'running' and not vps.suspended else None
    except EngineError as exc:
        visible, reason = None, str(exc)  # Keep ordinary guest power controls usable if a secret cannot be decrypted.
    return {'access': access, 'pending': pending, 'latest': latest, 'reason': reason, 'session': visible,
            'can_stop': bool(access and metric['status'] == 'running' and not vps.suspended and not pending
                             and current_app.config['SSHX_ENABLED'] and not current_app.config['TEST_MODE']),
            'max_minutes': current_app.config['SSHX_MAX_SECONDS'] // 60,
            'ready_minutes': (current_app.config['SSHX_READY_SECONDS'] + 59) // 60}


@bp.post('/<ident>/sshx/generate')
@login_required
def generate(ident):
    vps = owned(ident)
    try:
        queue_action(current_user, vps, 'sshx_generate')
        flash('Generating SSHX inside this VM. The actual access link will appear below when the task completes.', 'success')
    except EngineError as exc:
        flash(str(exc), 'error')
    return redirect(url_for('vps.details', ident=ident, _anchor='sshx'))


@bp.post('/<ident>/sshx/stop')
@login_required
def stop(ident):
    vps = owned(ident)
    try:
        queue_action(current_user, vps, 'sshx_stop')
        flash('Stopping the verified SSHX client inside this VM. A hidden link alone does not revoke access.', 'success')
    except EngineError as exc:
        flash(str(exc), 'error')
    return redirect(url_for('vps.details', ident=ident, _anchor='sshx'))


@bp.route('/<ident>/sshx/enroll', methods=['GET', 'POST'])
@login_required
def enroll(ident):
    vps = owned(ident)
    spec, node = vps.spec(), vps.node
    guard = GuestGuard(spec, current_user, node)
    fingerprint, failure = None, None
    try:
        if vps.suspended:
            raise EngineError('Enrollment is unavailable while the VM is suspended.')
        sshx.validate_spec(spec)
        with locked(f'control-{ident}', blocking=False), admission(f'user:{current_user.id}', ident):
            if db.session.scalar(db.select(Job.id).where(Job.instance_id == ident, Job.status.in_(ACTIVE_JOBS))):
                raise EngineError('Wait for this VM’s pending task or reconcile its uncertain operation first.')
            if request.method == 'GET':
                fingerprint = sshx.dispatch(spec, 'probe', node=node, check=guard)['fingerprint']
            else:
                if request.form.get('trust_host') != '1':
                    raise EngineError('Verify and explicitly accept the shown guest host fingerprint first.')
                fingerprint = request.form.get('host_fingerprint', '')
                if request.form.get('method') == 'password':
                    auth = credentials({'method': 'password', 'password': request.form.get('guest_password', '')})
                elif request.form.get('method') == 'key':
                    auth = credentials({'method': 'key', 'private_key': request.form.get('private_key', ''),
                                        'passphrase': request.form.get('passphrase', '')})
                else:
                    raise EngineError('Select guest password or private-key authentication.')
                private, public = new_key()
                try:
                    sshx.dispatch(spec, 'enroll', node=node, host_fingerprint=fingerprint, auth=auth,
                                  public_key=public, check=guard)
                    # Authenticate with the new key before replacing any saved key.
                    verified = sshx.dispatch(spec, 'verify', node=node, host_fingerprint=fingerprint, private=private, check=guard)
                    guard(force=True)
                    access = db.session.get(GuestAccess, ident)
                    if not access:
                        access = GuestAccess(instance_id=ident)
                        db.session.add(access)
                    access.private_key_encrypted = encrypt({'private_key': private})
                    access.host_fingerprint = verified['fingerprint']
                    audit('sshx.enrolled', 'Encrypted per-VM management access enrolled; guest credentials preserved.', current_user.id, ident)
                    db.session.commit()
                finally:
                    auth.clear()
                flash('SSHX management access is ready. Existing guest passwords and keys were preserved.', 'success')
                return redirect(url_for('vps.details', ident=ident, _anchor='sshx'))
    except SQLAlchemyError:
        db.session.rollback()
        flash('Guest authentication was not reset, but management-key storage could not be confirmed. Retry enrollment using your existing guest credential.', 'error')
        return redirect(url_for('sshx.enroll', ident=ident))
    except (EngineError, BlockingIOError) as exc:
        db.session.rollback()
        # Never re-render submitted credentials. Fingerprints are public, not guest secrets.
        failure = ('The guest operation may have completed; your prior saved key was preserved. Retry enrollment with guest credentials.'
                   if isinstance(exc, UncertainError) else (str(exc) if isinstance(exc, EngineError) else 'This VM is busy. Wait for its current operation.'))
        if request.method == 'POST':
            flash(failure, 'error')
            return redirect(url_for('sshx.enroll', ident=ident))
    return render_template('sshx_enroll.html', vps=vps, fingerprint=fingerprint, failure=failure)

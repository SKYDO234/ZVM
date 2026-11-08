"""Non-replaying operator recovery. Never unlock live work or erase storage claims."""
from flask import current_app
from engines import EngineError, engine_for
from extensions import db
from models import Node, SSHXSession, User, VPS
from services.security import audit, decrypt, locked

SIMPLE_POWER = ('start', 'stop', 'restart', 'force_stop')


def execution_lock(ident, agent=False):
    return locked(f'{"operation" if agent else "job"}-{ident}', blocking=False)


def options(job, actor):
    administrator = bool(actor.is_authenticated and actor.is_admin)
    return {
        'can_cancel': administrator and job.status == 'queued',
        'can_reconcile': administrator and job.status == 'uncertain' and bool(job.payload),
        'can_close_power': (administrator and job.status == 'uncertain' and bool(job.payload)
                           and job.kind in SIMPLE_POWER and not any((job.ram_mb, job.vcpus, job.disk_gb))),
    }


def _operator(actor, expected_tag=None):
    user = db.session.get(User, actor.id, populate_existing=True)
    if not user or not user.enabled or not user.is_admin:
        raise EngineError('An enabled administrator is required for operation recovery.')
    if expected_tag is not None and user.get_id() != expected_tag:
        raise EngineError('Administrator authority changed during inspection. No operation was closed.')
    if current_app.config['TEST_MODE']:
        raise EngineError('Test mode: job recovery mutations are disabled.')
    return user


def cancel_queued(job, actor):
    """The execution lock makes cancellation and worker claims mutually exclusive."""
    actor = _operator(actor)
    tag = actor.get_id()
    try:
        with execution_lock(job.id), locked(f'control-{job.instance_id}', blocking=False), locked('allocation'):
            db.session.refresh(job)
            if job.status != 'queued':
                raise EngineError('Only a queued, unclaimed job can be cancelled. Started or uncertain work requires inspection.')
            _operator(actor, tag)
            job.status, job.payload = 'cancelled', None
            job.message = 'Cancelled before the worker claimed this request. No engine action was performed.'
            audit('job.cancelled', job.message, actor.id, job.instance_id)
            db.session.commit()
    except BlockingIOError as exc:
        raise EngineError('A worker still owns this operation or instance. It was not cancelled; wait for its actual outcome.') from exc


def close_power(job, actor):
    """Close an interrupted zero-reservation power request as FAILED, not success.

    Current state is proven without replaying the action. The VPS and its quota
    allocation remain. Creation, deletion, storage, assignment and SSHX jobs are
    deliberately excluded. Remote work must first be terminal on the real agent.
    """
    from services.recovery import inspect_power_state
    from services import sshx
    actor = _operator(actor)
    tag = actor.get_id()
    try:
        with execution_lock(job.id), locked(f'control-{job.instance_id}', blocking=False):
            db.session.refresh(job)
            if (job.status != 'uncertain' or job.kind not in SIMPLE_POWER or not job.payload
                    or any((job.ram_mb, job.vcpus, job.disk_gb))):
                raise EngineError('Only an uncertain basic power request with preserved context and no allocation reservation can be closed this way. Storage/provisioning reservations are never bypassed.')
            payload = decrypt(job.payload)
            saved = payload.get('spec') if isinstance(payload, dict) else None
            instance = db.session.get(VPS, job.instance_id)
            if (not instance or not isinstance(saved, dict) or instance.node_id != job.node_id or instance.engine != job.engine
                    or any(type(saved.get(k)) is not type(getattr(instance, k)) or saved.get(k) != getattr(instance, k)
                           for k in ('id', 'owner_id', 'engine', 'ram_mb', 'vcpus', 'disk_gb'))):
                raise EngineError('The preserved instance identity or allocation changed. Manual inspection is required.')
            engine = engine_for(job.engine, db.session.get(Node, job.node_id) if job.node_id else None)
            if job.node_id:
                remote = engine.operation_status(job.id)
                if remote['status'] == 'uncertain':
                    remote = engine.close_power(job.id)
                if remote['status'] != 'failed':
                    raise EngineError(f'The external operation is {remote["status"]}. Inspect/reconcile it; a parent lock cannot clear live or completed agent work.')
                # Even a terminal agent failure is not a substitute for fresh,
                # TLS-authenticated instance identity/allocation/state proof.
                state = engine.metrics(instance.spec()).get('status')
                if state not in ('running', 'stopped'):
                    raise EngineError('The node cannot prove the current guest state; the parent request remains uncertain.')
            else:
                state = inspect_power_state(instance.spec(), engine)
            with locked('allocation'):
                _operator(actor, tag)
                if state == 'stopped':
                    sshx.retire(instance.id)
                else:
                    session = db.session.get(SSHXSession, instance.id)
                    if session:
                        # Do not claim revocation or display an old capability
                        # when an interrupted restart's history is unproven.
                        session.state = 'uncertain'
                job.status, job.payload = 'failed', None
                job.message = (f'Interrupted {job.kind.replace("_", " ")} request closed after verified {state} state. '
                               'The original outcome is not claimed; no power/storage action was replayed. The VPS allocation is retained.')
                audit('job.power_closed', job.message, actor.id, job.instance_id)
                db.session.commit()
    except BlockingIOError as exc:
        raise EngineError('A worker still owns this operation or instance. No lock was cleared; wait until it finishes.') from exc

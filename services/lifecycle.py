"""Shared lifecycle safety and presentation policy; never an engine substitute."""
from flask import has_request_context, url_for
from flask_login import current_user
from engines import EngineError, UncertainError
from extensions import db
from models import Job

ACTIVE_JOBS = ('queued', 'running', 'uncertain')
POWER_ACTIONS = ('start', 'stop', 'restart', 'force_stop', 'delete')


class JobConflict(EngineError):
    """Expose the real blocker, never silently enqueue a conflicting action."""
    def __init__(self, job, action):
        self.job = job
        self.duplicate = job.kind == action and job.status in ('queued', 'running') and action in POWER_ACTIONS
        requested = action.replace('_', ' ').title()
        detail = f'{job.kind.replace("_", " ").title()} job #{job.id[:8]} is {job.status}.'
        super().__init__((f'{detail} No additional operation was queued.' if self.duplicate else
                          f'{requested} was not queued: {detail}') +
                         (' An uncertain job needs inspection in Jobs & recovery; no live lock or storage reservation was cleared.'
                          if job.status == 'uncertain' else ' Follow the existing job instead of submitting another request.'))


def blocking_jobs(jobs):
    """Only public status/authorized internal links; no encrypted context/keys."""
    result = []
    for job in jobs:
        viewable = has_request_context() and (current_user.is_admin or current_user.id == job.owner_id)
        result.append({'id': job.id, 'kind': job.kind, 'status': job.status,
                       'url': url_for('vps.job', ident=job.id) if viewable else None})
    return result


def shutdown_recovery(job, action):
    """Only a proven shutdown may recover an uncertain guest SSHX operation."""
    return (job.status == 'uncertain' and job.kind in ('sshx_generate', 'sshx_stop')
            and action in ('stop', 'force_stop', 'suspend', 'delete'))


def running_result(engine, spec):
    """A fresh, engine-verified running state makes a duplicate Start a no-op.

    This does not infer success from DB runtime, an open port, or a UI badge.
    QEMU proves the exact process and QMP state; Docker proves owned labels;
    external metrics are TLS-authenticated and identity/allocation-validated.
    """
    metric = engine.metrics(spec)
    if isinstance(metric, dict) and metric.get('status') == 'running':
        return {'status': 'running', 'already_running': True}
    return None


def stop_before_transition(engine, spec, **kwargs):
    """Never restart/delete after a failed or unproven graceful shutdown."""
    result = engine.stop(spec, **kwargs)
    if not isinstance(result, dict) or result.get('status') != 'stopped':
        raise UncertainError('The engine did not prove a complete shutdown. No restart or deletion was attempted. Inspect the actual guest state before retrying.')
    return result


def control_state(vps, status):
    """UI hints only. Routes and workers independently enforce authorization."""
    active = list(db.session.scalars(db.select(Job).where(
        Job.instance_id == vps.id, Job.status.in_(ACTIVE_JOBS))))
    enabled = {
        'start': status == 'stopped',
        'stop': status not in ('stopped', 'missing'),
        'restart': status == 'running',
        'force_stop': status not in ('stopped', 'missing'),
        'delete': status in ('running', 'stopped', 'missing'),
    }
    reasons = {
        'start': ('This VPS is already running.' if status == 'running' else
                  'Start is available only for a verified stopped instance.'),
        'stop': 'This VPS is already stopped or its managed resource is missing.',
        'restart': 'Restart is available only for a verified running instance. Use Start for a stopped VPS.',
        'force_stop': 'This VPS is already stopped or its managed resource is missing.',
        'delete': 'The current guest state cannot be verified. Restore node access or ask an administrator to inspect it.',
    }
    notice = ''
    if vps.suspended:
        enabled['start'] = enabled['restart'] = False
        reasons['start'] = reasons['restart'] = 'This VPS is suspended. Contact an administrator.'
        notice = 'This VPS is suspended. Start and restart are unavailable; you can still stop or delete your own instance.'
    for kind in POWER_ACTIONS:
        blocked = [job for job in active if not shutdown_recovery(job, kind)]
        if blocked:
            reason = ('An uncertain operation needs administrator reconciliation before another lifecycle action.'
                      if any(job.status == 'uncertain' for job in blocked) else
                      'Another operation is queued or running. Wait for it to finish.')
            enabled[kind], reasons[kind], notice = False, reason, reason
    controls = {kind: {'enabled': enabled[kind], 'reason': '' if enabled[kind] else reasons[kind]}
                for kind in POWER_ACTIONS}
    return {'controls': controls, 'control_notice': notice, 'blocking_jobs': blocking_jobs(active)}

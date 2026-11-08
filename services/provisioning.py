import logging
import hashlib
import threading
import uuid
from flask import current_app
from engines import EngineError, UncertainError, engine_for
from extensions import db
from models import GuestAccess, Job, Node, SSHXSession, User, VPS
from models.user import utcnow
from services.security import audit, decrypt, encrypt, integer, locked, safe_message, settings
from services.validation import capacity_check, quota_check
from services.guest_ssh import admission, new_key
from services.guest_access import GuestGuard
from services import sshx
from services.lifecycle import ACTIVE_JOBS, POWER_ACTIONS, running_result, shutdown_recovery, stop_before_transition


def queue_create(user, spec, credentials, node=None):
    if current_app.config['TEST_MODE']:
        raise EngineError('Test mode does not provision or create VPS records.')
    if not user.enabled or not user.is_admin:
        raise EngineError('Only administrators can create and assign instances.')
    owner = db.session.get(User, spec.get('owner_id'))
    if not owner or not owner.enabled:
        raise EngineError('Select an enabled account to own this instance.')
    with locked('allocation'):
        quota_check(owner, spec)
        capacity_check(spec, node)
        credentials = dict(credentials)
        payload = {'spec': spec, 'credentials': credentials, 'actor_id': user.id, 'actor_tag': user.get_id()}
        if spec['engine'] == 'qemu':
            private, credentials['control_public_key'] = new_key()
            payload['control_private_key'] = private
        job = Job(id=str(uuid.uuid4()), owner_id=owner.id, instance_id=spec['id'], node_id=node.id if node else None,
                  kind='create', engine=spec['engine'], ram_mb=spec['ram_mb'], vcpus=spec['vcpus'], disk_gb=spec['disk_gb'],
                  payload=encrypt(payload))
        db.session.add(job)
        audit('provision.queued', f'Provisioning {spec["name"]} with {spec["engine"]}; assigned account ID {owner.id}.', user.id, spec['id'])
        db.session.commit()
        return job


def queue_action(user, vps, action, extra=None):
    if current_app.config['TEST_MODE']:
        raise EngineError('Test mode: lifecycle mutations are disabled.')
    if not user.enabled or (vps.owner_id != user.id and not user.is_admin):
        raise EngineError('Instance ownership check failed.')
    if action not in ('start', 'stop', 'restart', 'force_stop', 'delete', 'resize', 'suspend', 'unsuspend', 'reinstall', 'network', 'assign', 'sshx_generate', 'sshx_stop'):
        raise EngineError('Unsupported action.')
    if vps.suspended and action in ('start', 'restart', 'reinstall', 'sshx_generate'):
        raise EngineError('This instance is suspended. Contact an administrator.')
    if action in ('suspend', 'unsuspend', 'network', 'assign') and not user.is_admin:
        raise EngineError('An administrator role is required.')
    with locked('allocation'):
        active = list(db.session.scalars(db.select(Job).where(Job.instance_id == vps.id, Job.status.in_(ACTIVE_JOBS))))
        # A proven VM shutdown safely ends even an unreported SSHX client. Never
        # relax locks/reservations for uncertain create/storage/lifecycle work.
        if any(not shutdown_recovery(j, action) for j in active):
            raise EngineError('An active or uncertain job already exists for this instance. Wait or ask an administrator to reconcile it.')
        extra = dict(extra or {})
        extra.update(actor_id=user.id, actor_tag=user.get_id())
        extra.setdefault('spec', vps.spec())  # Preserve identity for safe delete/crash inspection.
        growth = 0
        if action == 'resize':
            if vps.engine != 'qemu':
                raise EngineError('Disk growth is only supported for stopped QEMU VMs.')
            size = integer(extra.get('disk_gb'), 'Disk', vps.disk_gb + 1, settings()['max_instance_disk_gb'])
            extra['disk_gb'], growth = size, size - vps.disk_gb
            proposed = vps.spec() | {'disk_gb': size}
            quota_check(vps.owner, proposed, resize_of=vps)
            capacity_check(proposed, vps.node, resize_of=vps, require_available_ram=False)
        assignee = None
        if action == 'assign':
            if extra.get('guest_credentials_reviewed') is not True:
                raise EngineError('Review guest credentials before reassignment: existing native SSH keys/passwords are not rotated automatically.')
            ident = integer(extra.get('owner_id'), 'Assigned account', 1, 2**31 - 1)
            assignee = db.session.get(User, ident)
            if not assignee or not assignee.enabled or assignee.id == vps.owner_id:
                raise EngineError('Select a different enabled owner.')
            if vps.engine != 'qemu':
                raise EngineError('Existing-instance reassignment currently requires a stopped QEMU VM.')
            quota_check(assignee, vps.spec() | {'owner_id': assignee.id})
            extra['owner_id'] = assignee.id
        if action == 'network':
            if vps.engine != 'qemu' or type(extra.get('network_restricted')) is not bool:
                raise EngineError('Choose a network policy for a stopped QEMU VM.')
        if action in ('sshx_generate', 'sshx_stop'):
            sshx.validate_spec(vps.spec())
            if not db.session.get(GuestAccess, vps.id):
                raise EngineError('Complete one-time SSHX enrollment for this existing VM first.')
            if action == 'sshx_generate' and vps.runtime.get('network_restricted', True):
                raise EngineError('An administrator must explicitly enable guest outbound internet while this VM is stopped.')
        if action == 'reinstall' and vps.engine == 'qemu':
            private, public = new_key()
            extra['credentials'] = dict(extra['credentials'], control_public_key=public)
            extra['control_private_key'] = private
        # Assigned owners can poll/view power and SSHX work requested by an
        # administrator. The encrypted actor/tag still authorize that requester;
        # growth reservation accounting remains unchanged.
        owner_visible = action in (*POWER_ACTIONS, 'sshx_generate', 'sshx_stop')
        job_owner = assignee.id if assignee else (vps.owner_id if owner_visible else user.id)
        job = Job(id=str(uuid.uuid4()), owner_id=job_owner, instance_id=vps.id, node_id=vps.node_id,
                  kind=action, engine=vps.engine, ram_mb=vps.ram_mb if assignee else 0,
                  vcpus=vps.vcpus if assignee else 0, disk_gb=vps.disk_gb if assignee else growth, payload=encrypt(extra))
        db.session.add(job)
        audit(f'{action}.queued', f'{action.replace("_", " ").title()} requested for {vps.name}.', user.id, vps.id)
        db.session.commit()
        return job


def _apply_result(job, payload, result):
    if not isinstance(result, dict):
        raise UncertainError('The engine returned no verified operation result.')
    expected = {'start': 'running', 'restart': 'running', 'stop': 'stopped', 'force_stop': 'stopped',
                'suspend': 'stopped', 'delete': 'deleted', 'reinstall': 'stopped', 'network': 'stopped', 'assign': 'stopped'}
    if job.kind in expected and result.get('status') != expected[job.kind]:
        raise UncertainError('The engine result did not prove the requested guest state. No tunnel revocation was claimed.')
    if job.kind == 'assign' and result.get('owner_id') != payload['owner_id']:
        raise UncertainError('The engine did not prove the selected ownership assignment.')
    if job.kind == 'network' and result.get('runtime', {}).get('network_restricted') is not payload['network_restricted']:
        raise UncertainError('The engine did not prove the selected guest network policy.')
    if job.kind in ('create', 'reinstall') and payload.get('control_private_key'):
        public = payload['credentials']['control_public_key']
        if result.get('runtime', {}).get('control_key_sha256') != hashlib.sha256(public.encode()).hexdigest():
            raise UncertainError('Provisioning did not prove the new management public key was included in the guest seed. Pending encrypted key retained for recovery.')
    if job.kind == 'create':
        spec = payload['spec']
        if not result.get('runtime') or not result.get('status'):
            raise UncertainError('Engine returned no verified resource metadata. No VPS record was inserted.')
        if not db.session.get(VPS, spec['id']):
            vps = VPS(**{k: spec[k] for k in ('id', 'owner_id', 'name', 'engine', 'os_id', 'ram_mb', 'vcpus', 'disk_gb', 'username')},
                      node_id=job.node_id, runtime=result['runtime'], ssh_port=result.get('ssh_port'))
            db.session.add(vps)
            db.session.flush()
        if payload.get('control_private_key') and not db.session.get(GuestAccess, spec['id']):
            db.session.add(GuestAccess(instance_id=spec['id'], private_key_encrypted=encrypt({'private_key': payload['control_private_key']})))
    else:
        vps = db.session.get(VPS, job.instance_id)
        if vps:
            if (job.kind in ('start', 'stop', 'restart', 'force_stop', 'suspend', 'delete', 'reinstall', 'network', 'assign')
                    and not (job.kind == 'start' and result.get('already_running') is True)):
                # An idempotent Start did not stop/restart the guest or its
                # SSHX client; do not falsely retire an existing capability.
                sshx.retire(vps.id)
                if job.kind in ('stop', 'force_stop', 'suspend', 'delete'):
                    for old in db.session.scalars(db.select(Job).where(Job.instance_id == vps.id, Job.kind.in_(['sshx_generate', 'sshx_stop']), Job.status == 'uncertain')):
                        old.status, old.payload = 'failed', None
                        old.message = 'VM shutdown proved the guest SSHX client cannot remain running.'
            if job.kind == 'sshx_generate':
                sshx.save_session(vps, job.id, result, payload.get('sshx_started_at'))
            elif job.kind == 'sshx_stop':
                sshx.retire(vps.id)
            elif job.kind == 'assign':
                vps.owner_id = payload['owner_id']
            elif job.kind == 'delete':
                db.session.delete(vps)
            elif job.kind == 'suspend':
                vps.suspended = True
            elif job.kind == 'unsuspend':
                vps.suspended = False
            elif job.kind == 'resize':
                vps.disk_gb = result['disk_gb']
            elif job.kind == 'reinstall':
                spec = payload['spec']
                vps.os_id = spec['os_id']
                vps.username = spec['username']
                vps.runtime = result['runtime']
                vps.ssh_port = result.get('ssh_port')
                if payload.get('control_private_key'):
                    access = db.session.get(GuestAccess, vps.id)
                    if access is None:
                        access = GuestAccess(instance_id=vps.id)
                        db.session.add(access)
                    access.private_key_encrypted = encrypt({'private_key': payload['control_private_key']})
                    access.host_fingerprint = None
            if result.get('runtime') and job.kind != 'delete':
                vps.runtime = result['runtime']
    job.status, job.payload = 'completed', None
    if job.kind == 'create':
        job.message = f"Provisioned successfully; current engine state: {result['status']}."
    elif job.kind == 'start' and result.get('already_running') is True:
        job.message = 'Already running; no second instance was started.'
    else:
        job.message = f"{job.kind.replace('_', ' ').title()} completed."
    audit(f'{job.kind}.completed', job.message, payload.get('actor_id', job.owner_id), job.instance_id)
    db.session.commit()


def process_job(job_id):
    job = db.session.get(Job, job_id)
    if not job or job.status != 'queued':
        return
    mutated = False
    already_running = None
    actor_id = None
    try:
        payload = decrypt(job.payload)
        actor_id = payload.get('actor_id', job.owner_id)
        job.status = 'running'
        job.message = ('Validating configuration and provisioning with the real engine…' if job.kind == 'create' else
                       'Validating the lifecycle request and actual managed instance state…')
        db.session.commit()
        user = db.session.get(User, payload.get('actor_id', job.owner_id))
        if not user or not user.enabled:
            raise EngineError('The requesting user is disabled.')
        if payload.get('actor_tag') and user.get_id() != payload['actor_tag']:
            raise EngineError('The requesting account/session changed after this operation was queued.')
        if job.kind in ('create', 'assign') and not user.is_admin:
            raise EngineError('Only administrators can create or assign instances, including queued operations.')
        node = db.session.get(Node, job.node_id) if job.node_id else None
        engine = engine_for(job.engine, node)
        # Capacity reservations live in Job rows. Keep the global lock short during large downloads.
        # Only disk growth holds it across the (short) resize operation, since that changes a reservation.
        from contextlib import nullcontext
        with locked(f'control-{job.instance_id}'):
            with locked('allocation'):
                if current_app.config['TEST_MODE']:
                    raise EngineError('Test mode: no real resources or VPS records are created.')
                if job.kind == 'create':
                    spec = payload['spec']
                    owner = db.session.get(User, spec['owner_id'])
                    if not owner or not owner.enabled or owner.id != job.owner_id:
                        raise EngineError('The assigned account is disabled or the quota owner changed.')
                    quota_check(owner, spec, exclude_job=job.id)
                    capacity_check(spec, node, exclude_job=job.id)
                    if job.engine == 'qemu' and not spec['ssh_port']:
                        spec['ssh_port'] = allocate_port(node, exclude_ports=[p['host'] for p in spec.get('forwards', [])])
                    validate_ports(spec, node)
                    payload['spec'] = spec
                    if job.engine == 'qemu' and not payload.get('control_private_key'):
                        private, public = new_key()
                        payload['control_private_key'] = private
                        payload['credentials'] = dict(payload.get('credentials', {}), control_public_key=public)
                    job.payload = encrypt(payload)
                    db.session.commit()
                else:
                    vps = db.session.get(VPS, job.instance_id)
                    if not vps:
                        raise EngineError('The instance no longer exists.')
                    if vps.owner_id != user.id and not user.is_admin:
                        raise EngineError('Instance ownership check failed.')
                    if vps.suspended and job.kind in ('start', 'restart', 'reinstall', 'sshx_generate'):
                        raise EngineError('The instance is suspended.')
                    spec = vps.spec()
                    if job.kind == 'start':
                        already_running = running_result(engine, spec)
                    if job.kind in ('start', 'restart') and already_running is None:
                        capacity_check(spec, node, resize_of=vps, require_available_ram=job.kind != 'restart')
                    if job.kind in ('suspend', 'unsuspend', 'network', 'assign') and not user.is_admin:
                        raise EngineError('An administrator role is required.')
                    if job.kind == 'assign':
                        owner = db.session.get(User, payload['owner_id'])
                        if not owner or not owner.enabled or owner.id != job.owner_id:
                            raise EngineError('The assigned account is disabled or changed.')
                        quota_check(owner, spec | {'owner_id': owner.id}, exclude_job=job.id)
            with (locked('allocation') if job.kind in ('resize', 'assign') else nullcontext()):
                if job.kind == 'resize':
                    new_spec = spec | {'disk_gb': payload['disk_gb']}
                    quota_check(vps.owner, new_spec, resize_of=vps, exclude_job=job.id)
                    capacity_check(new_spec, node, resize_of=vps, exclude_job=job.id, require_available_ram=False)
                mutated = already_running is None
                if already_running is not None:
                    result = already_running
                elif job.kind in ('sshx_generate', 'sshx_stop'):
                    payload['sshx_started_at'] = utcnow().isoformat()
                    job.payload = encrypt(payload)
                    db.session.commit()
                    private, pin = sshx.stored_access(spec['id'])
                    guard = GuestGuard(spec, user, node)
                    previous = db.session.get(SSHXSession, spec['id'])
                    if previous:
                        previous.state = 'uncertain'  # Hiding a link is NOT claiming it was revoked.
                        db.session.commit()
                    with admission(f'user:{user.id}', spec['id']):
                        result = sshx.dispatch(spec, 'generate' if job.kind == 'sshx_generate' else 'stop', node=node,
                                               private=private, host_fingerprint=pin, operation_id=job.id,
                                               seconds=current_app.config['SSHX_MAX_SECONDS'], check=guard)
                    try:
                        guard(force=True)
                    except EngineError:
                        raise UncertainError('Authority changed after an SSHX guest operation. Inspect its outcome or stop the VM.') from None
                elif job.kind == 'assign':
                    result = engine.assign(spec, payload['owner_id'], operation_id=job.id)
                elif job.kind == 'network':
                    result = engine.network(spec, payload['network_restricted'], operation_id=job.id)
                elif job.kind == 'create':
                    result = engine.create(spec, payload['credentials'], operation_id=job.id)
                elif job.kind == 'restart' and node is None:
                    stop_before_transition(engine, spec, operation_id=job.id)
                    # The old process has released memory. Recheck actual availability now.
                    with locked('allocation'):
                        capacity_check(spec, resize_of=vps, exclude_job=job.id)
                    result = engine.start(spec, operation_id=job.id)
                elif job.kind == 'delete' and node is None:
                    # One owner-authorized job, with no implicit Force stop.
                    # External nodes perform this atomically in their worker;
                    # never reuse one remote operation ID for stop then delete.
                    stop_before_transition(engine, spec, operation_id=job.id)
                    result = engine.delete(spec, operation_id=job.id)
                elif job.kind == 'suspend':
                    result = engine.stop(spec, operation_id=job.id)
                elif job.kind == 'unsuspend':
                    result = {'status': 'unsuspended'}
                elif job.kind == 'resize':
                    result = engine.resize(spec, payload['disk_gb'], operation_id=job.id)
                elif job.kind == 'reinstall':
                    result = engine.reinstall(payload['spec'], payload['credentials'], operation_id=job.id)
                else:
                    result = getattr(engine, job.kind)(spec, operation_id=job.id)
                if job.kind in ('resize', 'assign'):
                    _apply_result(job, payload, result)
                else:
                    with locked('allocation'):
                        _apply_result(job, payload, result)
    except UncertainError as exc:
        db.session.rollback()
        job = db.session.get(Job, job_id)
        if job.status == 'completed':
            return
        job.status = 'uncertain' if mutated else 'failed'
        job.message = safe_message(exc) + ('' if mutated else ' No engine mutation was attempted.')
        if not mutated:
            job.payload = None
        audit('job.uncertain', job.message, actor_id if actor_id is not None and db.session.get(User, actor_id) else None, job.instance_id)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        job = db.session.get(Job, job_id)
        if job.status == 'completed':
            return
        if mutated and not isinstance(exc, EngineError):
            job.status = 'uncertain'
            job.message = 'An engine mutation may have completed before an internal or persistence error. Inspect actual resources before recovery.'
        else:
            job.status = 'failed'
            job.message = safe_message(exc) if isinstance(exc, EngineError) else 'An internal engine error occurred. Consult the server log; no success was reported.'
            job.payload = None
        audit('job.failed', job.message, actor_id if actor_id is not None and db.session.get(User, actor_id) else None, job.instance_id)
        db.session.commit()
        if not isinstance(exc, EngineError):
            logging.exception('Provisioning job %s failed', job_id)


def allocate_port(node=None, exclude_ports=None):
    import socket
    from services.security import settings
    s = settings()
    instances = list(db.session.scalars(db.select(VPS).where(VPS.node_id == (node.id if node else None))))
    used = {v.ssh_port for v in instances if v.ssh_port}
    used.update(p['host'] for v in instances for p in v.runtime.get('forwards', []))
    used.update(exclude_ports or [])
    if node:
        # Agent checks the actual bind too. Allocate a configured unique port on that node.
        used.update(engine_for('qemu', node).capabilities().get('reserved_ports', []))
    for port in range(s['ssh_port_min'], s['ssh_port_max'] + 1):
        if port in used:
            continue
        if node:
            return port
        with socket.socket() as sock:
            try:
                sock.bind(('127.0.0.1', port))
                return port
            except OSError:
                pass
    raise EngineError('No SSH forwarding port is available in the configured range.')


def reconcile_job(job):
    """Inspect outcomes and update metadata; never replay a guest mutation."""
    from services.recovery import inspect_outcome
    with locked(f'control-{job.instance_id}'):
        db.session.refresh(job)
        if job.status != 'uncertain':
            raise EngineError('Only uncertain jobs need reconciliation.')
        if not job.payload:
            raise EngineError('The original operation context is unavailable. Manual inspection is required.')
        payload = decrypt(job.payload)
        if job.kind in ('sshx_generate', 'sshx_stop'):
            instance = db.session.get(VPS, job.instance_id)
            if not instance:
                raise EngineError('The original VM no longer exists.')
            spec = instance.spec()
            node = db.session.get(Node, job.node_id) if job.node_id else None
            engine = engine_for(job.engine, node)
            if engine.metrics(spec).get('status') == 'stopped':
                sshx.retire(instance.id)
                job.status, job.payload, job.message = 'failed', None, 'The VM is proven stopped; no SSHX client can remain running.'
                db.session.commit()
                return
            private, pin = sshx.stored_access(instance.id)
            with admission('reconcile:sshx', instance.id):
                result = sshx.dispatch(spec, 'inspect' if job.kind == 'sshx_generate' else 'inspect_stop', node=node, private=private, host_fingerprint=pin,
                                       operation_id=job.id, seconds=current_app.config['SSHX_MAX_SECONDS'])
            with locked('allocation'):
                _apply_result(job, payload, result)
            return
        if job.node_id:
            node = db.session.get(Node, job.node_id)
            engine = engine_for(job.engine, node)
            result = engine.operation_status(job.id)
            if result['status'] == 'uncertain':
                result = engine.reconcile(job.id)
            if result['status'] == 'completed':
                if job.kind == 'create':
                    metric = engine.metrics(payload['spec'])
                    if metric.get('status') in ('missing', 'unknown'):
                        raise EngineError('The external operation completed, but its resource is no longer proven to exist.')
                with locked('allocation'):
                    _apply_result(job, payload, result['result'])
                return
            if result['status'] == 'failed':
                with locked('allocation'):
                    job.status, job.message, job.payload = 'failed', result.get('error') or 'Node operation failed.', None
                    db.session.commit()
                return
            raise EngineError(f'External operation is still {result["status"]}; reservation retained.')
        if job.kind == 'create':
            spec = payload['spec']
        else:
            instance = db.session.get(VPS, job.instance_id)
            spec = instance.spec() if instance else payload.get('spec')
            if not spec or (instance is None and job.kind != 'delete'):
                raise EngineError('Original instance identity is unavailable; manual inspection is required.')
        result = inspect_outcome(job.kind, spec, payload, engine_for(job.engine))
        with locked('allocation'):
            _apply_result(job, payload, result)


def worker_loop(app, stop_event=None):
    stop_event = stop_event or threading.Event()
    if app.config['TEST_MODE']:
        return
    from services.maintenance import start_maintenance
    with app.app_context():
        try:
            with locked('worker-leader', blocking=False):
                start_maintenance(app)
                for job in db.session.scalars(db.select(Job).where(Job.status == 'running')):
                    job.status = 'uncertain'
                    job.message = 'Worker stopped during an operation. Resources may exist; an administrator must reconcile this job.'
                db.session.commit()
                while not stop_event.is_set():
                    try:
                        ident = db.session.scalar(db.select(Job.id).where(Job.status == 'queued').order_by(Job.created_at).limit(1))
                        if ident:
                            process_job(ident)
                        else:
                            stop_event.wait(1)
                    except Exception:
                        logging.exception('Worker loop error')
                        db.session.rollback()
                        stop_event.wait(2)
                    finally:
                        db.session.remove()
        except BlockingIOError:
            logging.info('Another worker owns the workspace queue.')


def start_worker(app):
    if app.config['TEST_MODE']:
        return None
    from services.background import start_background
    return start_background(app, 'skvm-provisioner', worker_loop)


def validate_ports(spec, node=None):
    if spec['engine'] != 'qemu':
        return
    import socket
    ports = [spec['ssh_port']] + [p['host'] for p in spec.get('forwards', [])]
    if len(set(ports)) != len(ports):
        raise EngineError('SSH and additional forwarding ports must be different.')
    instances = db.session.scalars(db.select(VPS).where(VPS.node_id == (node.id if node else None)))
    used = []
    for instance in instances:
        used.append(instance.ssh_port)
        used.extend(p['host'] for p in instance.runtime.get('forwards', []))
    if any(port in used for port in ports):
        raise EngineError('A forwarding port is already reserved by another instance.')
    if not node:
        for port in ports:
            with socket.socket() as sock:
                try:
                    sock.bind(('127.0.0.1', port))
                except OSError as exc:
                    raise EngineError(f'Forwarding port {port} is already in use.') from exc

import logging
import threading
import uuid
from flask import current_app
from engines import EngineError, UncertainError, engine_for
from extensions import db
from models import Job, Node, User, VPS
from services.security import audit, decrypt, encrypt, integer, locked, safe_message, settings
from services.validation import capacity_check, quota_check

ACTIVE_JOBS = ['queued', 'running', 'uncertain']


def queue_create(user, spec, credentials, node=None):
    if current_app.config['TEST_MODE']:
        raise EngineError('Test mode does not provision or create VPS records.')
    with locked('allocation'):
        quota_check(user, spec)
        capacity_check(spec, node)
        job = Job(id=str(uuid.uuid4()), owner_id=user.id, instance_id=spec['id'], node_id=node.id if node else None,
                  kind='create', engine=spec['engine'], ram_mb=spec['ram_mb'], vcpus=spec['vcpus'], disk_gb=spec['disk_gb'],
                  payload=encrypt({'spec': spec, 'credentials': credentials}))
        db.session.add(job)
        audit('provision.queued', f'Provisioning {spec["name"]} with {spec["engine"]}.', user.id, spec['id'])
        db.session.commit()
        return job


def queue_action(user, vps, action, extra=None):
    if current_app.config['TEST_MODE']:
        raise EngineError('Test mode: lifecycle mutations are disabled.')
    if action not in ('start', 'stop', 'restart', 'force_stop', 'delete', 'resize', 'suspend', 'unsuspend', 'reinstall'):
        raise EngineError('Unsupported action.')
    if vps.suspended and action in ('start', 'restart', 'reinstall'):
        raise EngineError('This instance is suspended. Contact an administrator.')
    if action in ('suspend', 'unsuspend') and not user.is_admin:
        raise EngineError('An administrator role is required.')
    with locked('allocation'):
        if db.session.scalar(db.select(Job.id).where(Job.instance_id == vps.id, Job.status.in_(ACTIVE_JOBS))):
            raise EngineError('An active or uncertain job already exists for this instance. Wait or ask an administrator to reconcile it.')
        extra = dict(extra or {})
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
        job = Job(id=str(uuid.uuid4()), owner_id=user.id, instance_id=vps.id, node_id=vps.node_id,
                  kind=action, engine=vps.engine, disk_gb=growth, payload=encrypt(extra))
        db.session.add(job)
        audit(f'{action}.queued', f'{action.replace("_", " ").title()} requested for {vps.name}.', user.id, vps.id)
        db.session.commit()
        return job


def _apply_result(job, payload, result):
    if job.kind == 'create':
        spec = payload['spec']
        if not result.get('runtime') or not result.get('status'):
            raise UncertainError('Engine returned no verified resource metadata. No VPS record was inserted.')
        if not db.session.get(VPS, spec['id']):
            vps = VPS(**{k: spec[k] for k in ('id', 'owner_id', 'name', 'engine', 'os_id', 'ram_mb', 'vcpus', 'disk_gb', 'username')},
                      node_id=job.node_id, runtime=result['runtime'], ssh_port=result.get('ssh_port'))
            db.session.add(vps)
    else:
        vps = db.session.get(VPS, job.instance_id)
        if vps:
            if job.kind == 'delete':
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
            if result.get('runtime') and job.kind != 'delete':
                vps.runtime = result['runtime']
    job.status, job.payload = 'completed', None
    if job.kind == 'create':
        job.message = f"Provisioned successfully; current engine state: {result['status']}."
    else:
        job.message = f"{job.kind.replace('_', ' ').title()} completed."
    audit(f'{job.kind}.completed', job.message, job.owner_id, job.instance_id)
    db.session.commit()


def process_job(job_id):
    job = db.session.get(Job, job_id)
    if not job or job.status != 'queued':
        return
    mutated = False
    try:
        payload = decrypt(job.payload)
        job.status, job.message = 'running', 'Validating configuration and provisioning with the real engine…'
        db.session.commit()
        user = db.session.get(User, job.owner_id)
        if not user or not user.enabled:
            raise EngineError('The requesting user is disabled.')
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
                    quota_check(user, spec, exclude_job=job.id)
                    capacity_check(spec, node, exclude_job=job.id)
                    if job.engine == 'qemu' and not spec['ssh_port']:
                        spec['ssh_port'] = allocate_port(node, exclude_ports=[p['host'] for p in spec.get('forwards', [])])
                    validate_ports(spec, node)
                    payload['spec'] = spec
                    job.payload = encrypt(payload)
                    db.session.commit()
                else:
                    vps = db.session.get(VPS, job.instance_id)
                    if not vps:
                        raise EngineError('The instance no longer exists.')
                    if vps.owner_id != user.id and not user.is_admin:
                        raise EngineError('Instance ownership check failed.')
                    if vps.suspended and job.kind in ('start', 'restart', 'reinstall'):
                        raise EngineError('The instance is suspended.')
                    spec = vps.spec()
                    if job.kind in ('start', 'restart'):
                        capacity_check(spec, node, resize_of=vps, require_available_ram=job.kind != 'restart')
                    if job.kind in ('suspend', 'unsuspend') and not user.is_admin:
                        raise EngineError('An administrator role is required.')
            with (locked('allocation') if job.kind == 'resize' else nullcontext()):
                if job.kind == 'resize':
                    new_spec = spec | {'disk_gb': payload['disk_gb']}
                    quota_check(vps.owner, new_spec, resize_of=vps, exclude_job=job.id)
                    capacity_check(new_spec, node, resize_of=vps, exclude_job=job.id, require_available_ram=False)
                mutated = True
                if job.kind == 'create':
                    result = engine.create(spec, payload['credentials'], operation_id=job.id)
                elif job.kind == 'restart' and node is None:
                    engine.stop(spec, operation_id=job.id)
                    # The old process has released memory. Recheck actual availability now.
                    with locked('allocation'):
                        capacity_check(spec, resize_of=vps, exclude_job=job.id)
                    result = engine.start(spec, operation_id=job.id)
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
                if job.kind == 'resize':
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
        audit('job.uncertain', job.message, job.owner_id, job.instance_id)
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
        audit('job.failed', job.message, job.owner_id, job.instance_id)
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

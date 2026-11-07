"""External agent worker. Persistent operation IDs prevent retries creating duplicate guests."""
import logging
import copy
import socket
import threading
from flask import current_app
from engines import EngineError, UncertainError, engine_for
from extensions import db
from models import AgentInstance, AgentOperation
from services.resource_monitor import host_metrics, require_known_capacity
from services.security import decrypt, locked, settings


def process_operation(ident):
    operation = db.session.get(AgentOperation, ident)
    mutated = False
    try:
        payload = decrypt(operation.payload)
        operation.status = 'running'
        db.session.commit()
        if current_app.config['TEST_MODE']:
            raise EngineError('Agent test mode: provisioning disabled.')
        with locked('agent-capacity'), locked(f'control-{payload["spec"]["id"]}'):
            kind = payload['kind']
            spec = payload['spec']
            if kind == 'create':
                if db.session.get(AgentInstance, spec['id']):
                    raise EngineError('Instance already exists.')
                enforce_capacity(spec)
                engine = engine_for(spec['engine'])
                mutated = True
                result = engine.create(spec, payload.get('credentials', {}))
                spec.update(runtime=result['runtime'], ssh_port=result.get('ssh_port'))
                db.session.add(AgentInstance(id=spec['id'], spec=spec))
            else:
                instance = db.session.get(AgentInstance, spec['id'])
                if not instance:
                    raise EngineError('Instance not found on this agent.')
                previous = copy.deepcopy(instance.spec)
                engine = engine_for(previous['engine'])
                if kind == 'reinstall':
                    enforce_capacity(spec, exclude=instance.id)
                    mutated = True
                    result = engine.reinstall(spec, payload['credentials'])
                    instance.spec = spec | {'runtime': result['runtime']}
                elif kind == 'assign':
                    mutated = True
                    result = engine.assign(previous, payload.get('owner_id'))
                    instance.spec = previous | {'owner_id': result['owner_id']}
                elif kind == 'network':
                    mutated = True
                    result = engine.network(previous, payload.get('network_restricted'))
                    instance.spec = previous | {'runtime': result['runtime'], 'network_restricted': payload['network_restricted']}
                elif kind == 'resize':
                    from services.security import integer
                    size = integer(payload.get('disk_gb'), 'Disk', previous['disk_gb'] + 1, settings()['max_instance_disk_gb'])
                    enforce_capacity(previous | {'disk_gb': size}, exclude=instance.id, require_available_ram=False)
                    mutated = True
                    result = engine.resize(previous, size)
                    instance.spec = previous | {'disk_gb': size}
                else:
                    if kind in ('start', 'restart'):
                        enforce_capacity(previous, exclude=instance.id, require_available_ram=kind != 'restart')
                    mutated = True
                    if kind == 'restart':
                        engine.stop(previous)
                        enforce_capacity(previous, exclude=instance.id)
                        result = engine.start(previous)
                    else:
                        result = getattr(engine, kind)(previous)
                    if kind == 'delete':
                        db.session.delete(instance)
                    elif result.get('runtime'):
                        instance.spec = previous | {'runtime': result['runtime']}
            operation.status, operation.result, operation.payload = 'completed', result, None
            db.session.commit()
    except Exception as exc:
        db.session.rollback()
        operation = db.session.get(AgentOperation, ident)
        if operation.status == 'completed':
            return
        operation.status = 'uncertain' if isinstance(exc, UncertainError) or (mutated and not isinstance(exc, EngineError)) else 'failed'
        operation.error = str(exc)[:1800] if isinstance(exc, EngineError) else 'Agent internal error; inspect the server log and actual resources.'
        if operation.status == 'failed':
            operation.payload = None
        db.session.commit()
        if not isinstance(exc, EngineError):
            logging.exception('Agent operation %s failed', ident)


def reconcile_operation(ident):
    """Authenticated operator recovery; do not repeat the original engine action."""
    from services.recovery import inspect_outcome
    if current_app.config['TEST_MODE']:
        raise EngineError('Agent test mode: reconciliation mutations are disabled.')
    try:
        with locked('agent-capacity', blocking=False):
            operation = db.session.get(AgentOperation, ident)
            if not operation or operation.status != 'uncertain' or not operation.payload:
                raise EngineError('Only an uncertain operation with preserved context can be reconciled.')
            payload = decrypt(operation.payload)
            requested = payload['spec']
            with locked(f'control-{requested["id"]}', blocking=False):
                instance = db.session.get(AgentInstance, requested['id'])
                spec = requested if payload['kind'] in ('create', 'reinstall') else (copy.deepcopy(instance.spec) if instance else requested)
                if spec.get('engine') not in ('qemu', 'docker'):
                    raise EngineError('The original engine identity is unavailable. Manual inspection is required.')
                result = inspect_outcome(payload['kind'], spec, payload, engine_for(spec['engine']))
                if payload['kind'] == 'create':
                    recovered = spec | {'runtime': result['runtime'], 'ssh_port': result.get('ssh_port')}
                    if instance:
                        if any(instance.spec.get(k) != spec.get(k) for k in ('owner_id', 'engine', 'os_id', 'ram_mb', 'vcpus', 'disk_gb')):
                            raise EngineError('The existing agent record differs from the recovery request.')
                        instance.spec = recovered
                    else:
                        db.session.add(AgentInstance(id=spec['id'], spec=recovered))
                elif payload['kind'] == 'reinstall':
                    if not instance:
                        raise EngineError('The original agent instance is missing.')
                    instance.spec = payload['spec'] | {'runtime': result['runtime'], 'ssh_port': result.get('ssh_port')}
                elif payload['kind'] == 'delete':
                    if instance:
                        db.session.delete(instance)
                elif instance:
                    if payload['kind'] == 'assign':
                        instance.spec = spec | {'owner_id': payload['owner_id']}
                    elif payload['kind'] == 'resize':
                        instance.spec = spec | {'disk_gb': result['disk_gb']}
                    elif result.get('runtime'):
                        instance.spec = spec | {'runtime': result['runtime']}
                else:
                    raise EngineError('The agent instance record is missing; no outcome was applied.')
                operation.status, operation.result, operation.payload, operation.error = 'completed', result, None, None
                db.session.commit()
                return operation
    except BlockingIOError as exc:
        raise EngineError('The agent is busy with another operation. Wait until it finishes, then reconcile again.') from exc


def enforce_capacity(spec, exclude=None, require_available_ram=True):
    instances = [i for i in db.session.scalars(db.select(AgentInstance)) if i.id != exclude]
    uncertain = list(db.session.scalars(db.select(AgentOperation).where(AgentOperation.status == 'uncertain')))
    reserved = []
    uncertain_growth = 0
    for operation in uncertain:
        payload = decrypt(operation.payload) if operation.payload else {}
        if payload.get('kind') == 'create' and payload['spec']['id'] != exclude and not db.session.get(AgentInstance, payload['spec']['id']):
            reserved.append(payload['spec'])
        elif payload.get('kind') == 'resize':
            previous = db.session.get(AgentInstance, payload['spec']['id'])
            if previous:
                uncertain_growth += max(0, int(payload['disk_gb']) - previous.spec['disk_gb'])
    allocations = [i.spec for i in instances] + reserved
    s, host = settings(), host_metrics()
    require_known_capacity(host)
    if len(allocations) >= s['max_instances_per_node']:
        raise EngineError('Agent instance count quota reached.')
    if sum(i['ram_mb'] for i in allocations) + spec['ram_mb'] > host['ram_total_mb'] * s['host_memory_fraction']:
        raise EngineError('Agent RAM allocation budget exhausted.')
    if require_available_ram and spec['ram_mb'] > max(0, host['ram_available_mb'] - 256):
        raise EngineError('Insufficient currently available agent RAM.')
    if sum(i['vcpus'] for i in allocations) + spec['vcpus'] > max(0, host['cpu_capacity']):
        raise EngineError('Agent CPU allocation budget exhausted.')
    if sum(i['disk_gb'] for i in allocations) + uncertain_growth + spec['disk_gb'] + s['host_storage_reserve_gb'] > host['disk_free_gb']:
        raise EngineError('Agent storage budget exhausted.')
    if spec['engine'] == 'qemu' and not exclude:
        ports = [spec['ssh_port']] + [p['host'] for p in spec.get('forwards', [])]
        used = [i.spec.get('ssh_port') for i in instances]
        used += [p['host'] for i in instances for p in i.spec.get('runtime', {}).get('forwards', [])]
        if len(set(ports)) != len(ports) or any(p in used for p in ports):
            raise EngineError('Agent forwarding port is already reserved.')
        for port in ports:
            with socket.socket() as sock:
                try:
                    sock.bind(('127.0.0.1', port))
                except OSError as exc:
                    raise EngineError(f'Agent port {port} is occupied.') from exc


def agent_loop(app, stop_event=None):
    stop_event = stop_event or threading.Event()
    if app.config['TEST_MODE']:
        return
    from services.maintenance import start_maintenance
    with app.app_context():
        try:
            with locked('agent-worker', blocking=False):
                start_maintenance(app)
                for operation in db.session.scalars(db.select(AgentOperation).where(AgentOperation.status == 'running')):
                    operation.status, operation.error = 'uncertain', 'Agent restarted mid-operation. Inspect resources before recovery.'
                db.session.commit()
                while not stop_event.is_set():
                    try:
                        ident = db.session.scalar(db.select(AgentOperation.id).where(AgentOperation.status == 'queued').order_by(AgentOperation.created_at).limit(1))
                        if ident:
                            process_operation(ident)
                        else:
                            stop_event.wait(1)
                    except Exception:
                        logging.exception('Agent worker failed')
                        db.session.rollback()
                        stop_event.wait(2)
                    finally:
                        db.session.remove()
        except BlockingIOError:
            logging.info('An agent worker is already running.')


def start_agent_worker(app):
    if app.config['TEST_MODE']:
        return None
    from services.background import start_background
    return start_background(app, 'skvm-node-worker', agent_loop)

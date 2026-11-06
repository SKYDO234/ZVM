"""Standalone external agent API. Register ONLY in node-agent mode; no browser sessions."""
import hashlib
import json
import re
import secrets
from flask import Blueprint, abort, current_app, jsonify, request
from engines import EngineError, engine_for
from extensions import db
from models import AgentInstance, AgentOperation, OSImage
from services.resource_monitor import host_metrics
from services.security import encrypt, integer, settings, ssh_key, valid_uuid

node_api = Blueprint('node_api', __name__, url_prefix='/v1')


@node_api.before_request
def authenticate():
    expected = current_app.config.get('NODE_TOKEN')
    supplied = request.headers.get('Authorization', '')
    if not expected or not secrets.compare_digest(supplied.encode('utf-8'), f'Bearer {expected}'.encode('ascii')):
        abort(401)


@node_api.get('/capabilities')
def capabilities():
    instances = list(db.session.scalars(db.select(AgentInstance)))
    def state(instance):
        try:
            return engine_for(instance.spec['engine']).metrics(instance.spec)['status']
        except EngineError:
            return 'unknown'
    return jsonify({'protocol_version': 1, 'host': host_metrics(), 'qemu': engine_for('qemu').capabilities(),
                    'docker': engine_for('docker').capabilities(),
                    'instances': [{'id': i.id, 'engine': i.spec['engine'], 'status': state(i)} for i in instances],
                    'reserved_ports': [i.spec['ssh_port'] for i in instances if i.spec.get('ssh_port')],
                    'provisioning': db.session.scalar(db.select(db.func.count()).select_from(AgentOperation).where(AgentOperation.status.in_(['queued', 'running', 'uncertain']))),
                    'images': [{'id': i.id, 'enabled': i.enabled, 'verification': i.verification} for i in db.session.scalars(db.select(OSImage))]})


def validate_agent_spec(raw, credentials):
    s = settings()
    ident = valid_uuid(raw.get('id'))
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9-]{1,61}[A-Za-z0-9]', str(raw.get('name', ''))):
        raise EngineError('Invalid guest name.')
    if raw.get('engine') not in ('qemu', 'docker'):
        raise EngineError('Invalid engine.')
    image = db.session.get(OSImage, str(raw.get('os_id', '')))
    if not image or not image.enabled:
        raise EngineError('OS is not enabled on this node.')
    spec = {k: raw.get(k) for k in ('name', 'engine', 'os_id')}
    spec.update(id=ident, owner_id=integer(raw.get('owner_id'), 'Owner ID', 1, 2**31 - 1),
                ram_mb=integer(raw.get('ram_mb'), 'RAM', 512 if raw['engine'] == 'qemu' else 128, s['max_instance_ram_mb']),
                vcpus=integer(raw.get('vcpus'), 'CPU', 1, s['max_instance_vcpus']),
                disk_gb=integer(raw.get('disk_gb'), 'Disk', image.min_disk_gb if raw['engine'] == 'qemu' else 1, s['max_instance_disk_gb']),
                runtime={}, username=None, ssh_port=None, forwards=[],
                allow_unenforced_storage=raw.get('allow_unenforced_storage') is True)
    if spec['engine'] == 'qemu':
        user = str(raw.get('username', ''))
        if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,30}', user) or user in ('root', 'nobody', 'daemon', 'bin', 'sys'):
            raise EngineError('Invalid guest username.')
        spec['username'] = user
        spec['ssh_port'] = integer(raw.get('ssh_port'), 'SSH port', s['ssh_port_min'], s['ssh_port_max'])
        if credentials.get('public_key'):
            credentials['public_key'] = ssh_key(credentials['public_key'])
        elif not re.fullmatch(r'\$6\$(rounds=\d{4,7}\$)?[./a-zA-Z0-9]{1,16}\$[./a-zA-Z0-9]{86}', str(credentials.get('password_hash', ''))):
            raise EngineError('A valid SHA512-crypt guest password hash or public key is required.')
        forwards = raw.get('forwards', [])
        if not isinstance(forwards, list) or len(forwards) > 4:
            raise EngineError('Too many port forwards.')
        spec['forwards'] = [{'host': integer(p.get('host'), 'Host port', s['ssh_port_min'], s['ssh_port_max']),
                             'guest': integer(p.get('guest'), 'Guest port', 1, 65535)} for p in forwards]
    return spec


@node_api.post('/operations')
def operation_create():
    try:
        data = request.get_json() or {}
        ident = valid_uuid(data.get('id'))
        kind = data.get('kind')
        if kind not in ('create', 'start', 'stop', 'force_stop', 'restart', 'delete', 'resize', 'reinstall'):
            raise EngineError('Unsupported node operation.')
        credentials = data.get('credentials', {})
        if kind in ('create', 'reinstall'):
            data['spec'] = validate_agent_spec(data.get('spec', {}), credentials)
            if kind == 'reinstall' and data['spec']['engine'] != 'qemu':
                raise EngineError('In-place reinstall is only supported for QEMU.')
        else:
            valid_uuid(data.get('spec', {}).get('id'))
        digest = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
        existing = db.session.get(AgentOperation, ident)
        if existing:
            if not secrets.compare_digest(existing.digest, digest):
                return jsonify(error='Operation ID already used for different input.'), 409
            return jsonify(id=ident, status=existing.status, result=existing.result, error=existing.error)
        db.session.add(AgentOperation(id=ident, digest=digest, payload=encrypt(data)))
        db.session.commit()
        return jsonify(id=ident, status='queued'), 202
    except (EngineError, TypeError, AttributeError) as exc:
        return jsonify(error=str(exc)), 400


@node_api.get('/operations/<ident>')
def operation_status(ident):
    operation = db.get_or_404(AgentOperation, ident)
    return jsonify(id=ident, status=operation.status, result=operation.result, error=operation.error)


@node_api.post('/operations/<ident>/reconcile')
def operation_reconcile(ident):
    from services.node_worker import reconcile_operation
    try:
        valid_uuid(ident)
        operation = reconcile_operation(ident)
        return jsonify(id=operation.id, status=operation.status, result=operation.result, error=operation.error)
    except EngineError as exc:
        db.session.rollback()
        return jsonify(error=str(exc)), 409


@node_api.get('/instances/<ident>')
def instance_status(ident):
    instance = db.get_or_404(AgentInstance, ident)
    metric = engine_for(instance.spec['engine']).metrics(instance.spec)
    return jsonify(metric | {'id': instance.id, 'allocation': {k: instance.spec[k] for k in ('ram_mb', 'vcpus', 'disk_gb')}})


@node_api.route('/instances/<ident>/console', methods=['GET', 'POST'])
def console(ident):
    instance = db.get_or_404(AgentInstance, ident)
    engine = engine_for(instance.spec['engine'])
    try:
        if request.method == 'POST':
            payload = request.get_json(silent=True) or {}
            if not isinstance(payload, dict):
                raise EngineError('Console requests must be JSON objects.')
            return jsonify(engine.console_input(instance.spec, payload.get('input', '')))
        return jsonify(output=engine.console(instance.spec))
    except EngineError as exc:
        return jsonify(error=str(exc)), 409

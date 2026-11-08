"""Prove an interrupted operation's outcome without replaying guest mutations.

Reconciliation never starts/stops a process, removes storage/networks, or resizes a
disk. A proven resize may synchronize the controller's JSON manifest only.
"""
import json
import hashlib
import re
from docker.errors import NotFound
from docker.utils import parse_bytes
from engines import EngineError
from services.image_manager import ImageManager
from services.security import atomic_json, instance_dir, run

FIELDS = ('id', 'owner_id', 'name', 'engine', 'os_id', 'ram_mb', 'vcpus', 'username', 'ssh_port')


def _manifest(spec, allow_disk=None):
    directory = instance_dir(spec['id'])
    for filename in ('config.json', 'disk.qcow2', 'seed.iso'):
        path = directory / filename
        if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
            raise EngineError(f'QEMU {filename} is missing, empty or unsafe; reservation retained.')
    try:
        saved = json.loads((directory / 'config.json').read_text())
    except (OSError, ValueError) as exc:
        raise EngineError('QEMU manifest is unreadable; reservation retained.') from exc
    if not isinstance(saved, dict) or any(type(saved.get(key)) is not type(spec.get(key)) or saved.get(key) != spec.get(key) for key in FIELDS):
        raise EngineError('QEMU manifest identity or allocations do not match this operation.')
    if type(saved.get('disk_gb')) is not int or saved['disk_gb'] not in (allow_disk or {spec['disk_gb']}):
        raise EngineError('QEMU manifest disk capacity does not match the operation.')
    runtime = saved.get('runtime')
    if not isinstance(runtime, dict) or runtime.get('provisioned') is not True or runtime.get('storage_enforced') is not True:
        raise EngineError('QEMU manifest does not prove completed provisioning.')
    if runtime.get('accel') not in ('tcg', 'kvm') or type(runtime.get('network_restricted')) is not bool:
        raise EngineError('QEMU accelerator/network metadata is incomplete.')
    if runtime.get('forwards', []) != spec.get('forwards', spec.get('runtime', {}).get('forwards', [])):
        raise EngineError('QEMU forwarding configuration does not match the operation.')
    # cloud-localds' default seed is an ISO9660 CIDATA volume, not an arbitrary file.
    with (directory / 'seed.iso').open('rb') as handle:
        handle.seek(16 * 2048)
        descriptor = handle.read(72)
    if descriptor[:7] != b'\x01CD001\x01' or descriptor[40:72].strip().upper() != b'CIDATA':
        raise EngineError('Cloud-init seed is not a valid CIDATA ISO descriptor.')
    return saved


def _disk_capacity(spec, expected):
    disk = instance_dir(spec['id']) / 'disk.qcow2'
    if ImageManager.inspect(disk).get('virtual-size') != expected * 2**30:
        raise EngineError('Actual QCOW2 virtual capacity does not match the requested capacity; no metadata was changed.')
    run(['qemu-img', 'check', '-f', 'qcow2', disk], timeout=180)


def _qemu_create(engine, spec):
    engine._ensure_disk_idle(spec)
    saved = _manifest(spec)
    _disk_capacity(spec, spec['disk_gb'])
    return {'status': 'stopped', 'runtime': saved['runtime'], 'ssh_port': saved['ssh_port']}


def _docker_create(engine, spec):
    with engine._client() as client:
        container = engine._container(client, spec)
        if container is None:
            raise EngineError('No matching container exists; reservation retained.')
        attrs = container.attrs
        config, host = attrs.get('Config', {}), attrs.get('HostConfig', {})
        labels = config.get('Labels') or {}
        if labels.get('skvm.managed') != 'true' or labels.get('skvm.os_id') != spec['os_id']:
            raise EngineError('Container OS/management labels do not prove this provisioning request.')
        memory = spec['ram_mb'] * 2**20
        if host.get('Memory') != memory or host.get('MemorySwap') != memory or host.get('NanoCpus') != spec['vcpus'] * 1_000_000_000:
            raise EngineError('Actual Docker CPU/memory limits differ from the requested allocation.')
        if config.get('User') != '1000:1000' or host.get('Privileged') is not False or 'ALL' not in host.get('CapDrop', []):
            raise EngineError('Container isolation settings do not match the controlled SKVM configuration.')
        if host.get('Binds') or attrs.get('Mounts') or host.get('CapAdd') or any(host.get(key) not in (None, '', 'private') for key in ('PidMode', 'IpcMode', 'UTSMode')):
            raise EngineError('Container host/shared namespaces, mounts or added capabilities are not allowed.')
        if host.get('PidsLimit') != 128 or host.get('Devices') or host.get('DeviceRequests'):
            raise EngineError('Container PID/device isolation differs from the controlled SKVM configuration.')
        if not set(host.get('SecurityOpt') or []).intersection({'no-new-privileges', 'no-new-privileges:true'}):
            raise EngineError('Container no-new-privileges protection is not configured.')
        name = f'skvm-net-{spec["id"]}'
        try:
            network = client.networks.get(name)
        except NotFound as exc:
            raise EngineError('The guest’s isolated Docker network is missing.') from exc
        network_labels = network.attrs.get('Labels') or {}
        if network_labels.get('skvm.instance') != spec['id'] or network_labels.get('skvm.managed') != 'true' or network.attrs.get('Internal') is not True:
            raise EngineError('The guest’s network is not its managed internal bridge.')
        attached = attrs.get('NetworkSettings', {}).get('Networks', {})
        if set(attached) != {name}:
            raise EngineError('Container network attachments differ from the controlled network.')
        size = (host.get('StorageOpt') or {}).get('size')
        enforced = bool(size)
        if enforced and parse_bytes(size) != spec['disk_gb'] * 2**30:
            raise EngineError('The actual Docker storage quota differs from the requested capacity.')
        if not enforced and not spec.get('allow_unenforced_storage'):
            raise EngineError('A missing Docker storage quota was not acknowledged as budget-only.')
        status = container.status
        if status not in ('created', 'exited', 'running', 'paused', 'restarting', 'dead'):
            raise EngineError('Container state cannot be proven; reservation retained.')
        image_id = attrs.get('Image')
        if not isinstance(image_id, str) or not image_id:
            raise EngineError('Container image identity is unavailable.')
        return {'status': 'stopped' if status in ('created', 'exited') else status, 'ssh_port': None,
                'runtime': {'container_id': container.id, 'image_id': image_id, 'image_digest': None,
                            'storage_enforced': enforced, 'uid': 1000, 'network': name}}


def _running_qemu(engine, spec):
    process = engine._process(spec)
    if process is None:
        raise EngineError('The matching QEMU process is not running.')
    command = process.cmdline()
    for flag, expected in (('-m', str(spec['ram_mb'])), ('-smp', str(spec['vcpus']))):
        if flag not in command or command[command.index(flag) + 1] != expected:
            raise EngineError('The running QEMU allocation differs from this instance’s configuration.')
    machine = command[command.index('-machine') + 1] if '-machine' in command else ''
    accel = re.search(r'(?:^|,)accel=(tcg|kvm)(?:,|$)', machine)
    if not accel:
        raise EngineError('The running QEMU accelerator cannot be verified.')
    return spec.get('runtime', {}) | {'accel': accel[1]}


def inspect_power_state(spec, engine):
    """Prove a stable current state, not that an interrupted action succeeded."""
    try:
        metric = engine.metrics(spec)
        state = metric.get('status') if isinstance(metric, dict) else None
        if state not in ('running', 'stopped'):
            raise EngineError('Current running/stopped state cannot be proven. The uncertain request and its context were retained.')
        if spec['engine'] == 'qemu':
            if state == 'running':
                _running_qemu(engine, spec)
            else:
                engine._ensure_disk_idle(spec)
        elif spec['engine'] == 'docker':
            with engine._client() as client:
                container = engine._container(client, spec)
                if container is None:
                    raise EngineError('The owned container is missing; power state is not proven.')
                host = container.attrs.get('HostConfig', {})
                if host.get('Memory') != spec['ram_mb'] * 2**20 or host.get('NanoCpus') != spec['vcpus'] * 10**9:
                    raise EngineError('Actual Docker CPU/memory limits differ from this managed allocation.')
                observed = 'stopped' if container.status in ('created', 'exited') else container.status
                if observed != state:
                    raise EngineError('Container state changed during inspection. Retry after it is stable.')
        else:
            raise EngineError('Unsupported engine for power-state inspection.')
        return state
    except EngineError:
        raise
    except Exception as exc:
        raise EngineError('Current managed instance state cannot be safely inspected; the request remains uncertain.') from exc


def inspect_outcome(kind, spec, payload, engine):
    try:
        if kind in ('network', 'assign'):
            if spec['engine'] != 'qemu':
                raise EngineError('Only stopped managed QEMU guests support this recovery.')
            engine._ensure_disk_idle(spec)
            saved = _manifest(spec | ({'owner_id': payload['owner_id']} if kind == 'assign' else {}))
            if kind == 'network' and saved['runtime']['network_restricted'] is not payload['network_restricted']:
                raise EngineError('The requested network policy is not proven in the VM manifest.')
            return {'status': 'stopped', 'runtime': saved['runtime'], 'owner_id': saved['owner_id']}
        if kind == 'reinstall':
            if spec['engine'] != 'qemu' or not payload.get('credentials', {}).get('control_public_key'):
                raise EngineError('Reinstall recovery needs the original unique management public key and exact stopped guest evidence.')
            if instance_dir(spec['id']).with_name(spec['id'] + '.reinstall-backup').exists():
                raise EngineError('Reinstall backup still exists; preparation/cleanup is not proven complete.')
            value = _qemu_create(engine, payload['spec'])
            expected = hashlib.sha256(payload['credentials']['control_public_key'].encode()).hexdigest()
            if value['runtime'].get('control_key_sha256') != expected:
                raise EngineError('The guest seed does not prove this reinstall’s unique key generation.')
            return value
        if kind == 'create':
            return _qemu_create(engine, spec) if spec['engine'] == 'qemu' else _docker_create(engine, spec)
        if kind == 'resize' and spec['engine'] == 'qemu':
            target = payload['disk_gb']
            if type(target) is not int or target < spec['disk_gb']:
                raise EngineError('Resize recovery cannot lower a configured disk capacity.')
            engine._ensure_disk_idle(spec)
            saved = _manifest(spec, allow_disk={spec['disk_gb'], target})
            _disk_capacity(spec, target)
            if saved['disk_gb'] != target:
                # Only controller metadata changes. Never replay qemu-img resize.
                atomic_json(instance_dir(spec['id']) / 'config.json', saved | {'disk_gb': target})
            return {'disk_gb': target}
        if kind == 'delete':
            if spec['engine'] == 'qemu':
                engine._ensure_disk_idle(spec)
                if instance_dir(spec['id']).exists():
                    raise EngineError('QEMU storage still exists; deletion is not proven.')
            else:
                with engine._client() as client:
                    if engine._container(client, spec) is not None:
                        raise EngineError('The managed container still exists; deletion is not proven.')
                    name = spec.get('runtime', {}).get('network') or f'skvm-net-{spec["id"]}'
                    try:
                        client.networks.get(name)
                    except NotFound:
                        pass
                    else:
                        raise EngineError('The guest network still exists. Inspect/clean it before reconciliation; it was not automatically removed.')
            return {'status': 'deleted'}
        if kind == 'restart':
            raise EngineError('Current running state alone cannot prove an interrupted restart occurred. Use Close interrupted power request to inspect stable state and record the old request as failed/unconfirmed; it is never replayed.')
        if kind in ('start', 'stop', 'force_stop', 'suspend'):
            metric = engine.metrics(spec)
            wanted = 'running' if kind in ('start', 'restart') else 'stopped'
            if metric.get('status') != wanted:
                raise EngineError(f'Actual engine state does not prove {kind} completed; reservation retained.')
            result = {'status': wanted}
            if kind == 'start':
                result.update(already_running=True, inspection_only=True)
            if spec['engine'] == 'qemu':
                if wanted == 'running':
                    result['runtime'] = _running_qemu(engine, spec)
                else:
                    engine._ensure_disk_idle(spec)
            return result
        raise EngineError('This operation cannot be proven from read-only state. Reinstall credentials and metadata-only policy changes require manual inspection.')
    except EngineError:
        raise
    except Exception as exc:
        # Incomplete manifests/API replies must not turn into a fake success or drop reservations.
        raise EngineError(f'Cannot safely inspect the engine outcome ({type(exc).__name__}); reservation retained.') from exc

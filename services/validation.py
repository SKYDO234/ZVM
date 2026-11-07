import re
import uuid
from engines import engine_for, EngineError
from extensions import db
from models import Job, Node, OSImage, VPS
from services.security import integer, settings, ssh_key, validate_password
from services.resource_monitor import host_metrics, require_known_capacity


def user_limits(user):
    s = settings()
    if user.plan:
        return {'max_instances': user.plan.max_instances, 'ram_mb': user.plan.ram_mb,
                'vcpus': user.plan.vcpus, 'disk_gb': user.plan.disk_gb}
    return {'max_instances': s['max_instances_per_user'], 'ram_mb': s['max_ram_mb_per_user'],
            'vcpus': s['max_vcpus_per_user'], 'disk_gb': s['max_disk_gb_per_user']}


def clean_spec(data, user_id):
    s = settings()
    name = str(data.get('name', '')).strip()
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9-]{1,61}[A-Za-z0-9]', name):
        raise EngineError('Instance name must be 3–63 letters, numbers or hyphens, beginning with a letter and ending with a letter or number.')
    engine = data.get('engine')
    if engine not in ('qemu', 'docker'):
        raise EngineError('Select QEMU virtual machine or Docker container.')
    image = db.session.get(OSImage, str(data.get('os_id', '')))
    if not image or not image.enabled:
        raise EngineError('Select an enabled operating system.')
    if image.eol_warning and data.get('accept_eol') not in ('1', True):
        raise EngineError('This OS has a support-lifecycle warning. Explicitly acknowledge it, or choose a supported release.')
    ram = integer(data.get('ram_mb'), 'RAM in MiB', 512 if engine == 'qemu' else 128, s['max_instance_ram_mb'])
    cpus = integer(data.get('vcpus'), 'vCPU count', 1, s['max_instance_vcpus'])
    disk = integer(data.get('disk_gb'), 'Disk in GiB', image.min_disk_gb if engine == 'qemu' else 1, s['max_instance_disk_gb'])
    spec = {'id': str(uuid.uuid4()), 'owner_id': user_id, 'name': name, 'engine': engine, 'os_id': image.id,
            'ram_mb': ram, 'vcpus': cpus, 'disk_gb': disk, 'username': None, 'ssh_port': None,
            'runtime': {}, 'forwards': [], 'allow_unenforced_storage': data.get('allow_unenforced_storage') in ('1', True)}
    credentials = {}
    if engine == 'qemu':
        mode = data.get('network_mode', 'restricted' if s['restrict_guest_network'] else 'internet')
        if mode not in ('restricted', 'internet'):
            raise EngineError('Choose restricted networking or outbound internet.')
        spec['network_restricted'] = mode == 'restricted'
        username = str(data.get('username', '')).strip()
        if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,30}', username) or username in ('root', 'daemon', 'nobody', 'bin', 'sys', 'sync', 'shutdown', 'halt'):
            raise EngineError('Use a non-system Linux username (1–31 lowercase letters, digits, underscores or hyphens). Root login is disabled.')
        spec['username'] = username
        if data.get('auth_method') == 'key':
            credentials['public_key'] = ssh_key(str(data.get('public_key', '')))
        elif data.get('auth_method') == 'password':
            password = validate_password(str(data.get('guest_password', '')))
            # SHA512-crypt, accepted by cloud-init/shadow; never store the plaintext password.
            from passlib.hash import sha512_crypt
            credentials['password_hash'] = sha512_crypt.using(rounds=100000).hash(password)
        else:
            raise EngineError('Select SSH public key or password authentication.')
        port = data.get('ssh_port')
        if port:
            spec['ssh_port'] = integer(port, 'SSH port', s['ssh_port_min'], s['ssh_port_max'])
        extra = str(data.get('forwards', '')).strip()
        if extra:
            if len(extra.split(',')) > 4:
                raise EngineError('At most four additional TCP forwards are allowed.')
            for pair in extra.split(','):
                parts = pair.strip().split(':')
                if len(parts) != 2:
                    raise EngineError('Use host:guest port pairs, separated by commas.')
                spec['forwards'].append({'host': integer(parts[0], 'Host port', s['ssh_port_min'], s['ssh_port_max']),
                                         'guest': integer(parts[1], 'Guest port', 1, 65535)})
            ports = [p['host'] for p in spec['forwards']] + ([spec['ssh_port']] if spec['ssh_port'] else [])
            if len(set(ports)) != len(ports):
                raise EngineError('Forwarded host ports must be unique.')
    return spec, credentials


def quota_check(user, spec, exclude_job=None, resize_of=None):
    lim = user_limits(user)
    instances = list(db.session.scalars(db.select(VPS).where(VPS.owner_id == user.id)))
    jobs = list(db.session.scalars(db.select(Job).where(
        Job.status.in_(['queued', 'running', 'uncertain']),
        ((Job.kind.in_(['create', 'assign'])) & (Job.owner_id == user.id)) |
        ((Job.kind == 'resize') & Job.instance_id.in_(db.select(VPS.id).where(VPS.owner_id == user.id))))))
    jobs = [j for j in jobs if j.id != exclude_job]
    if not resize_of and len(instances) + sum(j.kind in ('create', 'assign') for j in jobs) >= lim['max_instances']:
        raise EngineError(f'Instance quota reached ({lim["max_instances"]}). Pending or uncertain jobs reserve capacity too.')
    for key, title in [('ram_mb', 'RAM'), ('vcpus', 'vCPU'), ('disk_gb', 'Disk')]:
        requested = spec[key] if not resize_of else (spec[key] - getattr(resize_of, key))
        total = sum(getattr(v, key) for v in instances) + sum(getattr(j, key) for j in jobs) + requested
        if total > lim[key]:
            raise EngineError(f'{title} allocation exceeds your plan limit ({lim[key]}).')
    if not resize_of and db.session.scalar(db.select(VPS.id).where(VPS.owner_id == user.id, VPS.name == spec['name'])):
        raise EngineError('You already have an instance with this name.')


def capacity_check(spec, node=None, exclude_job=None, resize_of=None, require_available_ram=True):
    s = settings()
    if node:
        caps = engine_for(spec['engine'], node).capabilities()
        if not caps.get(spec['engine'], {}).get('available'):
            raise EngineError(caps.get(spec['engine'], {}).get('reason', 'Selected external engine is unavailable.'))
        # The node agent performs its own authoritative, serialized capacity check too.
        host = caps['host']
    else:
        caps = engine_for(spec['engine']).capabilities()
        if not caps['available']:
            raise EngineError(caps['reason'])
        if spec['engine'] == 'docker' and not caps.get('storage_limits') and not spec.get('allow_unenforced_storage', spec.get('runtime', {}).get('storage_enforced') is False):
            raise EngineError('Docker disk size cannot be enforced on this host. Acknowledge a budget-only allocation, or use QEMU.')
        host = host_metrics()
    require_known_capacity(host)
    node_id = node.id if node else None
    existing = list(db.session.scalars(db.select(VPS).where(VPS.node_id == node_id)))
    pending = list(db.session.scalars(db.select(Job).where(Job.node_id == node_id, Job.kind.in_(['create', 'resize']), Job.status.in_(['queued', 'running', 'uncertain']))))
    pending = [j for j in pending if j.id != exclude_job]
    if not resize_of and len(existing) + sum(j.kind == 'create' for j in pending) >= s['max_instances_per_node']:
        raise EngineError('This provisioning node has reached the configured instance count limit.')
    ram_used = sum(v.ram_mb for v in existing) + sum(j.ram_mb for j in pending)
    cpu_used = sum(v.vcpus for v in existing) + sum(j.vcpus for j in pending)
    disk_used = sum(v.disk_gb for v in existing) + sum(j.disk_gb for j in pending)
    if resize_of:
        ram_used -= resize_of.ram_mb
        cpu_used -= resize_of.vcpus
        disk_used -= resize_of.disk_gb
    if ram_used + spec['ram_mb'] > host['ram_total_mb'] * s['host_memory_fraction']:
        raise EngineError('Insufficient node RAM budget. Configured allocations are conservatively reserved, even for stopped guests.')
    if require_available_ram and spec['ram_mb'] > max(0, host['ram_available_mb'] - 256):
        raise EngineError('Not enough currently available host RAM (including a 256 MiB safety margin).')
    if cpu_used + spec['vcpus'] > max(0, host['cpu_capacity']):
        raise EngineError('Configured vCPU allocations exceed this node’s effective CPU capacity. CPU overcommit is disabled.')
    # Conservative: entire virtual capacity + other reserved capacities must fit current free space.
    # This deliberately double-counts already materialized bytes rather than silently overcommitting storage.
    if disk_used + spec['disk_gb'] + s['host_storage_reserve_gb'] > host['disk_free_gb']:
        raise EngineError('Insufficient host storage for the full reserved disk capacity plus the safety reserve. Choose a smaller disk or another node.')


def select_node(raw):
    if not raw or str(raw) == 'local':
        return None
    ident = integer(raw, 'Node', 1, 2**31 - 1)
    node = db.session.get(Node, ident)
    if not node or not node.enabled:
        raise EngineError('Selected node is unavailable or disabled.')
    return node

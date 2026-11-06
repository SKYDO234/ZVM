"""Validate versioned node replies before they influence allocations or job outcomes."""
import math
import re
from engines import EngineError, UncertainError
from services.security import valid_uuid


def _number(value):
    try:
        return type(value) in (int, float) and math.isfinite(value) and value >= 0
    except OverflowError:
        return False


def capabilities(data):
    if not isinstance(data, dict) or type(data.get('protocol_version')) is not int or data['protocol_version'] != 1:
        raise EngineError('Unsupported external-agent protocol. Upgrade the panel and node together.')
    host = data.get('host')
    if not isinstance(host, dict) or any(not _number(host.get(key)) for key in ('ram_total_mb', 'ram_available_mb', 'cpu_capacity', 'disk_free_gb')):
        raise EngineError('External agent returned invalid host capacity; no capacity was assumed.')
    if host['ram_available_mb'] > host['ram_total_mb'] or type(host.get('capacity_known')) is not bool:
        raise EngineError('External agent cannot prove its effective host capacity.')
    for engine in ('qemu', 'docker'):
        cap = data.get(engine)
        if not isinstance(cap, dict) or type(cap.get('available')) is not bool or not isinstance(cap.get('reason'), str):
            raise EngineError('External agent returned invalid engine capabilities.')
    if not isinstance(data.get('instances'), list) or not isinstance(data.get('reserved_ports'), list):
        raise EngineError('External agent returned invalid instance inventory.')
    for instance in data['instances']:
        if not isinstance(instance, dict) or instance.get('engine') not in ('qemu', 'docker') or not _status(instance.get('status')):
            raise EngineError('External agent returned invalid instance inventory.')
        valid_uuid(instance.get('id'))
    if any(type(port) is not int or not 1 <= port <= 65535 for port in data['reserved_ports']):
        raise EngineError('External agent returned invalid port reservations.')
    return data


def _status(value):
    return isinstance(value, str) and re.fullmatch(r'[a-z][a-z_-]{0,39}', value) is not None


def metric(data, spec):
    if not isinstance(data, dict) or data.get('id') != spec['id'] or not _status(data.get('status')):
        raise EngineError('External instance identity/state could not be verified.')
    allocation = data.get('allocation')
    if not isinstance(allocation, dict) or any(type(allocation.get(key)) is not int or allocation[key] != spec[key] for key in ('ram_mb', 'vcpus', 'disk_gb')):
        raise EngineError('External allocations differ from the panel record. Inspect/reconcile the node before further mutations.')
    usage = data.get('usage')
    if not isinstance(usage, dict) or any(value is not None and not _number(value) for key, value in usage.items() if key in ('disk_actual_bytes', 'process_rss_mb', 'process_cpu_percent', 'pid')):
        raise EngineError('External resource metrics are malformed; no reading was invented.')
    # Never let node JSON overwrite panel-owned identity, owner, node or allocation fields.
    return {key: data[key] for key in ('status', 'usage', 'accel', 'storage_enforced') if key in data}


def operation(data, ident):
    if not isinstance(data, dict) or data.get('id') != ident or data.get('status') not in ('queued', 'running', 'uncertain', 'completed', 'failed'):
        raise UncertainError('External operation response is malformed or refers to a different ID. Inspect actual state; reservations remain held.')
    if data['status'] == 'completed' and not isinstance(data.get('result'), dict):
        raise UncertainError('External completion has no verified resource result. Reservations remain held.')
    return data

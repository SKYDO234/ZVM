"""Host capacity is deliberately separate from each guest's configured allocations."""
import os
import math
import time
import psutil
from flask import current_app
from engines import engine_for, EngineError
from services.cgroups import inspect as cgroup_snapshot


_cpu_samples = {}


def host_metrics():
    mem, group = psutil.virtual_memory(), cgroup_snapshot()
    total, available = mem.total, mem.available
    if group.memory_limit is not None:
        total = min(total, group.memory_limit)
    if group.memory_available is not None:
        available = min(available, group.memory_available)
    available = min(available, total)
    used = group.memory_usage if group.memory_usage is not None else mem.total - mem.available
    cpus = len(os.sched_getaffinity(0)) if hasattr(os, 'sched_getaffinity') else (psutil.cpu_count() or 1)
    if group.cpu_limit is not None:
        cpus = min(cpus, group.cpu_limit)
    # Never round a fractional quota up into a CPU that does not exist.
    cpus = math.floor(cpus * 100) / 100
    if group.cpu_counter is not None:
        before, started = group.read_cpu_seconds(), time.monotonic()
        time.sleep(0.05)
        after, elapsed = group.read_cpu_seconds(), time.monotonic() - started
        cpu_percent = ((after - before) / elapsed / cpus * 100
                       if before is not None and after is not None and after >= before and elapsed > 0 and cpus > 0 else None)
    else:
        cpu_percent = psutil.cpu_percent(interval=0.05)
    disk = psutil.disk_usage(current_app.config['DATA_DIR'])
    proc = psutil.Process()
    return {
        'kind': 'codespace' if os.getenv('CODESPACES') else 'local',
        'capacity_known': not group.errors,
        'capacity_reason': ' '.join(dict.fromkeys(group.errors))[:2000],
        'ram_total_mb': total // 2**20, 'ram_available_mb': available // 2**20,
        'ram_used_mb': used // 2**20,
        'ram_percent': round(used / total * 100, 1) if total else 100.0,
        'memory_scope': 'cgroup' if group.memory_usage is not None else 'host',
        'cpu_capacity': cpus, 'cpu_percent': round(cpu_percent, 2) if cpu_percent is not None else None,
        'cpu_scope': 'cgroup' if group.cpu_counter is not None else 'host',
        'disk_total_gb': math.floor(disk.total / 2**30 * 100) / 100,
        'disk_free_gb': math.floor(disk.free / 2**30 * 100) / 100,
        'panel_rss_mb': round(proc.memory_info().rss / 2**20, 1),
        'panel_cpu_percent': process_metrics(proc)['process_cpu_percent'], 'process_count': len(psutil.pids()),
        'sampled_at': time.time(),
    }


def require_known_capacity(host):
    if not host.get('capacity_known', True):
        raise EngineError('Effective host capacity cannot be verified. ' + host.get('capacity_reason', 'Inspect cgroup permissions or use another node.'))


def process_metrics(process):
    if process is None:
        return {'process_rss_mb': 0, 'process_cpu_percent': 0, 'pid': None}
    try:
        key = (process.pid, process.create_time())
        now = time.monotonic()
        cpu_time = sum(process.cpu_times()[:2])
        old = _cpu_samples.get(key)
        cpu = max(0, (cpu_time - old[1]) / (now - old[0]) * 100) if old and now > old[0] else None
        _cpu_samples[key] = (now, cpu_time)
        if len(_cpu_samples) > 500:
            for k in list(_cpu_samples)[:250]:
                _cpu_samples.pop(k, None)
        return {'pid': process.pid, 'process_rss_mb': round(process.memory_info().rss / 2**20, 2),
                'process_cpu_percent': round(cpu, 2) if cpu is not None else None}
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return {'pid': None, 'process_rss_mb': None, 'process_cpu_percent': None}


def instance_metrics(vps):
    base = {'id': vps.id, 'name': vps.name, 'engine': vps.engine,
            'allocation': {'ram_mb': vps.ram_mb, 'vcpus': vps.vcpus, 'disk_gb': vps.disk_gb},
            'suspended': vps.suspended, 'node': vps.node.name if vps.node else 'Local workspace'}
    try:
        result = engine_for(vps.engine, vps.node).metrics(vps.spec())
        return base | result
    except EngineError as exc:
        return base | {'status': 'unknown', 'error': str(exc), 'usage': {}}


def totals(instances, metrics):
    return {'count': len(instances), 'running': sum(m['status'] == 'running' for m in metrics),
            'stopped': sum(m['status'] == 'stopped' for m in metrics),
            'unknown': sum(m['status'] not in ('running', 'stopped') for m in metrics),
            'ram_mb': sum(v.ram_mb for v in instances), 'vcpus': sum(v.vcpus for v in instances),
            'disk_gb': sum(v.disk_gb for v in instances)}

"""Read effective Linux cgroup v1/v2 budgets, including limiting ancestors.

Membership paths are mapped through mountinfo rather than assuming the cgroup
filesystem root is this process's leaf. No file outside a discovered mount is read.
"""
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
import re


@dataclass
class Snapshot:
    memory_limit: int | None = None
    memory_available: int | None = None
    memory_usage: int | None = None
    cpu_limit: float | None = None
    cpu_counter: Path | None = None
    cpu_counter_unit: str | None = None
    errors: list[str] = field(default_factory=list)

    def read_cpu_seconds(self):
        if self.cpu_counter is None:
            return None
        try:
            text = self.cpu_counter.read_text()
            if self.cpu_counter_unit == 'ns':
                return int(text.strip()) / 1e9
            values = dict(row.split() for row in text.splitlines())
            return int(values['usage_usec']) / 1e6
        except (OSError, ValueError, KeyError):
            return None


def _read(path, snapshot):
    try:
        return path.read_text().strip()
    except FileNotFoundError:
        return None  # Root cgroups and non-delegated controllers may omit files.
    except OSError as exc:
        snapshot.errors.append(f'Cannot read cgroup budget at {path}: {type(exc).__name__}.')
        return None


def _number(text, path, snapshot, unlimited=False):
    if text is None or (unlimited and text in ('max', '-1')):
        return None
    try:
        number = int(text)
        if number < 0:
            raise ValueError
        return number
    except ValueError:
        snapshot.errors.append(f'Invalid cgroup budget in {path}.')
        return None


def cpu_set_count(text):
    """Count disjoint CPU ranges without expanding a possibly huge kernel range."""
    ranges = []
    for part in text.split(','):
        if not re.fullmatch(r'\d+(-\d+)?', part):
            raise ValueError('Invalid CPU set')
        bounds = [int(n) for n in part.split('-')]
        low, high = bounds[0], bounds[-1]
        if high < low:
            raise ValueError('Invalid CPU range')
        ranges.append((low, high))
    total, end = 0, -1
    for low, high in sorted(ranges):
        total += max(0, high - max(low, end + 1) + 1)
        end = max(end, high)
    return total


def _unescape(value):
    return re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), value)


def _locations(memberships, mounts, snapshot):
    members = {}
    for row in memberships.splitlines():
        try:
            ident, controllers, path = row.split(':', 2)
            for controller in (['v2'] if ident == '0' and not controllers else controllers.split(',')):
                members[controller] = PurePosixPath(path)
        except ValueError:
            snapshot.errors.append('Cannot parse this process’s cgroup membership.')
    found = set()
    for row in mounts.splitlines():
        try:
            before, after = row.split(' - ', 1)
            fields, filesystem = before.split(), after.split()
            if filesystem[0] not in ('cgroup', 'cgroup2'):
                continue
            root = PurePosixPath(_unescape(fields[3]))
            mount = Path(_unescape(fields[4]))
            controllers = ['v2'] if filesystem[0] == 'cgroup2' else filesystem[2].split(',')
            for controller in controllers:
                if controller not in members or controller not in ('v2', 'memory', 'cpu', 'cpuacct', 'cpuset'):
                    continue
                member = members[controller]
                if '..' in member.parts or not member.is_absolute():
                    snapshot.errors.append('Unsafe or unmappable cgroup membership path.')
                    continue
                try:
                    relative = member.relative_to(root)
                except ValueError:
                    # A cgroup namespace can expose its mount root as /.
                    if member != PurePosixPath('/'):
                        continue
                    relative = PurePosixPath('.')
                leaf = mount / str(relative)
                if not leaf.is_relative_to(mount):
                    continue
                if not leaf.is_dir():
                    snapshot.errors.append(f'Cgroup membership directory is unavailable at {leaf}.')
                    continue
                found.add(controller)
                yield controller, leaf, mount
        except (ValueError, IndexError):
            snapshot.errors.append('Cannot parse this process’s cgroup mounts.')
    missing = set(members).intersection({'v2', 'memory', 'cpu', 'cpuacct', 'cpuset'}) - found
    if missing:
        snapshot.errors.append('Cannot locate mounted cgroup controllers: ' + ', '.join(sorted(missing)) + '.')


def _minimum(old, value):
    return value if old is None else min(old, value)


def inspect(cgroup_file=Path('/proc/self/cgroup'), mountinfo_file=Path('/proc/self/mountinfo')):
    result = Snapshot()
    memberships = _read(Path(cgroup_file), result)
    mounts = _read(Path(mountinfo_file), result)
    if memberships is None or mounts is None:
        result.errors.append('Linux cgroup topology is unavailable; effective capacity cannot be verified.')
        return result
    for controller, leaf, root in _locations(memberships, mounts, result):
        path = leaf
        while True:
            if controller in ('v2', 'memory'):
                limit_name = 'memory.max' if controller == 'v2' else 'memory.limit_in_bytes'
                usage_name = 'memory.current' if controller == 'v2' else 'memory.usage_in_bytes'
                limit = _number(_read(path / limit_name, result), path / limit_name, result, unlimited=True)
                usage = _number(_read(path / usage_name, result), path / usage_name, result)
                if path == leaf and usage is not None:
                    result.memory_usage = usage
                if limit is not None:
                    result.memory_limit = _minimum(result.memory_limit, limit)
                    if usage is None:
                        result.errors.append(f'Cannot measure usage against the memory budget at {path}.')
                    else:
                        result.memory_available = _minimum(result.memory_available, max(0, limit - usage))
            if controller in ('v2', 'cpu'):
                if controller == 'v2':
                    raw = _read(path / 'cpu.max', result)
                    pair = raw.split() if raw else None
                else:
                    quota = _read(path / 'cpu.cfs_quota_us', result)
                    period = _read(path / 'cpu.cfs_period_us', result)
                    pair = [quota, period] if quota is not None else None
                if pair:
                    if len(pair) != 2 or pair[1] is None:
                        result.errors.append(f'Invalid CPU quota at {path}.')
                    else:
                        quota = _number(pair[0], path, result, unlimited=True)
                        period = _number(pair[1], path, result)
                        if not period:
                            result.errors.append(f'Invalid CPU quota period at {path}.')
                        elif quota is not None:
                            result.cpu_limit = _minimum(result.cpu_limit, quota / period)
            if controller in ('v2', 'cpuset'):
                raw = _read(path / ('cpuset.cpus.effective' if controller == 'v2' else 'cpuset.cpus'), result)
                if raw:
                    try:
                        result.cpu_limit = _minimum(result.cpu_limit, cpu_set_count(raw))
                    except ValueError:
                        result.errors.append(f'Invalid effective CPU set at {path}.')
            if path == root:
                break
            path = path.parent
        counter = leaf / ('cpu.stat' if controller == 'v2' else 'cpuacct.usage')
        if controller in ('v2', 'cpuacct') and counter.is_file():
            result.cpu_counter, result.cpu_counter_unit = counter, 'us' if controller == 'v2' else 'ns'
    return result

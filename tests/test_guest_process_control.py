"""Execute the fixed helper with a wholly synthetic /proc/kernel; no host OS calls."""
import builtins
import io
from types import SimpleNamespace
import uuid

import pytest

from services.guest_process_control import SSHX_PROCESS_CONTROL

VM, OP = str(uuid.uuid4()), str(uuid.uuid4())


def run_helper(action='stop', *, reuse=None, supported=True, blocked=False, orphan=False, denied=False):
    tasks = {41: {'exe': '/usr/bin/timeout', 'vm': VM, 'alive': not orphan},
             42: {'exe': '/usr/local/bin/sshx', 'vm': VM, 'alive': True},
             43: {'exe': '/usr/bin/sleep', 'vm': VM, 'alive': True},
             44: {'exe': '/usr/local/bin/sshx', 'vm': str(uuid.uuid4()), 'alive': True}}
    bindings, signals, closed = {}, [], []
    def pidfd_open(pid):
        if denied:
            raise PermissionError('synthetic seccomp rejection')
        task = tasks[pid]
        if not task['alive']:
            raise ProcessLookupError()
        fd = 1000 + pid
        bindings[fd] = task
        if reuse == 'before-proof' and pid == 41:
            task['alive'] = False
            tasks[pid] = {'exe': '/usr/bin/sleep', 'vm': VM, 'alive': True}
        return fd
    def file(path, mode='r'):
        if '/fdinfo/' in path:
            fd = int(path.rsplit('/', 1)[1])
            return io.StringIO('Pid:\t' + (str(fd - 1000) if bindings[fd]['alive'] else '-1') + '\n')
        pid = int(path.split('/')[2])
        task = tasks[pid]
        return io.BytesIO(b'SKVM_SSHX_INSTANCE=' + task['vm'].encode() + b'\x00SKVM_SSHX_OPERATION=' + OP.encode() + b'\x00')
    def send(fd, sig):
        assert sig == 2
        task = bindings[fd]
        if reuse == 'after-proof' and fd == 1041:
            task['alive'] = False
            tasks[41] = {'exe': '/usr/bin/sleep', 'vm': VM, 'alive': True}
            raise ProcessLookupError()
        if not task['alive']:
            raise ProcessLookupError()
        signals.append(fd)
        if not blocked:
            task['alive'] = False
    tick = iter([0, 11] if blocked else [0, 0, 1, 2])
    fake_os = SimpleNamespace(listdir=lambda _: [str(pid) for pid in tasks],
                              stat=lambda _: SimpleNamespace(st_uid=1000), geteuid=lambda: 1000,
                              readlink=lambda path: tasks[int(path.split('/')[2])]['exe'], close=closed.append)
    if supported:
        fake_os.pidfd_open = pidfd_open
    def ready(inputs, *_):
        return [fd for fd in inputs if not bindings[fd]['alive']], [], []
    def exit(code):
        raise SystemExit(code)
    modules = {'os': fake_os, 'signal': SimpleNamespace(SIGINT=2, pidfd_send_signal=send),
               'select': SimpleNamespace(select=ready), 'uuid': uuid,
               'time': SimpleNamespace(monotonic=lambda: next(tick)),
               'sys': SimpleNamespace(argv=['fixed-helper', action, VM, '/usr/bin/timeout', '/usr/local/bin/sshx'], exit=exit)}
    safe_builtins = dict(vars(builtins), __import__=lambda name, *a, **kw: modules[name], open=file)
    with pytest.raises(SystemExit) as stopped:
        exec(compile(SSHX_PROCESS_CONTROL, '<fixed-guest-helper>', 'exec'), {'__builtins__': safe_builtins})
    return stopped.value.code, signals, tasks, closed


@pytest.mark.parametrize('reuse', [None, 'before-proof', 'after-proof'])
def test_pidfd_verification_never_signals_reused_or_unrelated_pid(reuse):
    code, signals, tasks, closed = run_helper(reuse=reuse)
    assert code == 0
    assert 1043 not in signals and 1044 not in signals
    if reuse:
        assert 1041 not in signals
        assert tasks[41]['alive']
    else:
        assert 1041 in signals
    assert 1042 in signals and closed


def test_tagged_orphan_sshx_is_stopped_even_without_timeout():
    code, signals, tasks, _ = run_helper(orphan=True)
    assert code == 0 and signals == [1042]
    assert not tasks[42]['alive'] and tasks[43]['alive'] and tasks[44]['alive']


def test_inspection_does_not_send_any_signal():
    code, signals, _, _ = run_helper(action='check')
    assert code == 1 and signals == []


def test_no_unsafe_fallback_when_kernel_or_python_lacks_pidfds():
    code, signals, _, _ = run_helper(supported=False)
    assert code == 2 and signals == []


def test_stop_timeout_is_not_reported_as_revoked():
    code, _, tasks, _ = run_helper(blocked=True)
    assert code == 1 and tasks[42]['alive']


def test_pidfd_permission_rejection_is_not_mistaken_for_no_clients():
    code, signals, _, _ = run_helper(denied=True)
    assert code == 2 and signals == []


@pytest.mark.parametrize('mode', ['generate', 'stop', 'inspect', 'inspect_stop'])
def test_fixed_guest_script_is_valid_posix_shell_without_executing_it(mode):
    import subprocess
    from services.sshx import guest_script
    script = guest_script({'id': VM}, mode, OP, 3600)
    assert 'kill -INT "$pid"' not in script
    assert 'pidfd_send_signal' in script and 'control_clients check' in script
    parsed = subprocess.run(['sh', '-n'], input=script, text=True, capture_output=True, timeout=5)
    assert parsed.returncode == 0, parsed.stderr

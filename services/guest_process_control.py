"""Fixed Python delivered INSIDE the VM; never evaluated by the control plane.

pidfds pin process identity before /proc verification and signaling, avoiding a
PID-reuse window. Tagged orphan sshx clients count even if timeout's PID vanished.
"""
SSHX_PROCESS_CONTROL = r'''import os
import select
import signal
import sys
import time
import uuid

if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
    sys.exit(2)
action, vm, timeout_path, sshx_path = sys.argv[1:]
if action not in ('stop', 'check') or str(uuid.UUID(vm)) != vm:
    sys.exit(1)

def clients():
    handles = []
    try:
        for entry in os.listdir('/proc'):
            if not entry.isdecimal():
                continue
            pid, fd = int(entry), None
            if pid <= 1:
                continue
            try:
                directory = '/proc/' + entry
                if os.stat(directory).st_uid != os.geteuid():
                    continue
                with open(directory + '/environ', 'rb') as stream:
                    env = dict(item.split(b'=', 1) for item in stream.read(65536).split(b'\x00') if b'=' in item)
                if env.get(b'SKVM_SSHX_INSTANCE') != vm.encode():
                    continue
                executable = os.readlink(directory + '/exe')
                # Replaced/deleted binaries retain the expected basename in /proc.
                if executable != timeout_path and executable != sshx_path and executable.removesuffix(' (deleted)').rsplit('/', 1)[-1] != 'sshx':
                    continue
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
            try:
                # Only open candidate fds. EPERM/seccomp here is NOT absence.
                fd = os.pidfd_open(pid)
                with open(directory + '/environ', 'rb') as stream:
                    current_env = dict(item.split(b'=', 1) for item in stream.read(65536).split(b'\x00') if b'=' in item)
                if current_env != env or os.readlink(directory + '/exe') != executable:
                    continue
                operation = env.get(b'SKVM_SSHX_OPERATION', b'').decode('ascii')
                if str(uuid.UUID(operation)) != operation:
                    raise ValueError('unknown tagged operation')
                with open('/proc/self/fdinfo/' + str(fd)) as stream:
                    identity = dict(line.rstrip().split(':', 1) for line in stream if ':' in line)
                if identity.get('Pid', '').strip() != entry:
                    continue
                if select.select([fd], [], [], 0)[0]:
                    continue
                handles.append(fd)
                fd = None
            except (FileNotFoundError, ProcessLookupError):
                continue
            finally:
                if fd is not None:
                    os.close(fd)
        return handles
    except BaseException:
        for fd in handles:
            os.close(fd)
        raise

handles = []
try:
    handles = clients()
    if action == 'stop':
        for fd in handles:
            try:
                signal.pidfd_send_signal(fd, signal.SIGINT)
            except ProcessLookupError:
                pass
        pending, deadline = set(handles), time.monotonic() + 10
        while pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                sys.exit(1)
            finished, _, _ = select.select(list(pending), [], [], remaining)
            pending.difference_update(finished)
        for fd in handles:
            os.close(fd)
        handles = []
        handles = clients()
    sys.exit(1 if handles else 0)
except OSError:
    # Unsupported kernels and inaccessible process evidence never use a PID kill fallback.
    sys.exit(2)
except Exception:
    sys.exit(1)
finally:
    for fd in handles:
        os.close(fd)
'''

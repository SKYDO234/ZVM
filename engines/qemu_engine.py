"""Audited Python replacement for n.txt: independent disks, TCG, cloud-init, exact PIDs."""
import json
import hashlib
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path
import psutil
import yaml
from flask import current_app
from engines import EngineError, UncertainError
from extensions import db
from models import OSImage
from services.security import atomic_json, instance_dir, locked, run, settings
from services.guest_bootstrap import SSHX_DEPENDENCIES


class QemuEngine:
    @staticmethod
    def _probe(accel):
        # A real, paused, diskless machine. Merely finding /dev/kvm is not enough.
        command = ['qemu-system-x86_64', '-machine', f'pc,accel={accel}', '-cpu', 'host' if accel == 'kvm' else 'max',
                   '-nodefaults', '-display', 'none', '-monitor', 'none', '-serial', 'none', '-m', '64', '-S']
        try:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.PIPE, start_new_session=True)
            try:
                _, stderr = process.communicate(timeout=0.6)
                return False, stderr.decode(errors='replace')[-600:]
            except subprocess.TimeoutExpired:
                process.terminate()
                process.communicate(timeout=3)
                return True, 'Paused-machine accelerator probe passed.'
        except (OSError, subprocess.TimeoutExpired) as exc:
            if 'process' in locals() and process.poll() is None:
                process.kill()
                process.communicate()
            return False, str(exc)

    def capabilities(self):
        enabled = current_app.config['ENABLE_QEMU'] and settings()['qemu_enabled']
        missing = [v for v in ('qemu-system-x86_64', 'qemu-img', 'cloud-localds') if not shutil.which(v)]
        result = {'available': False, 'missing': missing, 'accel': 'tcg', 'kvm': False,
                  'name': 'QEMU virtual machines', 'reason': '', 'warning': 'TCG is software emulation: boot and CPU-heavy workloads can be slow. Allocations are virtual, not dedicated hardware.'}
        if not enabled:
            result['reason'] = 'QEMU is disabled by the operator.'
        elif current_app.config['TEST_MODE']:
            result['reason'] = 'Test mode: real provisioning is deliberately disabled.'
        elif missing:
            result['reason'] = 'Missing userspace dependencies: ' + ', '.join(missing) + '. Run scripts/install-codespaces.sh or connect an external node.'
        else:
            ok, reason = self._probe('tcg')
            result['available'], result['reason'] = ok, reason
            if current_app.config['USE_KVM'] and os.access('/dev/kvm', os.R_OK | os.W_OK):
                kvm_ok, kvm_reason = self._probe('kvm')
                result['kvm'] = kvm_ok
                if kvm_ok:
                    result.update(available=True, accel='kvm', reason=kvm_reason)
        return result

    def _process(self, spec):
        directory = instance_dir(spec['id'])
        runtime = directory / 'process.json'
        def matches(process):
            command = process.cmdline()
            if process.status() == psutil.STATUS_ZOMBIE or '-uuid' not in command:
                return False
            if command[command.index('-uuid') + 1] != spec['id']:
                return False
            if Path(process.exe()).name != 'qemu-system-x86_64':
                return False
            disk_arg = f'file={directory / "disk.qcow2"},'
            return any(arg.startswith(disk_arg) for arg in command)
        if runtime.exists():
            try:
                meta = json.loads(runtime.read_text())
                process = psutil.Process(meta['pid'])
                if abs(process.create_time() - meta['created']) <= 0.01 and matches(process):
                    return process
            except (OSError, ValueError, KeyError, IndexError, psutil.NoSuchProcess):
                pass
            except psutil.AccessDenied as exc:
                raise EngineError('Cannot verify QEMU process identity. Refusing an unsafe operation.') from exc
        # Recover from lost process metadata without broad pgrep/pkill or name substring matching.
        found = []
        for process in psutil.process_iter(['name', 'cmdline']):
            try:
                if '-uuid' in (process.info.get('cmdline') or []) and matches(process):
                    found.append(process)
            except (psutil.NoSuchProcess, IndexError):
                continue
            except psutil.AccessDenied:
                if str(directory / 'disk.qcow2') in str(process.info.get('cmdline')):
                    raise EngineError('A possible guest process cannot be verified; refusing to modify its disk.')
        if len(found) > 1:
            raise EngineError('Multiple exact VM identities were found. Manual inspection is required; no disk was modified.')
        if found:
            atomic_json(runtime, {'pid': found[0].pid, 'created': found[0].create_time()})
            return found[0]
        return None

    def _qmp(self, spec, command):
        if command not in ('query-status', 'system_powerdown', 'quit', 'cont'):
            raise EngineError('QMP command is not allowed.')
        path = instance_dir(spec['id']) / 'qmp.sock'
        try:
            with socket.socket(socket.AF_UNIX) as sock:
                sock.settimeout(4)
                sock.connect(str(path))
                with sock.makefile('rwb', buffering=0) as conn:
                    json.loads(conn.readline())
                    conn.write(b'{"execute":"qmp_capabilities","id":"hello"}\n')
                    self._read_qmp(conn, 'hello')
                    conn.write(json.dumps({'execute': command, 'id': 'operation'}).encode() + b'\n')
                    return self._read_qmp(conn, 'operation')
        except (OSError, ValueError) as exc:
            raise EngineError(f'QEMU monitor unavailable: {exc}') from exc

    @staticmethod
    def _read_qmp(conn, ident):
        for _ in range(100):
            line = conn.readline(65536)
            if not line:
                raise EngineError('QEMU monitor disconnected.')
            message = json.loads(line)
            if message.get('id') == ident:
                if 'error' in message:
                    raise EngineError(message['error'].get('desc', 'QMP operation failed.'))
                return message.get('return', {})
        raise EngineError('QEMU monitor response limit exceeded.')

    def create(self, spec, credentials, operation_id=None):
        capability = self.capabilities()
        if not capability['available']:
            raise EngineError(capability['reason'])
        directory = instance_dir(spec['id'])
        with locked(f'vm-{spec["id"]}'):
            if directory.exists():
                raise EngineError('Instance storage already exists. Refusing to overwrite a disk; inspect the earlier job.')
            image = db.session.get(OSImage, spec['os_id'])
            if not image or not image.enabled:
                raise EngineError('Selected cloud image is not enabled on this node.')
            from services.image_manager import ImageManager
            base = ImageManager().obtain(image)
            info = ImageManager.inspect(base)
            if info['virtual-size'] > spec['disk_gb'] * 2**30:
                raise EngineError(f'The cloud image requires at least {(info["virtual-size"] + 2**30 - 1) // 2**30} GiB. Increase the disk capacity.')
            directory.mkdir(mode=0o700)
            try:
                run(['qemu-img', 'convert', '-f', 'qcow2', '-O', 'qcow2', base, directory / 'disk.qcow2'], timeout=300)
                os.chmod(directory / 'disk.qcow2', 0o600)
                run(['qemu-img', 'resize', '-f', 'qcow2', directory / 'disk.qcow2', f'{spec["disk_gb"]}G'])
                self._seed(spec, credentials)
                runtime = {'accel': capability['accel'], 'storage_enforced': True,
                           'network_restricted': spec.get('network_restricted', settings()['restrict_guest_network']),
                           'forwards': spec.get('forwards', []), 'provisioned': True}
                if credentials.get('control_public_key'):
                    runtime['control_key_sha256'] = hashlib.sha256(credentials['control_public_key'].encode()).hexdigest()
                spec['runtime'] = runtime
                atomic_json(directory / 'config.json', spec)
            except Exception:
                shutil.rmtree(directory)
                raise
        # Create does not auto-start: disk/seed creation is a real stopped VM, not a fake running guest.
        return {'runtime': runtime, 'ssh_port': spec['ssh_port'], 'status': 'stopped'}

    def _seed(self, spec, credentials):
        directory = instance_dir(spec['id'])
        user = {'name': spec['username'], 'sudo': 'ALL=(ALL) NOPASSWD:ALL', 'shell': '/bin/bash',
                'lock_passwd': not bool(credentials.get('password_hash'))}
        keys = [credentials[k] for k in ('public_key', 'control_public_key') if credentials.get(k)]
        if keys:
            user['ssh_authorized_keys'] = keys
        if credentials.get('password_hash'):
            user['passwd'] = credentials['password_hash']
        cloud = {'hostname': spec['name'].lower(), 'manage_etc_hosts': True, 'disable_root': True,
                 'ssh_pwauth': bool(credentials.get('password_hash')), 'users': [user],
                 'chpasswd': {'expire': False}, 'growpart': {'mode': 'auto', 'devices': ['/'], 'ignore_growroot_disabled': False},
                 'resize_rootfs': True}
        if spec.get('network_restricted', settings()['restrict_guest_network']) is False:
            # Explicit internet-enabled guests prepare the installer prerequisites.
            # Do not make already-ready images refresh tens of MiB of indexes
            # under TCG. This constant guest-only script installs only if needed.
            cloud['runcmd'] = [['sh', '-c', SSHX_DEPENDENCIES]]
        userdata, metadata = directory / 'user-data', directory / 'meta-data'
        try:
            for path, text in [(userdata, '#cloud-config\n' + yaml.safe_dump(cloud)),
                               (metadata, yaml.safe_dump({'instance-id': spec['id'], 'local-hostname': spec['name'].lower()}))]:
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(fd, 'w') as f:
                    f.write(text)
            run(['cloud-localds', directory / 'seed.iso', userdata, metadata])
            os.chmod(directory / 'seed.iso', 0o600)
        finally:
            userdata.unlink(missing_ok=True)
            metadata.unlink(missing_ok=True)

    def _command(self, spec, accel):
        directory = instance_dir(spec['id'])
        if len(str(directory / 'qmp.sock').encode()) > 100:
            raise EngineError('Workspace path is too long for Unix sockets; use a shorter SKVM_DATA_DIR.')
        runtime = spec.get('runtime', {})
        forwards = [f'hostfwd=tcp:127.0.0.1:{spec["ssh_port"]}-:22']
        forwards += [f'hostfwd=tcp:127.0.0.1:{p["host"]}-:{p["guest"]}' for p in runtime.get('forwards', [])]
        restricted = 'on' if runtime.get('network_restricted', True) else 'off'
        return ['qemu-system-x86_64', '-name', f'skvm-{spec["id"]}', '-uuid', spec['id'],
                '-m', str(spec['ram_mb']), '-smp', str(spec['vcpus']), '-cpu', 'host' if accel == 'kvm' else 'max',
                '-machine', f'type=pc,accel={accel}', '-display', 'none', '-S', '-monitor', 'none',
                '-qmp', f'unix:{directory / "qmp.sock"},server=on,wait=off',
                '-serial', f'file:{directory / "serial.log"}',
                '-drive', f'file={directory / "disk.qcow2"},format=qcow2,if=virtio',
                '-drive', f'file={directory / "seed.iso"},format=raw,if=virtio,readonly=on',
                '-boot', 'order=c', '-device', 'virtio-net-pci,netdev=net0',
                '-netdev', f'user,id=net0,restrict={restricted},' + ','.join(forwards),
                '-device', 'virtio-balloon-pci', '-object', 'rng-random,filename=/dev/urandom,id=rng0',
                '-device', 'virtio-rng-pci,rng=rng0', '-rtc', 'base=utc,clock=host']

    def start(self, spec, **_):
        with locked(f'vm-{spec["id"]}'):
            if self._process(spec):
                raise EngineError('This VM is already running; a second process was not started.')
            capability = self.capabilities()
            if not capability['available']:
                raise EngineError(capability['reason'])
            directory = instance_dir(spec['id'])
            if not all((directory / name).is_file() for name in ('disk.qcow2', 'seed.iso', 'config.json')):
                raise EngineError('VM disk or cloud-init seed is missing. Refusing to create a blank replacement.')
            for name in ('qmp.sock', 'serial.sock'):
                (directory / name).unlink(missing_ok=True)
            with open(directory / 'qemu.log', 'ab', buffering=0) as log:
                process = subprocess.Popen(self._command(spec, capability['accel']), stdin=subprocess.DEVNULL,
                                           stdout=log, stderr=log, close_fds=True, start_new_session=True)
            resumed = False
            try:
                identity = psutil.Process(process.pid).create_time()
                atomic_json(directory / 'process.json', {'pid': process.pid, 'created': identity})
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        reason = (directory / 'qemu.log').read_text(errors='replace')[-1800:]
                        raise EngineError(f'QEMU exited during startup: {reason}')
                    if (directory / 'qmp.sock').exists():
                        try:
                            state = self._qmp(spec, 'query-status')
                            if not state.get('running'):
                                resumed = True  # A lost reply may still mean the command reached QEMU.
                                self._qmp(spec, 'cont')
                                state = self._qmp(spec, 'query-status')
                            if state.get('running'):
                                return {'status': 'running', 'runtime': spec['runtime'] | {'accel': capability['accel']}}
                        except EngineError:
                            if resumed:
                                raise
                            # A bound socket is not necessarily listening yet. Retry until the deadline.
                            pass
                    time.sleep(0.1)
                raise EngineError('QEMU did not expose a working monitor before the startup timeout.')
            except Exception as exc:
                if process.poll() is None:
                    if resumed:
                        raise UncertainError('QEMU may have resumed but startup could not be confirmed. The process was NOT force-stopped. An operator must inspect its monitor/process before reconciling this job.') from exc
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                raise

    def stop(self, spec, **_):
        with locked(f'vm-{spec["id"]}'):
            process = self._process(spec)
            if not process:
                return {'status': 'stopped'}
            self._qmp(spec, 'system_powerdown')
            try:
                # TCG guests may need the OS's 90-second service-stop timeout,
                # plus final disk flushing. Wait boundedly; never auto-kill.
                process.wait(timeout=180)
            except psutil.TimeoutExpired as exc:
                if not self._process(spec):
                    return {'status': 'stopped'}
                raise EngineError('ACPI shutdown requested, but the guest is still running. Wait and refresh, or explicitly use Force stop (risk of data loss).') from exc
            return {'status': 'stopped'}

    def force_stop(self, spec, **_):
        with locked(f'vm-{spec["id"]}'):
            process = self._process(spec)
            if process:
                try:
                    self._qmp(spec, 'quit')
                    process.wait(timeout=5)
                except (EngineError, psutil.TimeoutExpired):
                    process = self._process(spec)  # re-check identity immediately before signaling
                    if process:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except psutil.TimeoutExpired:
                            process = self._process(spec)
                            if process:
                                process.kill()
                                process.wait(timeout=5)
            return {'status': 'stopped'}

    def restart(self, spec, **kwargs):
        self.stop(spec)
        return self.start(spec)

    def _ensure_disk_idle(self, spec):
        if self._process(spec):
            raise EngineError('Stop the VM before modifying its disk.')
        disk = str(instance_dir(spec['id']) / 'disk.qcow2')
        # Also refuse an externally launched process holding this disk, even with a different UUID.
        for process in psutil.process_iter(['name']):
            try:
                if any(f.path == disk for f in process.open_files()):
                    raise EngineError('This disk is open by another process. Refusing deletion or replacement.')
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
            except psutil.AccessDenied:
                if (process.info.get('name') or '').startswith('qemu-system'):
                    raise EngineError('Cannot inspect a QEMU process for disk ownership. Manual inspection is required.')

    def delete(self, spec, **_):
        with locked(f'vm-{spec["id"]}'):
            self._ensure_disk_idle(spec)
            directory = instance_dir(spec['id'])
            if directory.exists():
                shutil.rmtree(directory)
            return {'status': 'deleted'}

    def resize(self, spec, disk_gb, **_):
        with locked(f'vm-{spec["id"]}'):
            if self._process(spec):
                raise EngineError('Stop the VM before resizing.')
            if disk_gb <= spec['disk_gb']:
                raise EngineError('Only disk growth is supported. Shrinking risks filesystem corruption.')
            directory = instance_dir(spec['id'])
            run(['qemu-img', 'resize', '-f', 'qcow2', directory / 'disk.qcow2', f'{disk_gb}G'])
            spec['disk_gb'] = disk_gb
            atomic_json(directory / 'config.json', spec)
            return {'disk_gb': disk_gb}

    def metrics(self, spec):
        from services.resource_monitor import process_metrics
        process = self._process(spec)
        disk = instance_dir(spec['id']) / 'disk.qcow2'
        usage = process_metrics(process)
        usage['disk_actual_bytes'] = disk.stat().st_blocks * 512 if disk.exists() else None
        state = 'stopped' if disk.exists() else 'missing'
        if process:
            try:
                qmp = self._qmp(spec, 'query-status')
                state = 'running' if qmp.get('running') else qmp.get('status', 'unknown')
            except EngineError:
                state = 'unknown'
        return {'status': state, 'usage': usage,
                'storage_enforced': True, 'accel': spec.get('runtime', {}).get('accel', 'tcg')}

    def ssh_endpoint(self, spec):
        """Prove this forward belongs to the actual guest, never a host SSH daemon.

        A DB port or an open TCP port alone isn't proof of guest identity. Check
        exact QEMU process identity, its real -netdev argument, owned listener
        and live QMP state. Call again after key exchange, before SSH auth.
        """
        if current_app.config['TEST_MODE']:
            raise EngineError('Guest SSH cannot connect in test mode.')
        process = self._process(spec)
        if not process:
            raise EngineError('The managed QEMU VM is not running. Start it first and wait for guest SSH to boot.')
        port = spec.get('ssh_port')
        if type(port) is not int or not 1024 <= port <= 65535:
            raise EngineError('The VM has no valid managed SSH forward.')
        forward = f'hostfwd=tcp:127.0.0.1:{port}-:22'
        try:
            command = process.cmdline()
            netdevs = [command[i + 1] for i, value in enumerate(command[:-1]) if value == '-netdev']
            if not any(forward in value.split(',') for value in netdevs):
                raise EngineError('The running QEMU process does not own the configured guest SSH forward. Refusing a host connection.')
            listeners = process.net_connections(kind='tcp')
            if not any(c.status == psutil.CONN_LISTEN and c.laddr.ip == '127.0.0.1' and c.laddr.port == port for c in listeners):
                raise EngineError('Cannot prove that the SSH listener belongs to this QEMU VM. No host connection was attempted.')
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError) as exc:
            raise EngineError('Cannot verify the QEMU-owned SSH listener. Check process permissions on its node.') from exc
        if self._qmp(spec, 'query-status').get('running') is not True:
            raise EngineError('The QEMU guest is paused or not running. Resume/start it before generating SSHX.')
        return '127.0.0.1', port

    def assign(self, spec, owner_id, **_):
        from services.security import integer
        owner_id = integer(owner_id, 'Assigned account', 1, 2**31 - 1)
        with locked(f'vm-{spec["id"]}'):
            self._ensure_disk_idle(spec)
            path = instance_dir(spec['id']) / 'config.json'
            if path.is_symlink() or not path.is_file():
                raise EngineError('The managed VM manifest is unavailable or unsafe.')
            saved = json.loads(path.read_text())
            if any(saved.get(k) != spec.get(k) for k in ('id', 'owner_id', 'engine', 'username', 'ssh_port')):
                raise EngineError('The managed VM manifest identity does not match.')
            atomic_json(path, saved | {'owner_id': owner_id})
            return {'status': 'stopped', 'owner_id': owner_id}

    def network(self, spec, restricted, **_):
        if type(restricted) is not bool:
            raise EngineError('Choose restricted networking or outbound internet.')
        with locked(f'vm-{spec["id"]}'):
            self._ensure_disk_idle(spec)
            path = instance_dir(spec['id']) / 'config.json'
            if path.is_symlink() or not path.is_file():
                raise EngineError('The managed VM manifest is unavailable or unsafe.')
            saved = json.loads(path.read_text())
            if any(saved.get(k) != spec.get(k) for k in ('id', 'owner_id', 'engine', 'username', 'ssh_port')):
                raise EngineError('The managed VM manifest identity does not match.')
            runtime = dict(spec.get('runtime', {}), network_restricted=restricted)
            atomic_json(path, saved | {'runtime': runtime, 'network_restricted': restricted})
            return {'status': 'stopped', 'runtime': runtime}

    def reinstall(self, spec, credentials, **_):
        # The controller holds the per-instance control lock. Old storage is retained until preparation succeeds.
        self._ensure_disk_idle(spec)
        directory = instance_dir(spec['id'])
        backup = directory.with_name(spec['id'] + '.reinstall-backup')
        if backup.exists():
            raise EngineError('A previous reinstall backup exists. Inspect it before retrying.')
        os.replace(directory, backup)
        try:
            result = self.create(spec, credentials)
        except Exception:
            if not directory.exists():
                os.replace(backup, directory)
            raise
        shutil.rmtree(backup)
        return result

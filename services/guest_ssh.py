"""Bounded, non-interactive SSH to a *proven managed guest*, never an arbitrary host.

There is no PTY, browser socket, agent forwarding, local SSH configuration or
request-supplied command. The only callers execute fixed enrollment/SSHX scripts.
"""
import base64
from contextlib import contextmanager
from datetime import timedelta
import hashlib
import logging
import re
import socket
import threading
import time
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from flask import current_app
import paramiko

from engines import EngineError, UncertainError
from engines.qemu_engine import QemuEngine
from extensions import db
from models import AuthAttempt
from models.sshx import GuestLease
from models.user import utcnow
from services.guest_keys import SSHError, private_key
from services.guest_access import GuestAuthorityError
from services.security import locked, valid_uuid

SSH_LOGGER = logging.getLogger('skvm.private-guest-ssh')
SSH_LOGGER.disabled = True
SSH_LOGGER.propagate = False
FINGERPRINT = re.compile(r'SHA256:[A-Za-z0-9+/]{43}')


class GuestSSHRetryableError(EngineError):
    """Proven pre-command failure, never an uncertain guest mutation."""


class GuestSSHNotReadyError(GuestSSHRetryableError):
    code = 'guest_ssh_not_ready'

    def __init__(self):
        super().__init__('The VM’s verified SSH service is not ready yet. Wait for guest boot/cloud-init and check sshd. No guest credentials or command were sent.')


class GuestSSHBusyError(GuestSSHRetryableError):
    code = 'guest_ssh_busy'

    def __init__(self):
        super().__init__('Guest SSH admission/rate limit reached. Wait one minute and retry.')


SSH_RETRY_ERRORS = {error.code: error for error in (GuestSSHNotReadyError, GuestSSHBusyError)}


def new_key():
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                               serialization.NoEncryption()).decode()
    public = key.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                          serialization.PublicFormat.OpenSSH).decode()
    return private, public + ' skvm-managed'


def validate_spec(spec):
    if not current_app.config['SSHX_ENABLED']:
        raise EngineError('SSHX is disabled by the operator.')
    if current_app.config['TEST_MODE']:
        raise EngineError('SSHX is unavailable in test mode; no guest connection was attempted.')
    valid_uuid(spec.get('id'))
    if spec.get('engine') != 'qemu':
        raise EngineError('SSHX requires a managed QEMU VM. Docker instances have no managed SSH service.')
    user = spec.get('username')
    if not isinstance(user, str) or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,30}', user) or user in ('root', 'nobody', 'daemon', 'bin', 'sys'):
        raise EngineError('The VM has no valid non-root SSH username.')
    port = spec.get('ssh_port')
    if type(port) is not int or not 1024 <= port <= 65535:
        raise EngineError('The VM has no valid managed SSH forward.')


def credentials(data):
    if not isinstance(data, dict):
        raise EngineError('Choose an existing guest password or private key.')
    if data.get('method') == 'password':
        password = data.get('password')
        if set(data) != {'method', 'password'} or not isinstance(password, str) or not 1 <= len(password) <= 1024:
            raise EngineError('An existing guest password of 1–1024 characters is required.')
    elif data.get('method') == 'key':
        material, phrase = data.get('private_key'), data.get('passphrase', '')
        if (set(data) - {'method', 'private_key', 'passphrase'} or not isinstance(material, str)
                or not 1 <= len(material.encode()) <= 65536 or not isinstance(phrase, str) or len(phrase) > 1024):
            raise EngineError('Enrollment private keys are limited to 64 KiB and passphrases to 1024 characters.')
    else:
        raise EngineError('Choose password or private-key authentication.')
    return dict(data)


def fingerprint(key):
    return 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')


@contextmanager
def admission(principal, ident):
    now, lease = utcnow(), str(uuid.uuid4())
    with locked('guest-ssh-admission'):
        db.session.execute(db.delete(GuestLease).where(GuestLease.expires_at < now))
        total = db.session.scalar(db.select(db.func.count()).select_from(GuestLease))
        own = db.session.scalar(db.select(db.func.count()).select_from(GuestLease).where(GuestLease.principal == principal))
        tag = hashlib.sha256(f'guest-ssh:{principal}'.encode()).hexdigest()
        attempts = db.session.scalar(db.select(db.func.count()).select_from(AuthAttempt).where(
            AuthAttempt.fingerprint == tag, AuthAttempt.created_at > now - timedelta(minutes=1)))
        if total >= 4 or own >= 2 or attempts >= 10:
            db.session.rollback()
            raise GuestSSHBusyError()
        db.session.add(AuthAttempt(fingerprint=tag))
        db.session.add(GuestLease(id=lease, principal=principal, instance_id=ident,
                                  expires_at=now + timedelta(seconds=180)))
        db.session.commit()
    try:
        yield
    finally:
        db.session.rollback()
        db.session.execute(db.delete(GuestLease).where(GuestLease.id == lease))
        db.session.commit()


class GuestSSH:
    def __init__(self, spec, expected_fingerprint=None, check=lambda: None):
        validate_spec(spec)
        if expected_fingerprint is not None and (not isinstance(expected_fingerprint, str) or not FINGERPRINT.fullmatch(expected_fingerprint)):
            raise EngineError('Invalid saved guest host fingerprint.')
        self.spec, self.check = dict(spec), check
        self.sock, self.transport = None, None
        try:
            check()
            endpoint = QemuEngine().ssh_endpoint(spec)
            if endpoint != ('127.0.0.1', spec['ssh_port']):
                raise EngineError('The verified guest endpoint does not match this VM’s managed forward.')
            self.sock = socket.create_connection(('127.0.0.1', endpoint[1]), timeout=5)
            self.transport = paramiko.Transport(self.sock)
            self.transport.set_log_channel(SSH_LOGGER.name)
            self.transport.banner_timeout = self.transport.auth_timeout = 10
            self.transport.start_client(timeout=10)
            if not self.transport.is_active() or not self.transport.remote_version:
                raise GuestSSHNotReadyError()
            check()
            QemuEngine().ssh_endpoint(spec)  # Re-prove the listener after the handshake.
            self.fingerprint = fingerprint(self.transport.get_remote_server_key())
            if expected_fingerprint is not None and self.fingerprint != expected_fingerprint:
                raise EngineError('Guest SSH host key changed. No credentials were sent. Verify the new fingerprint and re-enroll explicitly; do not bypass this check.')
        except EngineError:
            self.close()
            raise
        except paramiko.ssh_exception.IncompatiblePeer:
            self.close()
            raise EngineError('The guest SSH service has no compatible key-exchange or host-key algorithm. Upgrade its SSH configuration; no credentials or command were sent.') from None
        except (OSError, EOFError, paramiko.SSHException):
            self.close()
            raise GuestSSHNotReadyError() from None
        except Exception:
            self.close()
            raise EngineError('Cannot establish verified guest SSH before authentication. Check its guest SSH service and managed forward. No guest command was sent.') from None

    def authenticate(self, auth):
        auth = credentials(auth)
        try:
            self.check()
            QemuEngine().ssh_endpoint(self.spec)
            if auth['method'] == 'password':
                self.transport.auth_password(self.spec['username'], auth['password'], fallback=False)
            else:
                self.transport.auth_publickey(self.spec['username'], private_key(auth))
            if not self.transport.is_authenticated():
                raise EngineError('Guest SSH authentication failed.')
            self.check()
        except (EngineError, SSHError):
            raise
        except Exception:
            raise EngineError('Guest SSH authentication failed. Use the guest account credentials, not your panel password. If a saved management key was rejected, use Repair management access with the existing guest credential; no VPS reset is needed.') from None
        finally:
            if self.transport and self.transport.auth_handler:
                self.transport.auth_handler.password = None
                self.transport.auth_handler.private_key = None
            auth.clear()

    def _request_exec(self, channel, deadline):
        """Bound Paramiko's acknowledgement wait, which ignores settimeout().

        Only the SSH protocol request runs on this short-lived thread; database
        authority checks remain in the calling application thread. Closing the
        channel wakes Paramiko's event waiter, never an unbounded executor join.
        """
        done, failures = threading.Event(), []

        def request():
            try:
                channel.exec_command('sh -s')
            except Exception as exc:
                failures.append(exc)
            finally:
                done.set()

        thread = threading.Thread(target=request, daemon=True, name='skvm-guest-exec-ack')
        thread.start()
        try:
            while True:
                self.check()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise UncertainError('The guest command request timed out before acknowledgement. Its outcome is unknown; inspect before retrying.')
                if done.wait(min(.05, remaining)):
                    if failures:
                        raise failures[0]
                    return
        finally:
            if not done.is_set():
                channel.close()
            thread.join(timeout=.2)

    def execute(self, script, seconds=120):
        """One total deadline, including channel setup and exec acknowledgement."""
        channel, started = None, False
        end = time.monotonic() + seconds
        try:
            self.check()
            QemuEngine().ssh_endpoint(self.spec)
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise EngineError('Guest command setup timed out before submission. No command was sent.')
            channel = self.transport.open_session(timeout=min(5, remaining))
            channel.settimeout(min(3, max(.01, end - time.monotonic())))
            # Once submitted, a lost acknowledgement is NOT proof of failure.
            started = True
            self._request_exec(channel, min(end, time.monotonic() + 10))
            self.check()
            if time.monotonic() >= end:
                raise UncertainError('The guest command timed out after submission. Its outcome is unknown; inspect before retrying.')
            channel.settimeout(min(3, end - time.monotonic()))
            channel.sendall(script.encode())
            channel.shutdown_write()
            output = bytearray()
            while True:
                self.check()
                for ready, receive in ((channel.recv_ready, channel.recv), (channel.recv_stderr_ready, channel.recv_stderr)):
                    while ready():
                        output.extend(receive(8192))
                        if len(output) > 65536:
                            raise UncertainError('Guest command output exceeded the safe limit. Its outcome must be inspected before retrying.')
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    code = channel.recv_exit_status()
                    if code != 0:
                        # Never return/log raw output: it may contain access links or credentials.
                        markers = set(re.findall(rb'SKVM_ERROR:([A-Z_]+)', output))
                        errors = {
                            b'TOOLS': 'Guest prerequisites are missing: bash, curl, tar, timeout, setsid and nohup. Install these inside the guest, then retry.',
                            b'PIDFD': 'Safe SSHX process control requires guest Python 3.9+ and Linux pidfd support. Install/upgrade these inside the VM, or stop the VM to revoke access.',
                            b'INSTALL': 'The SSHX installer failed inside the VM. Check guest outbound HTTPS, DNS, CA certificates and passwordless sudo.',
                            b'NO_LINK': 'SSHX did not produce a valid link before the deadline. Check guest outbound access to sshx.io.',
                            b'PROCESS': 'The saved SSHX process identity cannot be verified. No unrelated process was signalled; inspect the guest.',
                            b'STOP': 'SSHX did not stop cleanly. The existing link was not declared revoked.',
                            b'ENROLL': 'Cannot safely add the management public key to the guest authorized_keys file.',
                            b'NOT_FOUND': 'No live SSHX process for this operation can be proven.',
                        }
                        raise EngineError(next((text for key, text in errors.items() if key in markers),
                                               'The fixed guest operation failed. No raw guest output was logged.'))
                    return output.decode('utf-8', errors='replace')
                if time.monotonic() >= end or not self.transport.is_active():
                    raise UncertainError('The guest command timed out or disconnected. Its outcome is unknown; reconcile before retrying.')
                time.sleep(0.05)
        except GuestAuthorityError:
            if started:
                raise UncertainError('Authority changed after guest command submission. A client may remain running; inspect or stop the VM before retrying.') from None
            raise
        except EngineError:
            raise
        except Exception:
            if started:
                raise UncertainError('The guest connection ended after command submission. Inspect its outcome before retrying.') from None
            raise EngineError('Cannot open a guest SSH command channel.') from None
        finally:
            if channel:
                channel.close()

    def close(self):
        if self.transport:
            self.transport.close()
        if self.sock:
            self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

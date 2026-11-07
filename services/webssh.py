"""Bounded SSH PTY transport. Never executes a command or uses the host's SSH agent.

The only local endpoint comes from a verified, live managed QEMU process. An
external node runs this same transport beside its own guest; the panel relays
its authenticated WSS stream rather than dialing the panel's localhost.
"""
import base64
import codecs
from datetime import timedelta
import hashlib
import io
import json
import logging
import secrets
import socket
import time
import uuid

from flask import current_app
import paramiko
from simple_websocket import ConnectionClosed

from engines import EngineError
from engines.qemu_engine import QemuEngine
from extensions import db
from models import AuthAttempt
from models.user import utcnow
from models.webssh import SSHHostKey, SSHLease
from services.security import locked, valid_uuid

MAX_MESSAGE = 96 * 1024
MAX_INPUT = 16 * 1024
AUTH_SECONDS = 10
TRUST_SECONDS = 45
RECHECK_SECONDS = 2
LEASE_SECONDS = 90

# SSH servers can place arbitrary text in banners/disconnects. Keep upstream
# packet/auth diagnostics out of application logs; expose controlled errors.
SSH_LOGGER = logging.getLogger('skvm.private-ssh-transport')
SSH_LOGGER.disabled = True
SSH_LOGGER.propagate = False


class SSHError(EngineError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def enabled():
    if not current_app.config['WEBSSH_ENABLED']:
        raise SSHError('disabled', 'WebSSH is disabled by the operator.')
    if current_app.config['TEST_MODE']:
        raise SSHError('test_mode', 'WebSSH is unavailable in test mode. No real guest connection was attempted.')


def validate_spec(spec):
    enabled()
    valid_uuid(spec.get('id'))
    if spec.get('engine') != 'qemu':
        raise SSHError('unsupported_engine', 'Docker images do not have managed SSH access. Use container logs and diagnostics in Console. WebSSH is available for QEMU VMs.')
    user = spec.get('username')
    import re
    if not isinstance(user, str) or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,30}', user) or user in ('root', 'nobody', 'daemon', 'bin', 'sys'):
        raise SSHError('invalid_target', 'The managed VM has no valid non-root SSH username. Inspect its provisioning configuration.')
    port = spec.get('ssh_port')
    if type(port) is not int or not 1024 <= port <= 65535:
        raise SSHError('invalid_target', 'The managed VM has no valid loopback SSH forward.')


def message(raw):
    if not isinstance(raw, str) or len(raw.encode('utf-8')) > MAX_MESSAGE:
        raise SSHError('invalid_message', 'WebSSH requires bounded JSON text messages.')
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):
        raise SSHError('invalid_message', 'Invalid WebSSH JSON message.') from None
    if not isinstance(data, dict) or not isinstance(data.get('type'), str):
        raise SSHError('invalid_message', 'Invalid WebSSH message.')
    return data


def dimensions(data):
    cols, rows = data.get('cols'), data.get('rows')
    if type(cols) is not int or type(rows) is not int or not 2 <= cols <= 500 or not 1 <= rows <= 200:
        raise SSHError('invalid_size', 'Terminal size must be 2–500 columns and 1–200 rows.')
    return cols, rows


def connection_message(data, browser=False):
    allowed = {'type', 'credentials', 'cols', 'rows'} | ({'csrf_token'} if browser else set())
    if set(data) - allowed or data.get('type') != 'connect':
        raise SSHError('invalid_target', 'Only managed VM connections are allowed. Hosts, ports, usernames and commands cannot be supplied by the browser.')
    dimensions(data)
    credentials = data.get('credentials')
    if not isinstance(credentials, dict):
        raise SSHError('invalid_credentials', 'Choose a guest password or private key.')
    method = credentials.get('method')
    if method == 'password':
        if set(credentials) != {'method', 'password'} or not isinstance(credentials['password'], str) or not 1 <= len(credentials['password']) <= 1024:
            raise SSHError('invalid_credentials', 'A guest password of 1–1024 characters is required.')
    elif method == 'key':
        if set(credentials) - {'method', 'private_key', 'passphrase'}:
            raise SSHError('invalid_credentials', 'Unexpected private-key authentication fields.')
        material = credentials.get('private_key')
        passphrase = credentials.get('passphrase', '')
        if not isinstance(material, str) or not 1 <= len(material.encode('utf-8')) <= 65536 or not isinstance(passphrase, str) or len(passphrase) > 1024:
            raise SSHError('invalid_credentials', 'Private keys are limited to 64 KiB and passphrases to 1024 characters.')
    else:
        raise SSHError('invalid_credentials', 'Choose password or private-key authentication.')
    # Copy only the protocol fields. A panel CSRF token is never sent to a node.
    return {key: data[key] for key in ('type', 'credentials', 'cols', 'rows')}


def send(ws, kind, **fields):
    ws.send(json.dumps({'type': kind, **fields}, ensure_ascii=True))


def error(ws, exc):
    try:
        send(ws, 'error', code=exc.code if isinstance(exc, SSHError) else 'unavailable', message=str(exc))
    except (ConnectionClosed, OSError):
        pass


def admit(principal, ident, browser_session=None):
    """File lock + SQLite rows enforce limits across all Gunicorn workers."""
    now = utcnow()
    with locked('webssh-admission'):
        db.session.execute(db.delete(SSHLease).where(SSHLease.expires_at < now))
        total = db.session.scalar(db.select(db.func.count()).select_from(SSHLease))
        own = db.session.scalar(db.select(db.func.count()).select_from(SSHLease).where(SSHLease.principal == principal))
        if total >= current_app.config['WEBSSH_MAX_SESSIONS'] or own >= current_app.config['WEBSSH_PER_USER_SESSIONS']:
            db.session.rollback()
            raise SSHError('session_limit', 'WebSSH session limit reached. Disconnect another terminal and try again.')
        fingerprint = hashlib.sha256(f'webssh:{principal}'.encode()).hexdigest()
        attempts = db.session.scalar(db.select(db.func.count()).select_from(AuthAttempt).where(
            AuthAttempt.fingerprint == fingerprint, AuthAttempt.created_at > now - timedelta(minutes=1)))
        if attempts >= 10:
            db.session.rollback()
            raise SSHError('rate_limit', 'Too many WebSSH connection attempts. Wait one minute before retrying.')
        db.session.add(AuthAttempt(fingerprint=fingerprint))
        # Old login and SSH attempts have no security value after a day.
        db.session.execute(db.delete(AuthAttempt).where(AuthAttempt.created_at < now - timedelta(days=1)))
        ident_lease = str(uuid.uuid4())
        db.session.add(SSHLease(id=ident_lease, principal=principal, instance_id=ident, browser_session=browser_session,
                               expires_at=now + timedelta(seconds=LEASE_SECONDS)))
        db.session.commit()
    return ident_lease


def renew(lease):
    row = db.session.get(SSHLease, lease, populate_existing=True)
    if row is None or row.expires_at < utcnow():
        raise SSHError('session_expired', 'This WebSSH session has expired. Reconnect to continue.')
    row.expires_at = utcnow() + timedelta(seconds=LEASE_SECONDS)
    db.session.commit()


def release(lease):
    db.session.rollback()
    db.session.execute(db.delete(SSHLease).where(SSHLease.id == lease))
    db.session.commit()


def fingerprint(key):
    return 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')


def _key_string(blob, offset):
    if offset + 4 > len(blob):
        raise ValueError
    length = int.from_bytes(blob[offset:offset + 4], 'big')
    offset += 4
    if length > len(blob) - offset:
        raise ValueError
    return blob[offset:offset + length], offset + length


def _openssh_key_class(material):
    """Bound untrusted bcrypt work *before* a library can start key decryption.

    OpenSSH stores a caller-chosen 32-bit KDF round count in the key header.
    Size limits alone don't bound that CPU work. Also select the declared key
    type once so an incorrect passphrase doesn't repeat expensive decryption.
    """
    try:
        body = material.split('-----BEGIN OPENSSH PRIVATE KEY-----', 1)[1].split('-----END OPENSSH PRIVATE KEY-----', 1)[0]
        raw = base64.b64decode(''.join(body.split()), validate=True)
        if raw[:15] != b'openssh-key-v1\x00':
            raise ValueError
        cipher, offset = _key_string(raw, 15)
        kdf, offset = _key_string(raw, offset)
        options, offset = _key_string(raw, offset)
        if kdf == b'bcrypt':
            salt, end = _key_string(options, 0)
            if not 1 <= len(salt) <= 64 or end + 4 != len(options):
                raise ValueError
            rounds = int.from_bytes(options[end:], 'big')
            if not 1 <= rounds <= 256:
                raise SSHError('key_cost_limit', 'This private key’s decryption work factor exceeds the WebSSH safety limit (256 bcrypt rounds). Use your native SSH client or a dedicated key with a bounded work factor.')
            if cipher not in (b'aes256-ctr', b'aes256-cbc'):
                raise ValueError
        elif kdf != b'none' or cipher != b'none':
            raise ValueError
        if raw[offset:offset + 4] != b'\x00\x00\x00\x01':
            raise ValueError
        public, private_offset = _key_string(raw, offset + 4)
        payload, _ = _key_string(raw, private_offset)
        if len(payload) > 8192:
            raise SSHError('key_cost_limit', 'The private key payload exceeds the 8 KiB validation-work limit. Use a native SSH client for larger keys.')
        kind, public_offset = _key_string(public, 0)
        if kind == b'ssh-ed25519':
            return paramiko.Ed25519Key
        if kind == b'ssh-rsa':
            exponent, public_offset = _key_string(public, public_offset)
            modulus, _ = _key_string(public, public_offset)
            if len(modulus) > 1025 or int.from_bytes(modulus, 'big').bit_length() > 8192 or len(exponent) > 8:
                raise SSHError('key_cost_limit', 'WebSSH accepts RSA keys up to 8192 bits with a bounded public exponent. Use a native SSH client for larger keys.')
            return paramiko.RSAKey
        if kind in (b'ecdsa-sha2-nistp256', b'ecdsa-sha2-nistp384', b'ecdsa-sha2-nistp521'):
            return paramiko.ECDSAKey
        raise ValueError
    except (ValueError, IndexError, UnicodeError):
        raise SSHError('invalid_private_key', 'Malformed or unsupported OpenSSH private key. No key decryption was attempted.') from None


def private_key(credentials):
    material = credentials['private_key']
    classes = (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey)
    if '-----BEGIN OPENSSH PRIVATE KEY-----' in material:
        classes = (_openssh_key_class(material),)
    elif len(material.encode('utf-8')) > 8192:
        raise SSHError('key_cost_limit', 'PEM private keys are limited to 8 KiB to bound key-validation work. Use a standard OpenSSH key or your native SSH client.')
    for key_class in classes:
        try:
            key = key_class.from_private_key(io.StringIO(credentials['private_key']), password=credentials.get('passphrase') or None)
            if key.get_bits() > 8192:
                raise SSHError('key_cost_limit', 'WebSSH supports private keys up to 8192 bits. Use your native client for larger keys.')
            return key
        except paramiko.PasswordRequiredException:
            raise SSHError('key_passphrase_required', 'This private key is encrypted. Enter its passphrase and reconnect.') from None
        except (paramiko.SSHException, ValueError, TypeError):
            continue
    raise SSHError('invalid_private_key', 'Cannot read this private key or passphrase. Use an OpenSSH Ed25519, ECDSA or RSA key, or a PEM RSA/ECDSA key.')


def trust_key(ws, ident, key, check):
    digest, algorithm = fingerprint(key), key.get_name()
    pin = db.session.get(SSHHostKey, ident, populate_existing=True)
    if pin and secrets.compare_digest(pin.fingerprint, digest) and pin.algorithm == algorithm:
        return False
    previous = pin.fingerprint if pin else None
    send(ws, 'host_key', fingerprint=digest, algorithm=algorithm, previous=previous, changed=previous is not None)
    deadline = time.monotonic() + TRUST_SECONDS
    while time.monotonic() < deadline:
        check()
        raw = ws.receive(timeout=RECHECK_SECONDS)
        if raw is None:
            continue
        reply = message(raw)
        if reply.get('type') == 'disconnect':
            raise SSHError('cancelled', 'Connection cancelled. No SSH credentials were sent to the guest.')
        if reply.get('type') != 'trust' or reply.get('fingerprint') != digest or reply.get('accept') is not True:
            raise SSHError('host_key_rejected', 'Host key was not accepted. No SSH credentials were sent to the guest.')
        # Changed keys need a distinct acknowledgement; never silently replace a pin.
        if previous and reply.get('confirm_changed') is not True:
            raise SSHError('host_key_changed', 'The guest host key changed. Verify the new fingerprint through the serial console before replacing the saved key.')
        check()
        with locked('webssh-host-key-' + ident):
            existing = db.session.get(SSHHostKey, ident, populate_existing=True)
            if existing and existing.fingerprint not in (previous, digest):
                raise SSHError('host_key_changed', 'Another session changed this VM’s trusted host key. Reconnect and verify it again.')
            if existing is None:
                existing = SSHHostKey(instance_id=ident)
                db.session.add(existing)
            existing.fingerprint, existing.algorithm, existing.trusted_at = digest, algorithm, utcnow()
            db.session.commit()
        return True
    raise SSHError('host_key_timeout', 'Host-key confirmation timed out. No SSH credentials were sent to the guest.')


def stream(ws, spec, first, check, audit=lambda action: None):
    """Real SSH handshake, verified host key, explicit auth, PTY and duplex I/O."""
    validate_spec(spec)
    transport = channel = tcp = None
    credentials = first['credentials']
    try:
        check()
        endpoint = QemuEngine().ssh_endpoint(spec)
        tcp = socket.create_connection(endpoint, timeout=5)
        transport = paramiko.Transport(tcp)
        transport.set_log_channel(SSH_LOGGER.name)
        transport.banner_timeout = AUTH_SECONDS
        transport.auth_timeout = AUTH_SECONDS
        transport.start_client(timeout=AUTH_SECONDS)
        if not transport.is_active():
            raise SSHError('handshake_failed', 'The guest did not complete an SSH handshake. Check its serial console and SSH service.')
        # Re-verify the runtime before trust/auth, not merely the database record.
        QemuEngine().ssh_endpoint(spec)
        if trust_key(ws, spec['id'], transport.get_remote_server_key(), check):
            audit('host_key_trusted')
        check()
        QemuEngine().ssh_endpoint(spec)
        check()
        if credentials['method'] == 'password':
            # No keyboard-interactive prompts / password fallbacks to other identities.
            transport.auth_password(spec['username'], credentials['password'], fallback=False)
        else:
            key = private_key(credentials)
            credentials.clear()
            check()
            transport.auth_publickey(spec['username'], key)
            key = None
        credentials.clear()
        if transport.auth_handler is not None:
            transport.auth_handler.password = None
            transport.auth_handler.private_key = None
        if not transport.is_authenticated():
            raise SSHError('authentication_failed', 'Guest SSH authentication failed. Check the provisioned guest username, password or authorized key.')
        check()
        channel = transport.open_session(timeout=AUTH_SECONDS)
        channel.settimeout(2)
        channel.set_combine_stderr(True)
        cols, rows = dimensions(first)
        channel.get_pty(term='xterm-256color', width=cols, height=rows)
        channel.invoke_shell()
        transport.set_keepalive(20)
        audit('connected')
        send(ws, 'connected', username=spec['username'], fingerprint=fingerprint(transport.get_remote_server_key()))
        decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')
        started = last_input = last_check = time.monotonic()
        window, input_bytes, input_messages = started, 0, 0
        while True:
            now = time.monotonic()
            if now - started >= current_app.config['WEBSSH_MAX_SECONDS'] or now - last_input >= current_app.config['WEBSSH_IDLE_SECONDS']:
                raise SSHError('session_expired', 'WebSSH reached its idle or maximum duration. Reconnect to continue.')
            if now - last_check >= RECHECK_SECONDS:
                check()
                last_check = now
            # Bound work per iteration so a noisy guest cannot starve revocation/input.
            for _ in range(4):
                if not channel.recv_ready():
                    break
                chunk = channel.recv(8192)
                if chunk:
                    text = decoder.decode(chunk)
                    if text:
                        send(ws, 'output', data=text)
            if (channel.closed or channel.exit_status_ready() or not transport.is_active()) and not channel.recv_ready():
                final = decoder.decode(b'', final=True)
                if final:
                    send(ws, 'output', data=final)
                send(ws, 'disconnected', message='The guest SSH session ended.')
                return
            raw = ws.receive(timeout=0.04)
            if raw is None:
                continue
            data = message(raw)
            input_bytes += len(raw.encode('utf-8'))
            input_messages += 1
            if now - window >= 1:
                window, input_bytes, input_messages = now, len(raw.encode('utf-8')), 1
            if input_bytes > 512 * 1024 or input_messages > 200:
                raise SSHError('rate_limit', 'Terminal input rate exceeded the safe limit. Reconnect and paste smaller chunks.')
            kind = data['type']
            if kind == 'disconnect':
                send(ws, 'disconnected', message='Disconnected. The guest continues running.')
                return
            if kind == 'ping':
                nonce = data.get('nonce')
                if not isinstance(nonce, (str, int)) or isinstance(nonce, bool) or len(str(nonce)) > 40:
                    raise SSHError('invalid_message', 'Invalid round-trip probe.')
                send(ws, 'pong', nonce=nonce)
            elif kind == 'resize':
                cols, rows = dimensions(data)
                channel.resize_pty(width=cols, height=rows)
            elif kind == 'input':
                text = data.get('data')
                if not isinstance(text, str) or not 1 <= len(text.encode('utf-8')) <= MAX_INPUT:
                    raise SSHError('invalid_message', 'Terminal input must be 1–16384 UTF-8 bytes.')
                check()  # Refresh authority (at most twice/second) before input.
                channel.sendall(text.encode('utf-8'))
                last_input = now
            else:
                raise SSHError('invalid_message', 'Unexpected terminal message.')
    except paramiko.AuthenticationException:
        raise SSHError('authentication_failed', 'Guest SSH authentication failed. Use the password or private key configured for this VM, not your panel password.') from None
    except paramiko.SSHException:
        raise SSHError('ssh_failed', 'The guest SSH handshake, authentication or PTY request failed. Check its SSH service in the serial console.') from None
    except ConnectionRefusedError:
        raise SSHError('connection_refused', 'The guest SSH forward is not accepting connections. Wait for cloud-init or check the guest SSH service in Console.') from None
    except (TimeoutError, socket.timeout):
        raise SSHError('timeout', 'The guest SSH connection timed out. Check its boot progress and SSH service in Console.') from None
    except (EOFError, OSError):
        raise SSHError('connection_lost', 'The guest SSH connection closed or became unavailable.') from None
    finally:
        credentials.clear()
        first.pop('credentials', None)
        if channel is not None:
            channel.close()
        if transport is not None:
            transport.close()
        if tcp is not None:
            tcp.close()

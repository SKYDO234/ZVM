import base64
import fcntl
import ipaddress
import json
import os
import re
import socket
import subprocess
import uuid
from contextlib import contextmanager
from functools import wraps
from pathlib import Path
from urllib.parse import urlsplit
from cryptography.fernet import Fernet, InvalidToken
from flask import abort, current_app, has_request_context
from flask_login import current_user
from config import private_file
from engines import EngineError
from extensions import db
from models import Audit, Setting


def settings():
    values = dict(current_app.config['SETTINGS_DEFAULTS'])
    values.update({s.key: s.value for s in db.session.scalars(db.select(Setting))})
    return values


def cipher():
    key = private_file(Path(current_app.config['DATA_DIR']) / '.encryption-key', lambda: Fernet.generate_key().decode())
    return Fernet(key.encode())


def encrypt(value):
    return cipher().encrypt(json.dumps(value).encode()).decode()


def decrypt(value):
    try:
        return json.loads(cipher().decrypt(value.encode()))
    except (InvalidToken, ValueError, UnicodeError) as exc:
        raise EngineError('Encrypted data cannot be read. Restore the original workspace encryption key; credentials are never silently replaced.') from exc


def audit(action, message, user_id=None, instance_id=None):
    if user_id is None and has_request_context() and current_user.is_authenticated:
        user_id = current_user.id
    db.session.add(Audit(user_id=user_id, instance_id=instance_id, action=action, message=message[:2000]))


def admin_required(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return func(*args, **kwargs)
    return wrapped


def valid_uuid(value):
    try:
        if str(uuid.UUID(str(value))) != str(value):
            raise ValueError
        return str(value)
    except (ValueError, AttributeError):
        raise EngineError('Invalid instance identifier.')


def instance_dir(instance_id):
    valid_uuid(instance_id)
    root = Path(current_app.config['DATA_DIR']).resolve() / 'vms'
    path = root / instance_id
    if path.is_symlink() or not path.resolve().is_relative_to(root):
        raise EngineError('Unsafe instance storage path.')
    return path


@contextmanager
def locked(name, blocking=True):
    if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,100}', name):
        raise EngineError('Invalid lock name.')
    path = Path(current_app.config['DATA_DIR']) / 'locks' / name
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        yield
    finally:
        os.close(fd)


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as out:
        json.dump(value, out, indent=2)
        out.flush()
        os.fsync(out.fileno())
    os.replace(temp, path)


def run(args, timeout=120):
    """Only called with application-built argument lists. Never a shell."""
    try:
        result = subprocess.run([str(a) for a in args], stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=timeout, check=False,
                                close_fds=True)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EngineError(f'{Path(args[0]).name}: {exc}') from exc
    if result.returncode:
        raise EngineError(f'{Path(args[0]).name}: {(result.stderr or result.stdout)[-1500:].strip()}')
    return result.stdout


def validate_url(url, hosts, public=True):
    try:
        parts = urlsplit(url)
        port = parts.port
    except (ValueError, TypeError) as exc:
        raise EngineError('Invalid HTTPS URL or port.') from exc
    if parts.scheme != 'https' or not parts.hostname or parts.username or parts.password or parts.fragment:
        raise EngineError('Only HTTPS URLs without credentials or fragments are allowed.')
    if parts.hostname.lower() not in hosts or port not in (None, 443):
        raise EngineError('URL host is not in the operator-configured allowlist (HTTPS port 443).')
    if public:
        try:
            addresses = socket.getaddrinfo(parts.hostname, 443, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise EngineError(f'Image host DNS lookup failed: {exc}') from exc
        if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses):
            raise EngineError('Image URLs must resolve to public IP addresses.')
    return url


def validate_password(password):
    if not 12 <= len(password) <= 128:
        raise EngineError('Use a password between 12 and 128 characters.')
    if '\x00' in password or '\n' in password or '\r' in password:
        raise EngineError('Passwords cannot contain NUL or line breaks.')
    return password


def ssh_key(value):
    value = value.strip()
    parts = value.split()
    if '\n' in value or len(value) > 8192 or len(parts) < 2 or parts[0] not in ('ssh-ed25519', 'ssh-rsa', 'ecdsa-sha2-nistp256'):
        raise EngineError('Supply one OpenSSH public key (ed25519, RSA, or ECDSA), without options.')
    try:
        raw = base64.b64decode(parts[1], validate=True)
        size = int.from_bytes(raw[:4], 'big')
        if size > 100 or raw[4:4 + size].decode() != parts[0] or len(raw) < 32:
            raise ValueError
    except (ValueError, UnicodeError):
        raise EngineError('Invalid OpenSSH public key encoding.')
    from cryptography.hazmat.primitives.serialization import load_ssh_public_key
    from cryptography.hazmat.primitives.asymmetric import rsa
    try:
        parsed = load_ssh_public_key(' '.join(parts[:2]).encode())
        if isinstance(parsed, rsa.RSAPublicKey) and parsed.key_size < 2048:
            raise ValueError('RSA key is too small')
    except (ValueError, TypeError) as exc:
        raise EngineError('Invalid SSH public key, or RSA key smaller than 2048 bits.') from exc
    return ' '.join(parts[:2])


def integer(value, label, minimum, maximum):
    if isinstance(value, bool) or not re.fullmatch(r'\d{1,10}', str(value or '')):
        raise EngineError(f'{label} must be a whole number.')
    number = int(value)
    if not minimum <= number <= maximum:
        raise EngineError(f'{label} must be between {minimum} and {maximum}.')
    return number


def safe_message(exc):
    # Do not include request bodies, node tokens, or guest credentials in logs.
    return str(exc)[:1800]

"""Workspace-local configuration. Secrets are never written to config.json."""
import json
import fcntl
import os
import secrets
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / '.env')
DEFAULTS = json.loads((ROOT / 'config.json').read_text())


def private_file(path, factory):
    """Atomic multi-process initialization, including the first Gunicorn startup."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'r+') as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        os.fchmod(handle.fileno(), 0o600)
        value = handle.read().strip()
        if not value:
            value = factory()
            handle.seek(0)
            handle.write(value)
            handle.truncate()
            handle.flush()
            os.fsync(handle.fileno())
        return value


def configuration():
    data = Path(os.getenv('SKVM_DATA_DIR', ROOT / 'data')).resolve()
    (ROOT / 'database').mkdir(exist_ok=True)
    secure_cookies = os.getenv('SKVM_COOKIE_SECURE', '1' if os.getenv('CODESPACES') == 'true' else '0') == '1'
    return dict(
        SECRET_KEY=os.getenv('SKVM_SECRET_KEY') or private_file(data / '.session-key', lambda: secrets.token_hex(48)),
        SQLALCHEMY_DATABASE_URI=os.getenv('SKVM_DATABASE_URL', f'sqlite:///{ROOT / "database/skvm.db"}'),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SQLALCHEMY_ENGINE_OPTIONS={'connect_args': {'timeout': 30}},
        DATA_DIR=data,
        SETTINGS_DEFAULTS=DEFAULTS,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        SESSION_COOKIE_SECURE=secure_cookies,
        PERMANENT_SESSION_LIFETIME=28800,
        REMEMBER_COOKIE_HTTPONLY=True,
        REMEMBER_COOKIE_SECURE=secure_cookies,
        MAX_CONTENT_LENGTH=256 * 1024,
        WTF_CSRF_TIME_LIMIT=7200,
        WTF_CSRF_SSL_STRICT=False,  # CSRF token still required; HTTPS is terminated by Codespaces.
        TEST_MODE=os.getenv('SKVM_TEST_MODE', '0') == '1',
        # None means automatic for normal panels, off for isolated tests/test mode.
        BOOTSTRAP_ADMIN=(None if 'SKVM_BOOTSTRAP_ADMIN' not in os.environ else os.environ['SKVM_BOOTSTRAP_ADMIN'] == '1'),
        USE_KVM=os.getenv('SKVM_USE_KVM', '0') == '1',
        ENABLE_QEMU=os.getenv('SKVM_ENABLE_QEMU', '1') == '1',
        ENABLE_DOCKER=os.getenv('SKVM_ENABLE_DOCKER', '1') == '1',
        DOCKER_STORAGE_LIMITS=os.getenv('SKVM_DOCKER_STORAGE_LIMITS', '0') == '1',
        NODE_HOSTS=[h.strip().lower() for h in os.getenv('SKVM_NODE_HOSTS', '').split(',') if h.strip()],
        NODE_TOKEN=os.getenv('SKVM_NODE_TOKEN'),
        NODE_CA_BUNDLE=os.getenv('SKVM_NODE_CA_BUNDLE'),
        NODE_AGENT=False,
        START_WORKER=False,
    )

"""Disposable browser/SSH protocol test bed. No VM or host shell is created.

The single replaced boundary is QEMU runtime discovery. The named synthetic
records exist only in this temporary DB and point at the real SSH/PTY echo
protocol fixture, never at a host SSH daemon. Production imports none of this.
"""
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from engines import EngineError
from engines.qemu_engine import QemuEngine
from extensions import db
from models import User, VPS
from services.webssh import fingerprint
from skvm import create_app
from tests.ssh_helpers import SSHProtocolServer


def main():
    with tempfile.TemporaryDirectory(prefix='skvm-webssh-browser-') as directory, SSHProtocolServer() as ssh:
        root = Path(directory)
        app = create_app({'TESTING': True, 'TEST_MODE': False, 'BOOTSTRAP_ADMIN': False,
                          'DATA_DIR': root / 'data', 'SQLALCHEMY_DATABASE_URI': f'sqlite:///{root}/test.db',
                          'SECRET_KEY': secrets.token_hex(48), 'START_WORKER': False, 'SESSION_COOKIE_SECURE': False,
                          'ENABLE_QEMU': False, 'ENABLE_DOCKER': False})
        state = {'accounts': {}, 'guest_password': ssh.password, 'private_key': ssh.private_key('test-key-passphrase'),
                 'passphrase': 'test-key-passphrase', 'fingerprint': fingerprint(ssh.key)}
        identifiers = set()
        with app.app_context():
            for project in ('webssh-desktop', 'webssh-android'):
                password = secrets.token_urlsafe(24)
                user = User(name='Isolated SSH browser tester', email=project + '@example.test', role='user')
                user.set_password(password)
                db.session.add(user)
                db.session.flush()
                ident = str(uuid.uuid4())
                identifiers.add(ident)
                db.session.add(VPS(id=ident, owner_id=user.id, name='isolated-ssh-protocol-fixture', engine='qemu',
                                   os_id='ubuntu-24.04', ram_mb=512, vcpus=1, disk_gb=8, username='guest',
                                   ssh_port=ssh.endpoint[1], runtime={}))
                state['accounts'][project] = {'email': user.email, 'password': password, 'instance': ident}
            db.session.commit()

        def fixture_endpoint(_self, spec):
            if spec['id'] not in identifiers:
                raise EngineError('Not an isolated SSH protocol fixture.')
            return ssh.endpoint
        QemuEngine.ssh_endpoint = fixture_endpoint
        destination = ROOT / 'test-results/.webssh-credentials.json'
        destination.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as handle:
            json.dump(state, handle)
        try:
            app.run(host='0.0.0.0', port=5559, debug=False, use_reloader=False, threaded=True)
        finally:
            destination.unlink(missing_ok=True)


if __name__ == '__main__':
    main()

"""Isolated browser + real SSH protocol fixture, NOT a VM/SSHX relay or demo mode.

The QEMU discovery and metrics boundaries below are deliberately replaced ONLY
in this test process. The SSH server records fixed-script stdin and emits marked
synthetic links; it never executes a shell/installer. Native acceptance is separate.
"""
import base64
import json
import os
from pathlib import Path
import re
import secrets
import sys
import tempfile
import uuid
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from engines.qemu_engine import QemuEngine
from extensions import db
from models import GuestAccess, User, VPS
from services.background import stop_background
from services.security import encrypt
from skvm import create_app
from tests.ssh_helpers import SSHProtocolServer


class ProtocolFixtureEngine:
    """Explicit browser-only state machine: never launches an engine or shell."""
    def __init__(self):
        self.states = {}

    def metrics(self, spec):
        return {'status': self.states.get(spec['id'], 'running'),
                'usage': {'pid': None, 'process_rss_mb': None,
                          'process_cpu_percent': None, 'disk_actual_bytes': None}}

    def start(self, spec, **kwargs):
        self.states[spec['id']] = 'running'
        return {'status': 'running'}

    def stop(self, spec, **kwargs):
        self.states[spec['id']] = 'stopped'
        return {'status': 'stopped'}

    force_stop = stop

    def delete(self, spec, **kwargs):
        assert self.states[spec['id']] == 'stopped'
        self.states[spec['id']] = 'missing'
        return {'status': 'deleted'}


with tempfile.TemporaryDirectory(prefix='skvm-sshx-browser-protocol-') as directory, SSHProtocolServer() as ssh:
    root = Path(directory)
    def program(script):
        if script.startswith('# SKVM_FIXED_ENROLLMENT'):
            encoded = re.search(r"key=\$\(printf '%s' '([A-Za-z0-9+/=]+)'", script)[1]
            public = base64.b64decode(encoded).decode().strip()
            ssh.extra_keys.add(base64.b64decode(public.split()[1]))
            return 0, 'SKVM_ENROLLED\n'
        mode = re.search(r"^mode='([a-z_]+)'", script, re.M)[1]
        if mode in ('stop', 'inspect_stop'):
            return 0, 'SKVM_STOPPED\n'
        ident = re.search(r"^vm='([a-f0-9-]+)'", script, re.M)[1]
        return 0, 'SKVM_RUNNING\nSKVM_SECONDS:3600\nLink: https://sshx.io/s/ui-protocol-' + ident.replace('-', '') + '#SyntheticUIKey0001\n'
    ssh.program = program
    engine = ProtocolFixtureEngine()
    with (patch.object(QemuEngine, 'ssh_endpoint', lambda self, spec: ssh.endpoint),
          patch('services.resource_monitor.engine_for', return_value=engine),
          patch('services.provisioning.engine_for', return_value=engine),
          patch('services.provisioning.capacity_check', return_value=None)):
        app = create_app({'TESTING': True, 'TEST_MODE': False, 'DATA_DIR': root / 'data',
                          'SQLALCHEMY_DATABASE_URI': f'sqlite:///{root / "panel.db"}', 'SECRET_KEY': secrets.token_hex(48),
                          'START_WORKER': True, 'BOOTSTRAP_ADMIN': False, 'SESSION_COOKIE_SECURE': False})
        state = {}
        with app.app_context():
            for project in ('sshx-desktop', 'sshx-android'):
                password = secrets.token_urlsafe(24)
                owner = User(name='Protocol fixture owner ' + project, email=project + '@example.test', role='user')
                owner.set_password(password)
                other = User(name='Other protocol user', email='other-' + project + '@example.test', role='user')
                other.set_password(password)
                db.session.add_all([owner, other])
                db.session.flush()
                instances = []
                for managed in (True, False):
                    instance = VPS(id=str(uuid.uuid4()), owner_id=owner.id,
                                   name=('managed-' if managed else 'enroll-') + project,
                                   engine='qemu', os_id='ubuntu-24.04', ram_mb=512, vcpus=1, disk_gb=8,
                                   username='guest', ssh_port=ssh.endpoint[1], runtime={'network_restricted': False})
                    db.session.add(instance)
                    db.session.flush()
                    if managed:
                        db.session.add(GuestAccess(instance_id=instance.id,
                                                   private_key_encrypted=encrypt({'private_key': ssh.private_key()})))
                    instances.append(instance.id)
                lifecycle = VPS(id=str(uuid.uuid4()), owner_id=owner.id, name='lifecycle-' + project,
                                engine='qemu', os_id='ubuntu-24.04', ram_mb=512, vcpus=1, disk_gb=8,
                                username='guest', ssh_port=ssh.endpoint[1], runtime={'network_restricted': True})
                db.session.add(lifecycle)
                db.session.flush()
                engine.states[lifecycle.id] = 'stopped'
                state[project] = {'email': owner.email, 'password': password, 'other_email': other.email,
                                  'managed_id': instances[0], 'enroll_id': instances[1], 'guest_password': ssh.password,
                                  'lifecycle_id': lifecycle.id}
            db.session.commit()
        destination = ROOT / 'test-results' / '.sshx-ui-credentials.json'
        destination.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as output:
            json.dump(state, output)
        try:
            app.run(host='127.0.0.1', port=5559, debug=False, use_reloader=False, threaded=True)
        finally:
            stop_background(app)

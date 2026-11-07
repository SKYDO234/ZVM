"""Guarded test-only WSGI factory; never used by the production launcher."""
import os
from pathlib import Path

from config import ROOT
from engines import EngineError
from engines.qemu_engine import QemuEngine
from services.security import valid_uuid
from skvm import create_app


def acceptance_app(ident, port):
    uri = os.environ.get('SKVM_DATABASE_URL', '')
    if (os.environ.get('SKVM_WEBSSH_ACCEPTANCE') != '1' or not uri.startswith('sqlite:///')
            or Path(uri.removeprefix('sqlite:///')).resolve() == ROOT / 'database/skvm.db'):
        raise RuntimeError('This SSH protocol fixture requires an explicitly disposable database.')
    valid_uuid(ident)
    port = int(port)
    if not 1024 <= port <= 65535:
        raise RuntimeError('Invalid isolated SSH fixture port.')
    app = create_app({'TESTING': True, 'START_WORKER': False, 'BOOTSTRAP_ADMIN': False,
                      'TEST_MODE': False, 'SESSION_COOKIE_SECURE': False})

    def fixture_endpoint(_self, spec):
        if spec['id'] != ident:
            raise EngineError('Unknown isolated SSH fixture.')
        return '127.0.0.1', port
    QemuEngine.ssh_endpoint = fixture_endpoint
    return app

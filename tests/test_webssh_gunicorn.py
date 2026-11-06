"""Real two-worker/gthread WebSocket acceptance against an isolated SSH fixture."""
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time

import requests
from websockets.exceptions import InvalidStatus

from tests.test_webssh import (browser_ws, connect_guest, output_until,
                               receive, ssh_server, vm)

__all__ = ['ssh_server']


def test_real_gunicorn_websocket_threads_limits_and_http_capacity(app, users, ssh_server, tmp_path):
    item = vm(users[0].id)
    ident = item.id
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0))
        port = reserve.getsockname()[1]
    environment = {**os.environ, 'SKVM_DATABASE_URL': app.config['SQLALCHEMY_DATABASE_URI'],
                   'SKVM_DATA_DIR': str(app.config['DATA_DIR']), 'SKVM_SECRET_KEY': app.secret_key,
                   'SKVM_BOOTSTRAP_ADMIN': '0', 'SKVM_TEST_MODE': '0', 'SKVM_START_WORKER': '0',
                   'SKVM_COOKIE_SECURE': '0', 'SKVM_WEBSSH_ACCEPTANCE': '1'}
    log_path = tmp_path / 'gunicorn.log'
    with log_path.open('w+') as log:
        process = subprocess.Popen([sys.executable, '-m', 'gunicorn', '--config', str(Path(__file__).parents[1] / 'gunicorn.conf.py'),
                                    '--bind', f'127.0.0.1:{port}', '--log-level', 'warning',
                                    f'tests.webssh_gunicorn_app:acceptance_app("{ident}",{ssh_server.endpoint[1]})'],
                                   env=environment, stdout=log, stderr=log)
        http = requests.Session()
        http.trust_env = False
        http.headers['User-Agent'] = 'SKVM-gthread-WebSSH-acceptance'
        base = f'http://127.0.0.1:{port}'
        sockets = []
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                assert process.poll() is None, log_path.read_text()[-4000:]
                try:
                    response = http.get(base + '/login', timeout=1)
                    if response.status_code == 200:
                        break
                except requests.RequestException:
                    pass
                time.sleep(0.05)
            else:
                raise AssertionError('Disposable Gunicorn did not start.')
            csrf = re.search(r'name="csrf-token" content="([^"]+)"', response.text)[1]
            response = http.post(base + '/login', data={'csrf_token': csrf, 'email': users[0].email,
                                 'password': 'Test-only-password-123!'}, timeout=5)
            assert response.status_code == 200 and response.url.endswith('/dashboard')
            html = http.get(base + '/webssh/' + ident, timeout=5).text
            csrf = re.search(r'name="csrf-token" content="([^"]+)"', html)[1]
            panel = {'http': http, 'base': base, 'id': ident, 'csrf': csrf}
            for _ in range(2):
                ws = browser_ws(panel)
                sockets.append(ws)
                assert connect_guest(ws, panel, ssh_server)['type'] == 'connected'
                output_until(ws, 'UTF-8 stream')
            # This is enforced in shared SQLite/file locks, not worker-local maps.
            try:
                extra = browser_ws(panel)
            except InvalidStatus as error:
                assert error.response.status_code == 409
            else:
                extra.close()
                raise AssertionError('Two-worker session admission was bypassed.')
            assert http.get(base + '/dashboard', timeout=5).status_code == 200
            assert http.get(base + '/api/metrics', timeout=5).status_code == 200
            # One browser logout revokes sockets regardless of which worker owns them.
            assert http.post(base + '/logout', data={'csrf_token': csrf}, timeout=5).status_code == 200
            for ws in sockets:
                assert receive(ws, 'error')['code'] == 'session_revoked'
        finally:
            for ws in sockets:
                ws.close()
            http.close()
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
    assert 'Traceback' not in log_path.read_text(), log_path.read_text()[-5000:]

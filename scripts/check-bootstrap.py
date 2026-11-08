#!/usr/bin/env python3
"""Destructive password-rotation acceptance ONLY against an explicitly disposable DB."""
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
from urllib.parse import urlsplit
import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from config import configuration


def main():
    config = configuration()
    uri = os.getenv('SKVM_DATABASE_URL', '')
    if os.getenv('SKVM_BOOTSTRAP_ACCEPTANCE') != '1' or not uri.startswith('sqlite:///'):
        raise RuntimeError('Refusing to rotate a persistent account. Set SKVM_BOOTSTRAP_ACCEPTANCE=1 and an explicit disposable SQLite URL.')
    database = Path(uri.removeprefix('sqlite:///')).resolve()
    if database == ROOT / 'database/skvm.db' or not database.is_file():
        raise RuntimeError('Acceptance requires an existing NON-production, disposable SQLite database.')
    assert config['TEST_MODE'] is False, 'Acceptance must exercise the real application, not test mode.'
    base = f"http://127.0.0.1:{int(os.getenv('SKVM_PORT', '31120'))}"
    first, other, later = (requests.Session() for _ in range(3))
    for session in (first, other, later):
        session.trust_env = False

    def token(session, path):
        response = session.get(base + path, timeout=10)
        response.raise_for_status()
        found = re.search(r'name="csrf-token" content="([^"]+)"', response.text)
        assert found, 'Missing actual CSRF token in rendered page.'
        return found[1]

    def sign_in(session, password):
        return session.post(base + '/login', data={'email': 'admin', 'password': password,
                            'csrf_token': token(session, '/login')}, allow_redirects=False, timeout=10)

    for session in (first, other):
        response = sign_in(session, 'admin123')
        assert response.status_code == 302 and urlsplit(response.headers['Location']).path == '/dashboard'
    for path in ('/dashboard', '/admin', '/admin/users', '/admin/instances', '/admin/plans', '/admin/nodes',
                 '/admin/images', '/admin/configuration', '/admin/jobs', '/admin/recovery', '/admin/audit',
                 '/vps/create', '/vps', '/user', '/settings', '/profile', '/docs'):
        response = first.get(base + path, allow_redirects=False, timeout=10)
        assert response.status_code == 200, (path, response.status_code)
        assert 'data-initial-password-reminder' in response.text, path
    response = first.get(base + '/api/metrics', timeout=10)
    assert response.status_code == 200 and response.json()['totals']['count'] == 0
    assert first.get(base + '/api/activity', timeout=10).status_code == 200
    response = first.post(base + '/vps/create', data={'csrf_token': token(first, '/vps/create'), 'name': 'invalid-without-engine'}, allow_redirects=False, timeout=10)
    assert response.status_code == 200  # Real validation error, never a bounce to Profile.
    response = first.post(base + '/admin/plans', data={'csrf_token': token(first, '/admin/plans'), 'name': 'Installer acceptance plan',
                          'max_instances': '2', 'ram_mb': '1024', 'vcpus': '1', 'disk_gb': '16'}, allow_redirects=False, timeout=10)
    assert response.status_code == 302 and urlsplit(response.headers.get('Location', '')).path == '/admin/plans', (
        'plan creation must return to its dedicated page', response.status_code, response.headers.get('Location'))
    assert 'Installer acceptance plan' in first.get(base + '/admin/plans', timeout=10).text
    password = 'Acceptance-' + secrets.token_urlsafe(24)
    response = first.post(base + '/profile', data={'csrf_token': token(first, '/profile'), 'name': 'Installer acceptance',
                          'current_password': 'admin123', 'new_password': password}, allow_redirects=False, timeout=10)
    assert response.status_code == 302, response.status_code
    admin = first.get(base + '/admin', timeout=10)
    assert admin.status_code == 200 and 'data-initial-password-reminder' not in admin.text
    assert first.get(base + '/api/metrics', timeout=10).json()['totals']['count'] == 0
    assert other.get(base + '/api/metrics', timeout=10).status_code == 401
    # Real Gunicorn restart must preserve the private replacement, not re-seed admin123.
    subprocess.run([sys.executable, str(ROOT / 'scripts/serve-panel.py'), '--stop'], check=True, timeout=40)
    subprocess.run([sys.executable, str(ROOT / 'scripts/serve-panel.py'), '--background'], check=True, timeout=40)
    assert sign_in(later, 'admin123').status_code == 200
    response = sign_in(later, password)
    assert response.status_code == 302 and urlsplit(response.headers['Location']).path == '/dashboard'
    assert later.get(base + '/admin', timeout=10).status_code == 200
    print('PASS: actual HTTP default login, working authorized navigation, working API/admin forms, password replacement, session revocation and restart persistence. No guest was fabricated.')


if __name__ == '__main__':
    try:
        main()
    except (AssertionError, RuntimeError, requests.RequestException, subprocess.SubprocessError) as exc:
        print(f'Bootstrap acceptance FAILED: {exc}', file=sys.stderr)
        raise SystemExit(1)

"""Protocol, target selection, RBAC, CSRF, trust and long-lived-session security."""
from datetime import timedelta
import json
import re
import threading
import time
import uuid

import paramiko
import pytest
import requests
from websockets.exceptions import InvalidStatus
from websockets.sync.client import connect
from werkzeug.serving import make_server

from engines import EngineError
from engines.qemu_engine import QemuEngine
from extensions import db
from models import Audit, SSHHostKey, SSHLease, VPS
from models.user import utcnow
from services import webssh
from services.node_webssh import WIRE_LOGGER
from tests.conftest import signin
from tests.ssh_helpers import SSHProtocolServer


def vm(owner, **changes):
    data = dict(id=str(uuid.uuid4()), owner_id=owner, name='ssh-protocol-fixture', engine='qemu',
                os_id='ubuntu-24.04', ram_mb=512, vcpus=1, disk_gb=8,
                username='guest', ssh_port=22000, runtime={})
    data.update(changes)
    item = VPS(**data)
    db.session.add(item)
    db.session.commit()
    return item


def first(password, **changes):
    return {'type': 'connect', 'credentials': {'method': 'password', 'password': password}, 'cols': 90, 'rows': 28, **changes}


@pytest.mark.parametrize('raw', [b'{}', '[]', '{', '{}', '{"type":4}', 'x' * (webssh.MAX_MESSAGE + 1)])
def test_rejects_invalid_or_oversized_protocol(raw):
    with pytest.raises(webssh.SSHError):
        webssh.message(raw)


@pytest.mark.parametrize('changes', [
    {'host': '127.0.0.1'}, {'port': 22}, {'username': 'root'}, {'command': 'id'},
    {'cols': True}, {'rows': 0}, {'cols': 501}, {'rows': 201},
    {'credentials': {'method': 'password', 'password': ''}},
    {'credentials': {'method': 'key', 'private_key': 'k' * 65537}},
    {'credentials': {'method': 'agent'}},
])
def test_connection_cannot_choose_an_arbitrary_target_or_unbounded_auth(changes):
    with pytest.raises(webssh.SSHError):
        webssh.connection_message(first('test-only', **changes))


@pytest.mark.parametrize('changes', [{'engine': 'docker'}, {'username': 'root'}, {'username': None}, {'ssh_port': 22}, {'ssh_port': True}])
def test_target_spec_fails_closed(app, users, changes):
    item = vm(users[0].id, **changes)
    with pytest.raises(webssh.SSHError):
        webssh.validate_spec(item.spec())


def test_page_requires_login_ownership_and_has_no_public_bot_tokens(app, client, users):
    item = vm(users[1].id)
    assert client.get('/webssh').status_code == 302
    signin(client)
    assert client.get('/webssh/' + item.id).status_code == 404
    empty = client.get('/webssh')
    assert empty.status_code == 200 and b'No managed instances' in empty.data
    operator = app.test_client()
    signin(operator, 'operator@example.test')
    result = operator.get('/webssh/' + item.id)
    assert result.status_code == 200 and b'not running' in result.data
    assert b'__TOKEN__' not in result.data and b'__UNLOCK_KEY__' not in result.data
    assert b'cdn.jsdelivr' not in result.data and b'fonts.googleapis' not in result.data
    assert b'/static/vendor/xterm.js' in result.data
    assert f'data-socket-url="/api/webssh/{item.id}"'.encode() in result.data


def test_cross_worker_lease_admission_expiry_and_rate_limits(app):
    leases = [webssh.admit('user:1', str(uuid.uuid4())) for _ in range(2)]
    with pytest.raises(webssh.SSHError, match='session limit'):
        webssh.admit('user:1', str(uuid.uuid4()))
    row = db.session.get(SSHLease, leases[0])
    row.expires_at = utcnow() - timedelta(seconds=1)
    db.session.commit()
    third = webssh.admit('user:1', str(uuid.uuid4()))
    for lease in (leases[1], third):
        webssh.release(lease)
    # Failed/released attempts still count; opening/closing isn't a brute-force bypass.
    for _ in range(7):
        webssh.release(webssh.admit('user:1', str(uuid.uuid4())))
    with pytest.raises(webssh.SSHError, match='Too many'):
        webssh.admit('user:1', str(uuid.uuid4()))


@pytest.fixture
def ssh_server():
    with SSHProtocolServer() as server:
        yield server


@pytest.fixture
def live_panel(app, users, ssh_server, monkeypatch):
    item = vm(users[0].id)
    ident = item.id
    # Deliberately replace ONLY runtime discovery. This fixture proves real SSH
    # protocol/PTY integration, not that a QEMU guest exists or has booted.
    def endpoint(_self, spec):
        if spec['id'] != ident:
            raise EngineError('Unknown test fixture endpoint.')
        return ssh_server.endpoint
    monkeypatch.setattr(QemuEngine, 'ssh_endpoint', endpoint)
    server = make_server('127.0.0.1', 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f'http://127.0.0.1:{server.server_port}'
    http = requests.Session()
    http.trust_env = False
    http.headers['User-Agent'] = 'SKVM-isolated-WebSSH-test'
    token = re.search(r'name="csrf-token" content="([^"]+)"', http.get(base + '/login', timeout=5).text)[1]
    result = http.post(base + '/login', data={'email': users[0].email, 'password': 'Test-only-password-123!', 'csrf_token': token}, timeout=5)
    assert result.status_code == 200 and result.url.endswith('/dashboard')
    dashboard_cookie = '; '.join(f'{key}={value}' for key, value in http.cookies.items())
    html = http.get(base + '/webssh/' + ident, timeout=5).text
    csrf = re.search(r'name="csrf-token" content="([^"]+)"', html)[1]
    state = {'http': http, 'base': base, 'id': ident, 'csrf': csrf, 'owner': users[0].id, 'dashboard_cookie': dashboard_cookie}
    try:
        yield state
    finally:
        http.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def browser_ws(panel, ident=None, origin=None, cookies=True, cookie_header=None):
    headers = {'Cookie': '; '.join(f'{key}={value}' for key, value in panel['http'].cookies.items())} if cookies else {}
    if cookie_header is not None:
        headers['Cookie'] = cookie_header
    return connect(panel['base'].replace('http:', 'ws:') + '/api/webssh/' + (ident or panel['id']),
                   origin=panel['base'] if origin is None else origin,
                   additional_headers=headers, user_agent_header=panel['http'].headers['User-Agent'],
                   proxy=None, compression=None, close_timeout=1, ping_interval=None, logger=WIRE_LOGGER)


def receive(ws, kind=None, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        data = json.loads(ws.recv(timeout=max(0.1, deadline - time.monotonic())))
        if kind is None or data['type'] == kind:
            return data
    raise AssertionError('WebSSH event not received: ' + str(kind))


def connect_guest(ws, panel, ssh_server, credentials=None):
    frame = first(ssh_server.password, csrf_token=panel['csrf'])
    if credentials:
        frame['credentials'] = credentials
    ws.send(json.dumps(frame))
    event = receive(ws)
    if event['type'] == 'host_key':
        assert event['fingerprint'] == webssh.fingerprint(ssh_server.key)
        ws.send(json.dumps({'type': 'trust', 'fingerprint': event['fingerprint'], 'accept': True}))
        event = receive(ws)
    return event


def output_until(ws, text):
    output = ''
    for _ in range(80):
        data = receive(ws)
        if data['type'] == 'error':
            raise AssertionError(data)
        if data['type'] == 'output':
            output += data['data']
        if text in output:
            return output
    raise AssertionError('SSH output not received: ' + repr(output))


def test_real_ssh_auth_pty_resize_unicode_stream_and_disconnect(app, live_panel, ssh_server):
    panel = live_panel
    with browser_ws(panel) as ws:
        ws.send(json.dumps(first(ssh_server.password, csrf_token=panel['csrf'])))
        event = receive(ws, 'host_key')
        assert ssh_server.auth_calls == []  # No password before explicit trust.
        ws.send(json.dumps({'type': 'trust', 'fingerprint': event['fingerprint'], 'accept': True}))
        assert receive(ws, 'connected')['username'] == 'guest'
        assert ssh_server.sizes[0] == (90, 28)
        greeting = output_until(ws, 'UTF-8 stream')
        assert '€' in greeting and '\ufffd' not in greeting
        ws.send(json.dumps({'type': 'resize', 'cols': 120, 'rows': 35}))
        ws.send(json.dumps({'type': 'input', 'data': '__fixture_size__\r'}))
        assert '120x35' in output_until(ws, 'PTY dimensions:')
        ws.send(json.dumps({'type': 'input', 'data': 'real SSH bytes 界\r'}))
        assert 'real SSH bytes 界' in output_until(ws, 'real SSH bytes 界')
        ws.send(json.dumps({'type': 'ping', 'nonce': 'measured-rtt'}))
        assert receive(ws, 'pong')['nonce'] == 'measured-rtt'
        ws.send(json.dumps({'type': 'disconnect'}))
        assert receive(ws, 'disconnected')
    with app.app_context():
        db.session.remove()
        assert db.session.get(SSHHostKey, panel['id']).fingerprint == webssh.fingerprint(ssh_server.key)
        wait_for_no_leases()


@pytest.mark.parametrize('failure', ['csrf', 'host', 'password'])
def test_connect_security_failures_never_open_a_guest_shell(live_panel, ssh_server, failure):
    panel = live_panel
    with browser_ws(panel) as ws:
        frame = first(ssh_server.password, csrf_token=panel['csrf'])
        if failure == 'csrf':
            frame['csrf_token'] = 'invalid-security-token'
        if failure == 'host':
            frame['host'] = '127.0.0.1'
        if failure == 'password':
            frame['credentials']['password'] = 'incorrect-test-guest-password'
        ws.send(json.dumps(frame))
        event = receive(ws)
        if failure == 'password':
            assert event['type'] == 'host_key' and not ssh_server.auth_calls
            ws.send(json.dumps({'type': 'trust', 'fingerprint': event['fingerprint'], 'accept': True}))
            event = receive(ws)
        assert event['type'] == 'error'
        assert event['code'] == {'csrf': 'csrf_failed', 'host': 'invalid_target', 'password': 'authentication_failed'}[failure]
        assert not ssh_server.sizes
        if failure != 'password':
            assert not ssh_server.transports and not ssh_server.auth_calls


@pytest.mark.parametrize('origin', ['https://evil.example', 'null', 'http://127.0.0.1:1'])
def test_cross_origin_websocket_handshakes_are_rejected(live_panel, ssh_server, origin):
    with pytest.raises(InvalidStatus) as error:
        browser_ws(live_panel, origin=origin)
    assert error.value.response.status_code == 403
    assert not ssh_server.transports


def test_anonymous_nonowner_and_absent_origin_cannot_upgrade(app, users, live_panel, ssh_server):
    with pytest.raises(InvalidStatus) as error:
        browser_ws(live_panel, cookies=False)
    assert error.value.response.status_code == 401
    other = vm(users[1].id, name='another-users-test-fixture')
    with pytest.raises(InvalidStatus) as error:
        browser_ws(live_panel, ident=other.id)
    assert error.value.response.status_code == 404
    with pytest.raises(InvalidStatus) as error:
        browser_ws(live_panel, origin='')
    assert error.value.response.status_code == 403
    assert not ssh_server.transports


def test_changed_fingerprint_needs_separate_confirmation(app, live_panel, ssh_server):
    old = webssh.fingerprint(paramiko.RSAKey.generate(2048))
    db.session.add(SSHHostKey(instance_id=live_panel['id'], fingerprint=old, algorithm='ssh-rsa'))
    db.session.commit()
    with browser_ws(live_panel) as ws:
        ws.send(json.dumps(first(ssh_server.password, csrf_token=live_panel['csrf'])))
        event = receive(ws)
        assert event['type'] == 'host_key' and event['changed'] and event['previous'] == old
        assert not ssh_server.auth_calls
        ws.send(json.dumps({'type': 'trust', 'fingerprint': event['fingerprint'], 'accept': True}))
        assert receive(ws)['code'] == 'host_key_changed'
    assert not ssh_server.auth_calls
    db.session.expire_all()
    assert db.session.get(SSHHostKey, live_panel['id']).fingerprint == old


@pytest.mark.parametrize('encrypted', [False, True])
def test_private_key_authentication_over_real_ssh(live_panel, ssh_server, encrypted):
    phrase = 'disposable-key-passphrase' if encrypted else ''
    credentials = {'method': 'key', 'private_key': ssh_server.private_key(phrase or None), 'passphrase': phrase}
    with browser_ws(live_panel) as ws:
        assert connect_guest(ws, live_panel, ssh_server, credentials)['type'] == 'connected'
        assert ssh_server.auth_calls and ssh_server.auth_calls[-1] == ('key', 'guest')
        ws.send(json.dumps({'type': 'disconnect'}))
        receive(ws, 'disconnected')


@pytest.mark.parametrize('revocation', ['logout', 'password', 'disable', 'suspend', 'delete'])
def test_open_sockets_close_after_authority_is_revoked(app, users, live_panel, ssh_server, revocation):
    panel = live_panel
    with browser_ws(panel) as ws:
        assert connect_guest(ws, panel, ssh_server)['type'] == 'connected'
        if revocation == 'logout':
            assert panel['http'].post(panel['base'] + '/logout', data={'csrf_token': panel['csrf']}, timeout=5).status_code == 200
        else:
            db.session.expire_all()
            if revocation in ('password', 'disable'):
                user = db.session.get(type(users[0]), panel['owner'])
                if revocation == 'password':
                    user.set_password('Changed-only-in-disposable-test-123!')
                    user.session_version += 1
                else:
                    user.enabled = False
            else:
                item = db.session.get(VPS, panel['id'])
                if revocation == 'delete':
                    db.session.delete(item)
                else:
                    item.suspended = True
            db.session.commit()
        event = receive(ws, 'error')
        assert event['code'] in ('session_revoked', 'suspended', 'access_revoked')
        # Cleanup closes the SSH channel as well, not just the UI socket.
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and any(t.is_active() for t in ssh_server.transports):
            time.sleep(0.02)
        assert not any(t.is_active() for t in ssh_server.transports)


def test_password_rotation_during_upgrade_cannot_refresh_a_stale_socket(app, users, live_panel, ssh_server):
    with browser_ws(live_panel) as ws:
        db.session.expire_all()
        users[0].session_version += 1
        db.session.commit()
        ws.send(json.dumps(first(ssh_server.password, csrf_token=live_panel['csrf'])))
        assert receive(ws, 'error')['code'] == 'session_revoked'
    assert not ssh_server.auth_calls


def test_credentials_and_terminal_input_are_not_persisted_or_audited(app, live_panel, ssh_server, caplog):
    marker = 'sensitive-test-input-' + uuid.uuid4().hex
    with browser_ws(live_panel) as ws:
        assert connect_guest(ws, live_panel, ssh_server)['type'] == 'connected'
        ws.send(json.dumps({'type': 'input', 'data': marker + '\r'}))
        output_until(ws, marker)
        ws.send(json.dumps({'type': 'disconnect'}))
        receive(ws, 'disconnected')
    db.session.expire_all()
    logs = ' '.join(row.message for row in db.session.scalars(db.select(Audit)))
    assert marker not in logs and ssh_server.password not in logs
    assert marker not in caplog.text and ssh_server.password not in caplog.text
    assert db.session.get(SSHHostKey, live_panel['id'])
    path = app.config['SQLALCHEMY_DATABASE_URI'].removeprefix('sqlite:///')
    from pathlib import Path
    for file in Path(path).parent.glob('test.db*'):
        contents = file.read_bytes()
        assert marker.encode() not in contents and ssh_server.password.encode() not in contents


def test_eof_and_oversized_terminal_input_clean_up(live_panel, ssh_server):
    with browser_ws(live_panel) as ws:
        assert connect_guest(ws, live_panel, ssh_server)['type'] == 'connected'
        ws.send(json.dumps({'type': 'input', 'data': 'x' * (webssh.MAX_INPUT + 1)}))
        assert receive(ws, 'error')['code'] == 'invalid_message'
    with browser_ws(live_panel) as ws:
        assert connect_guest(ws, live_panel, ssh_server)['type'] == 'connected'
        ws.send(json.dumps({'type': 'input', 'data': '\u0004'}))
        assert receive(ws, 'disconnected')


def test_guest_idle_timeout_is_not_kept_alive_by_transport_probes(app, live_panel, ssh_server):
    app.config['WEBSSH_IDLE_SECONDS'] = 0.2
    with browser_ws(live_panel) as ws:
        assert connect_guest(ws, live_panel, ssh_server)['type'] == 'connected'
        ws.send(json.dumps({'type': 'ping', 'nonce': 'not-user-activity'}))
        assert receive(ws, 'error')['code'] == 'session_expired'



def wait_for_no_leases():
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        db.session.rollback()
        if db.session.scalar(db.select(db.func.count()).select_from(SSHLease)) == 0:
            return
        time.sleep(0.02)
    raise AssertionError('WebSSH leases were not released after socket cleanup.')


def test_pending_input_is_bounded_during_stalled_guest_auth(app, live_panel, ssh_server):
    from websockets.exceptions import ConnectionClosed
    ssh_server.auth_delay = 1
    db.session.add(SSHHostKey(instance_id=live_panel['id'], fingerprint=webssh.fingerprint(ssh_server.key), algorithm='ssh-rsa'))
    db.session.commit()
    with browser_ws(live_panel) as ws:
        ws.send(json.dumps(first(ssh_server.password, csrf_token=live_panel['csrf'])))
        deadline = time.monotonic() + 5
        while not ssh_server.auth_calls and time.monotonic() < deadline:
            time.sleep(0.01)
        assert ssh_server.auth_calls
        # The main request is blocked in real SSH authentication here. A mere
        # per-message/rate limit in its I/O loop would not bound queued frames.
        try:
            for index in range(80):
                ws.send(json.dumps({'type': 'ping', 'nonce': str(index)}))
            ws.recv(timeout=5)
        except ConnectionClosed as error:
            assert error.rcvd is not None and error.rcvd.code == 1009
        else:
            raise AssertionError('Unbounded pending messages were accepted.')
    wait_for_no_leases()
    assert not ssh_server.sizes  # Never opened a shell after the client flooded.


@pytest.mark.parametrize('failure', ['host_key_trusted', 'connected'])
def test_audit_database_failure_closes_guest_and_releases_lease(app, live_panel, ssh_server, monkeypatch, failure):
    from sqlalchemy.exc import OperationalError
    import routes.webssh as routes
    original = routes.record
    def unavailable(action, user_id, ident):
        if action == failure:
            raise OperationalError('audit storage unavailable', {}, Exception('disposable failure'))
        original(action, user_id, ident)
    monkeypatch.setattr(routes, 'record', unavailable)
    with browser_ws(live_panel) as ws:
        event = connect_guest(ws, live_panel, ssh_server)
        assert event['type'] == 'error' and event['code'] == 'service_unavailable'
    wait_for_no_leases()
    deadline = time.monotonic() + 3
    while any(t.is_active() for t in ssh_server.transports) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert all(not t.is_active() for t in ssh_server.transports)
    assert bool(ssh_server.sizes) is (failure == 'connected')
    if failure == 'host_key_trusted':
        assert ssh_server.auth_calls == []



def test_delayed_dashboard_cookie_refresh_does_not_break_webssh(live_panel, ssh_server):
    # Deterministically replay the cookie from before WebSSH rendered, as an
    # in-flight dashboard metrics response can do after page navigation.
    with browser_ws(live_panel, cookie_header=live_panel['dashboard_cookie']) as ws:
        assert connect_guest(ws, live_panel, ssh_server)['type'] == 'connected'
        ws.send(json.dumps({'type': 'disconnect'}))
        assert receive(ws, 'disconnected')
    wait_for_no_leases()


def test_webssh_reuses_existing_session_seed_without_cookie_schema_change(app, client, users):
    from services.webssh_access import browser_session
    signin(client)
    client.get('/dashboard')
    with client.session_transaction() as session:
        before = dict(session)
    client.get('/webssh')
    with client.session_transaction() as session:
        assert dict(session) == before
        assert 'webssh_session' not in session
    with app.test_request_context('/'):
        from flask import session
        assert browser_session() is None
        tag = browser_session(create=True)
        assert len(tag) == 64 and browser_session() == tag
        session['webssh_session'] = 'preserved-rolling-update-binding'
        assert browser_session() != tag

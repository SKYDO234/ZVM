"""Real TLS -> agent WebSocket -> SSH PTY, not a remote OS/VM deployment.

Only DNS/TCP routing and QEMU endpoint discovery are replaced. TLS certificate
and hostname validation, bearer auth, both WebSockets, SSH and PTY I/O are real.
"""
import json
import socket
import threading

import pytest
import urllib3.connection
from websockets.exceptions import InvalidStatus
from werkzeug.serving import make_server

from engines import EngineError
from extensions import db
from models import AgentInstance, Node, VPS
from services import node_webssh, webssh
from services.security import encrypt
from skvm import create_app
from tests.test_node_tls import certificates
from tests.test_webssh import (browser_ws, connect_guest, first, live_panel,
                               output_until, receive, ssh_server, wait_for_no_leases)

# Register the imported disposable SSH/live panel fixtures in this module.
__all__ = ['live_panel', 'ssh_server']
TOKEN = 'isolated-node-token-no-production-use-0123456789'


@pytest.fixture
def tls_node(app, live_panel, ssh_server, tmp_path, monkeypatch):
    panel = live_panel
    spec = db.session.get(VPS, panel['id']).spec()
    agent = create_app({'TESTING': True, 'NODE_AGENT': True, 'NODE_TOKEN': TOKEN,
                        'DATA_DIR': tmp_path / 'relay-agent', 'SQLALCHEMY_DATABASE_URI': f'sqlite:///{tmp_path}/relay-agent.db',
                        'TEST_MODE': False, 'START_WORKER': False, 'ENABLE_QEMU': False, 'ENABLE_DOCKER': False})
    with agent.app_context():
        db.session.add(AgentInstance(id=spec['id'], spec=spec))
        db.session.commit()
    ca, cert, key = certificates(tmp_path)
    server = make_server('127.0.0.1', 0, agent, threaded=True, ssl_context=(str(cert), str(key)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    original_dial = socket.create_connection
    original_https = urllib3.connection.HTTPSConnection._new_conn
    dialed = []

    def dial(address, *args, **kwargs):
        if address[0] in ('node.test', 'wrong-node.test'):
            dialed.append(address[0])
            address = ('127.0.0.1', server.server_port)
        return original_dial(address, *args, **kwargs)

    def http_dial(connection):
        if connection.host in ('node.test', 'wrong-node.test'):
            return original_dial(('127.0.0.1', server.server_port), timeout=connection.timeout)
        return original_https(connection)

    monkeypatch.setattr(socket, 'create_connection', dial)
    monkeypatch.setattr(urllib3.connection.HTTPSConnection, '_new_conn', http_dial)
    app.config.update(NODE_HOSTS=['node.test', 'wrong-node.test'], NODE_CA_BUNDLE=str(ca))
    node = Node(name='isolated-tls-ssh-fixture', url='https://node.test', token_encrypted=encrypt(TOKEN))
    db.session.add(node)
    db.session.flush()
    item = db.session.get(VPS, spec['id'])
    item.node_id = node.id
    db.session.commit()
    try:
        yield {'node': node, 'agent': agent, 'spec': spec, 'panel': panel, 'dialed': dialed}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        with agent.app_context():
            db.session.remove()
            db.engine.dispose()


def test_real_tls_agent_relay_ssh_auth_resize_and_input(app, tls_node, ssh_server):
    panel = tls_node['panel']
    with browser_ws(panel) as ws:
        assert connect_guest(ws, panel, ssh_server)['type'] == 'connected'
        output_until(ws, 'UTF-8 stream')
        ws.send(json.dumps({'type': 'resize', 'cols': 101, 'rows': 39}))
        ws.send(json.dumps({'type': 'input', 'data': '__fixture_size__\r'}))
        assert '101x39' in output_until(ws, 'PTY dimensions:')
        ws.send(json.dumps({'type': 'ping', 'nonce': 'relay-round-trip'}))
        assert receive(ws, 'pong')['nonce'] == 'relay-round-trip'
        ws.send(json.dumps({'type': 'disconnect'}))
        assert receive(ws, 'disconnected')
    assert tls_node['dialed'] == ['node.test']
    with tls_node['agent'].app_context():
        assert db.session.get(AgentInstance, panel['id'])
        wait_for_no_leases()


@pytest.mark.parametrize('failure', ['ca', 'hostname', 'bearer', 'allowlist'])
def test_node_wss_rejects_bad_tls_auth_and_nonallowlisted_origins(app, tls_node, ssh_server, failure):
    node = tls_node['node']
    if failure == 'ca':
        app.config['NODE_CA_BUNDLE'] = None
    elif failure == 'hostname':
        node.url = 'https://wrong-node.test'
    elif failure == 'bearer':
        node.token_encrypted = encrypt('invalid-disposable-node-token-0123456789')
    else:
        app.config['NODE_HOSTS'] = []
    with pytest.raises(EngineError):
        node_webssh.open_stream(node, tls_node['spec']['id'])
    assert not ssh_server.transports  # No SSH/host-local fallback on any failure.


def test_agent_refuses_browser_origin_and_mismatched_target(app, tls_node, ssh_server):
    from websockets.sync.client import connect
    from services.node_webssh import WIRE_LOGGER
    import ssl
    context = ssl.create_default_context(cafile=app.config['NODE_CA_BUNDLE'])
    uri = 'wss://node.test/v1/instances/' + tls_node['spec']['id'] + '/webssh'
    with pytest.raises(InvalidStatus) as error:
        connect(uri, ssl=context, proxy=None, origin='https://node.test', additional_headers={'Authorization': 'Bearer ' + TOKEN}, logger=WIRE_LOGGER)
    assert error.value.response.status_code == 403
    with node_webssh.open_stream(tls_node['node'], tls_node['spec']['id']) as peer:
        frame = first(ssh_server.password)
        frame['target'] = node_webssh.target(tls_node['spec']) | {'username': 'root'}
        peer.send(json.dumps(frame))
        assert receive(peer)['code'] == 'target_changed'
    assert not ssh_server.auth_calls and not ssh_server.transports


def test_disabling_remote_node_revokes_an_open_relay(app, tls_node, ssh_server):
    with browser_ws(tls_node['panel']) as ws:
        assert connect_guest(ws, tls_node['panel'], ssh_server)['type'] == 'connected'
        node = db.session.get(Node, tls_node['node'].id)
        node.enabled = False
        db.session.commit()
        assert receive(ws, 'error')['code'] == 'node_changed'


def test_node_errors_cannot_leak_bearers_passwords_or_identity(app, tls_node):
    secret = TOKEN + ' guest-password-must-not-be-echoed'
    with pytest.raises(webssh.SSHError) as error:
        node_webssh.remote_message({'type': 'error', 'code': 'authentication_failed', 'message': secret}, tls_node['spec'])
    assert error.value.code == 'authentication_failed' and secret not in str(error.value)
    with pytest.raises(webssh.SSHError):
        node_webssh.remote_message({'type': 'connected', 'username': 'root', 'fingerprint': 'SHA256:' + 'A' * 43}, tls_node['spec'])


def test_node_wss_does_not_follow_authenticated_redirects(app, tls_node, ssh_server):
    from flask import redirect, request
    agent = tls_node['agent']
    # A real HTTP redirect at the TLS handshake boundary, not a mocked client.
    @agent.before_request
    def reject_with_redirect():
        if request.path.endswith('/webssh'):
            return redirect('https://never-follow-this.invalid/webssh', code=302)
    with pytest.raises(webssh.SSHError, match='could not be opened'):
        node_webssh.open_stream(tls_node['node'], tls_node['spec']['id'])
    assert tls_node['dialed'] == ['node.test']
    assert not ssh_server.transports

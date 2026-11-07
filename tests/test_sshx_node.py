"""Real HTTPS + bearer + SSH protocols; explicit endpoint fixture, NOT a VM/relay."""
import socket
import threading
import uuid
from unittest.mock import Mock

import pytest
import urllib3.connection
from werkzeug.serving import make_server

from engines import EngineError, UncertainError
from engines.node_engine import NodeEngine
from engines.qemu_engine import QemuEngine
from extensions import db
from models import AgentInstance, AgentOperation, Node
from services import sshx
from services.guest_access import target
from services.guest_ssh import fingerprint
from services.security import encrypt
from tests.ssh_helpers import SSHProtocolServer
from tests.test_node import agent_app
from tests.test_node_tls import certificates

TOKEN = 'test-only-node-token-at-least-32-chars'
LINK = 'https://sshx.io/s/tls-protocol-fixture#SyntheticKey0001'


@pytest.fixture
def tls_guest(app, tmp_path, monkeypatch):
    agent = agent_app(tmp_path)
    agent.config['TEST_MODE'] = False
    ssh = SSHProtocolServer(lambda script: (0, 'SKVM_RUNNING\nSKVM_SECONDS:3600\nLink: ' + LINK + '\n'))
    spec = {'id': str(uuid.uuid4()), 'owner_id': 1, 'name': 'tls-protocol-only', 'engine': 'qemu',
            'os_id': 'ubuntu-24.04', 'ram_mb': 512, 'vcpus': 1, 'disk_gb': 8, 'username': 'guest',
            'ssh_port': ssh.endpoint[1], 'runtime': {'network_restricted': False}}
    with agent.app_context():
        db.session.add(AgentInstance(id=spec['id'], spec=spec))
        db.session.commit()
    # This is the sole VM boundary replacement. KEX, auth, exec and HTTPS are real.
    endpoint = Mock(return_value=ssh.endpoint)
    monkeypatch.setattr(QemuEngine, 'ssh_endpoint', endpoint)
    ca, cert, key = certificates(tmp_path)
    server = make_server('127.0.0.1', 0, agent, threaded=True, ssl_context=(str(cert), str(key)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    original = urllib3.connection.HTTPSConnection._new_conn
    def dial(connection):
        if connection.host == 'node.test':
            return socket.create_connection(('127.0.0.1', server.server_port), timeout=connection.timeout)
        return original(connection)
    monkeypatch.setattr(urllib3.connection.HTTPSConnection, '_new_conn', dial)
    monkeypatch.setenv('HTTPS_PROXY', 'http://unreachable-proxy.test:1')
    app.config.update(NODE_HOSTS=['node.test'], NODE_CA_BUNDLE=str(ca))
    node = Node(name='TLS protocol fixture', url='https://node.test', token_encrypted=encrypt(TOKEN))
    try:
        yield agent, node, spec, ssh, endpoint
    finally:
        ssh.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        with agent.app_context():
            db.session.remove()
            db.engine.dispose()


def test_tls_node_executes_only_selected_fixed_guest_script_and_returns_link(tls_guest, caplog):
    agent, node, spec, ssh, endpoint = tls_guest
    value = sshx.dispatch(spec, 'generate', node=node, private=ssh.private_key(), operation_id=str(uuid.uuid4()))
    assert value['link'] == LINK and value['fingerprint'] == fingerprint(ssh.key)
    assert ssh.commands == [b'sh -s']
    assert spec['id'] in ssh.scripts[0] and 'curl -sSf https://sshx.io/get | sh' in ssh.scripts[0]
    assert 'PRIVATE KEY' not in ssh.scripts[0]
    assert endpoint.call_count == 4
    assert LINK not in caplog.text and TOKEN not in caplog.text
    with agent.app_context():
        assert db.session.scalar(db.select(db.func.count()).select_from(AgentOperation)) == 0
        assert 'PRIVATE KEY' not in str(db.session.get(AgentInstance, spec['id']).spec)
        assert LINK not in str(db.session.get(AgentInstance, spec['id']).spec)


def test_remote_enrollment_key_verification_really_authenticates(tls_guest):
    _, node, spec, ssh, _ = tls_guest
    value = sshx.dispatch(spec, 'verify', node=node, private=ssh.private_key(), host_fingerprint=fingerprint(ssh.key))
    assert value['state'] == 'verified'
    assert ssh.auth_calls and ssh.commands == []


def test_node_mismatch_never_sends_guest_credentials(tls_guest):
    _, node, spec, ssh, _ = tls_guest
    with pytest.raises(EngineError, match='HTTP 409'):
        sshx.dispatch(spec | {'owner_id': 2}, 'verify', node=node, private=ssh.private_key())
    assert ssh.auth_calls == [] and ssh.commands == []


def test_node_rejects_changed_host_key_before_authentication(tls_guest):
    _, node, spec, ssh, _ = tls_guest
    with pytest.raises(EngineError, match='HTTP 409'):
        sshx.dispatch(spec, 'verify', node=node, private=ssh.private_key(), host_fingerprint='SHA256:' + 'A' * 43)
    assert ssh.auth_calls == []


@pytest.mark.parametrize('extra', [{'host': '127.0.0.1'}, {'command': 'id'}, {'username': 'root'}, {'port': 22}])
def test_bearer_api_still_rejects_arbitrary_targets_or_commands(tls_guest, extra):
    agent, _, spec, ssh, _ = tls_guest
    with agent.test_client() as client:
        response = client.post(f'/v1/instances/{spec["id"]}/sshx', headers={'Authorization': 'Bearer ' + TOKEN},
                               json={'mode': 'probe', 'target': target(spec), **extra})
        assert response.status_code == 409
    assert ssh.auth_calls == [] and ssh.commands == []


def test_machine_endpoint_rejects_browser_origin_cookies_and_missing_bearer(tls_guest):
    agent, _, spec, ssh, _ = tls_guest
    url = f'/v1/instances/{spec["id"]}/sshx'
    with agent.test_client() as client:
        data = {'mode': 'probe', 'target': target(spec)}
        assert client.post(url, json=data).status_code == 401
        assert client.post(url, json=data, headers={'Authorization': 'Bearer wrong'}).status_code == 401
        assert client.post(url, json=data, headers={'Authorization': 'Bearer ' + TOKEN, 'Origin': 'https://node.test'}).status_code == 403
        assert client.get(f'/v1/instances/{spec["id"]}/console', headers={'Authorization': 'Bearer ' + TOKEN}).status_code == 404
        assert client.get(f'/v1/instances/{spec["id"]}/webssh', headers={'Authorization': 'Bearer ' + TOKEN}).status_code == 404
    assert ssh.auth_calls == []


def test_old_node_is_explicitly_unsupported_no_panel_localhost_fallback(app, monkeypatch):
    node = Node(name='old fixture', url='https://node.test', token_encrypted=encrypt(TOKEN))
    transport = NodeEngine(node)
    monkeypatch.setattr(transport, 'capabilities', lambda: {'protocol_version': 1})
    request = Mock()
    monkeypatch.setattr(transport, '_request', request)
    with pytest.raises(EngineError, match='Upgrade/restart'):
        transport.guest_ssh({'id': str(uuid.uuid4())}, 'probe')
    request.assert_not_called()


def test_untrusted_node_fingerprint_result_is_not_saved(app, monkeypatch):
    node = Node(name='protocol fixture', url='https://node.test', token_encrypted=encrypt(TOKEN))
    spec = {'id': str(uuid.uuid4()), 'engine': 'qemu', 'username': 'guest', 'ssh_port': 22555}
    monkeypatch.setattr(NodeEngine, 'guest_ssh', lambda *a, **kw: {'state': 'verified', 'fingerprint': 'SHA256:' + 'B' * 43})
    with pytest.raises(UncertainError, match='different guest fingerprint'):
        sshx.dispatch(spec, 'verify', node=node, private='not-used-at-explicit-transport-boundary', host_fingerprint='SHA256:' + 'A' * 43)

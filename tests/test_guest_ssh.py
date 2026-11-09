"""Real KEX/auth/exec protocol, explicitly NOT a QEMU boot or real SSHX relay."""
import base64
import io
import logging
import time
import uuid
from unittest.mock import Mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
import paramiko
import pytest

from engines import EngineError, UncertainError
from engines.qemu_engine import QemuEngine
from services.guest_access import GuestAuthorityError
from services.guest_ssh import GuestSSH, credentials, fingerprint, new_key
from services import sshx
from tests.ssh_helpers import SSHProtocolServer

SYNTHETIC_LINK = 'https://sshx.io/s/protocol-fixture-only#SyntheticKey0001'


@pytest.fixture
def ssh_server():
    with SSHProtocolServer() as server:
        yield server


@pytest.fixture
def guest(app, ssh_server, monkeypatch):
    endpoint = Mock(return_value=ssh_server.endpoint)
    monkeypatch.setattr(QemuEngine, 'ssh_endpoint', endpoint)
    return {'id': str(uuid.uuid4()), 'owner_id': 1, 'engine': 'qemu', 'username': 'guest',
            'ssh_port': ssh_server.endpoint[1], 'ram_mb': 512, 'vcpus': 1, 'disk_gb': 8,
            'runtime': {'network_restricted': False}}


def test_probe_verifies_endpoint_but_sends_no_credentials(guest, ssh_server):
    data = sshx.local(guest, 'probe')
    assert data == {'fingerprint': fingerprint(ssh_server.key), 'state': 'probed'}
    assert ssh_server.auth_calls == [] and ssh_server.commands == []
    assert QemuEngine.ssh_endpoint.call_count == 2


def test_host_key_mismatch_precedes_any_guest_authentication(guest, ssh_server):
    with pytest.raises(EngineError, match='No credentials were sent'):
        sshx.local(guest, 'verify', private=ssh_server.private_key(), host_fingerprint='SHA256:' + 'A' * 43)
    assert ssh_server.auth_calls == []


@pytest.mark.parametrize('method', ['password', 'key'])
def test_fixed_command_uses_real_ssh_auth_and_stdin_no_pty(guest, ssh_server, method):
    auth = ({'method': 'password', 'password': ssh_server.password} if method == 'password' else
            {'method': 'key', 'private_key': ssh_server.private_key('fixture-passphrase'), 'passphrase': 'fixture-passphrase'})
    with GuestSSH(guest, fingerprint(ssh_server.key)) as connection:
        connection.authenticate(auth)
        assert connection.execute('# fixed test protocol only\n') == 'fixture script received\n'
    assert ssh_server.commands == [b'sh -s']
    assert ssh_server.scripts == ['# fixed test protocol only\n']
    assert QemuEngine.ssh_endpoint.call_count == 4
    assert ssh_server.auth_calls[-1][1] == 'guest'


def test_command_deadline_includes_a_stalled_exec_acknowledgement(guest, ssh_server):
    # Channel.settimeout does not bound Paramiko's exec acknowledgement wait.
    # The fixture delays only the SSH protocol response; it executes no shell.
    ssh_server.exec_delay = .4
    with GuestSSH(guest, fingerprint(ssh_server.key)) as connection:
        connection.authenticate({'method': 'key', 'private_key': ssh_server.private_key()})
        started = time.monotonic()
        with pytest.raises(UncertainError, match='timed out|outcome|unknown'):
            connection.execute('# fixed protocol deadline regression\n', seconds=.1)
        assert time.monotonic() - started < .8
    assert ssh_server.commands == [b'sh -s']


@pytest.mark.parametrize('kind', ['ed25519', 'rsa', 'ecdsa'])
def test_encrypted_formats_really_authenticate_without_an_agent(guest, ssh_server, kind):
    key = {'ed25519': lambda: ed25519.Ed25519PrivateKey.generate(),
           'rsa': lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
           'ecdsa': lambda: ec.generate_private_key(ec.SECP256R1())}[kind]()
    material = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                serialization.BestAvailableEncryption(b'fixture-passphrase')).decode()
    classes = {'ed25519': paramiko.Ed25519Key, 'rsa': paramiko.RSAKey, 'ecdsa': paramiko.ECDSAKey}
    ssh_server.client_key = classes[kind].from_private_key(io.StringIO(material), password='fixture-passphrase')
    with GuestSSH(guest, fingerprint(ssh_server.key)) as connection:
        connection.authenticate({'method': 'key', 'private_key': material, 'passphrase': 'fixture-passphrase'})
    assert ssh_server.auth_calls[-1] == ('key', 'guest')
    assert ssh_server.commands == []


def test_generate_reads_one_validated_real_protocol_output_not_a_placeholder(guest, ssh_server, monkeypatch, caplog):
    # The program is a synthetic protocol callback; it does not execute the installer.
    ssh_server.program = lambda script: (0, 'SKVM_RUNNING\nSKVM_SECONDS:3600\n\x1b[32mLink: ' + SYNTHETIC_LINK + '\x1b[0m\n')
    host_runner = Mock(side_effect=AssertionError('No host command is allowed for SSHX.'))
    monkeypatch.setattr('services.security.run', host_runner)
    caplog.set_level(logging.DEBUG)
    data = sshx.local(guest, 'generate', operation_id=str(uuid.uuid4()), private=ssh_server.private_key())
    assert data['link'] == SYNTHETIC_LINK and data['state'] == 'generated'
    script = ssh_server.scripts[-1]
    assert 'curl -sSf https://sshx.io/get | sh' in script
    assert 'timeout --signal=INT --kill-after=5' in script
    assert 'SKVM_SSHX_INSTANCE=' in script and 'SSHX_SERVER=https://sshx.io' in script
    assert 'PRIVATE KEY' not in script
    assert SYNTHETIC_LINK not in caplog.text and ssh_server.password not in caplog.text
    host_runner.assert_not_called()


def test_enrollment_is_append_only_and_proves_new_key_auth(guest, ssh_server):
    private, public = new_key()
    def enroll(script):
        encoded = base64.b64encode((public + '\n').encode()).decode()
        assert encoded in script and "printf '\\n%s\\n'" in script
        assert 'chpasswd' not in script and 'passwd ' not in script
        assert ssh_server.password not in script and private not in script
        ssh_server.extra_keys.add(base64.b64decode(public.split()[1]))
        return 0, 'SKVM_ENROLLED\n'
    ssh_server.program = enroll
    pin = fingerprint(ssh_server.key)
    assert sshx.local(guest, 'enroll', host_fingerprint=pin, auth={'method': 'password', 'password': ssh_server.password}, public_key=public)['state'] == 'enrolled'
    assert sshx.local(guest, 'verify', private=private, host_fingerprint=pin)['state'] == 'verified'
    assert ssh_server.commands == [b'sh -s']


@pytest.mark.parametrize('output', [
    'SKVM_RUNNING\nSKVM_SECONDS:3600\nhttps://evil.example/s/anything#secret\n',
    'SKVM_RUNNING\nSKVM_SECONDS:3600\n',
    'SKVM_RUNNING\nSKVM_SECONDS:3600\n' + SYNTHETIC_LINK + '\nhttps://sshx.io/s/second-fixture#AnotherTestKey01\n',
    SYNTHETIC_LINK + '\n',
])
def test_invalid_or_ambiguous_client_output_is_uncertain_never_success(guest, ssh_server, output):
    ssh_server.program = lambda script: (0, output)
    with pytest.raises(UncertainError):
        sshx.local(guest, 'generate', operation_id=str(uuid.uuid4()), private=ssh_server.private_key())


def test_oversized_output_is_bounded_and_not_logged(guest, ssh_server, caplog):
    ssh_server.program = lambda script: (0, 'x' * 65537)
    with GuestSSH(guest) as connection:
        connection.authenticate({'method': 'password', 'password': ssh_server.password})
        with pytest.raises(UncertainError, match='safe limit'):
            connection.execute('# fixed test protocol only\n')
    assert 'x' * 200 not in caplog.text


def test_authority_change_after_exec_is_uncertain(guest, ssh_server):
    def guard():
        if ssh_server.commands:
            raise GuestAuthorityError('fixture authority revoked')
    with GuestSSH(guest, check=guard) as connection:
        connection.authenticate({'method': 'password', 'password': ssh_server.password})
        with pytest.raises(UncertainError, match='Authority changed'):
            connection.execute('# fixed test protocol only\n')


def test_restricted_guest_does_not_authenticate_or_change_network(guest, ssh_server):
    guest['runtime']['network_restricted'] = True
    with pytest.raises(EngineError, match='explicitly enable'):
        sshx.local(guest, 'generate', operation_id=str(uuid.uuid4()), private=ssh_server.private_key())
    assert ssh_server.auth_calls == []
    assert guest['runtime']['network_restricted'] is True


@pytest.mark.parametrize('value', [
    'http://sshx.io/s/test#SyntheticKey0001', 'https://sshx.io.evil.test/s/test#SyntheticKey0001',
    'https://user@sshx.io/s/test#SyntheticKey0001', 'https://sshx.io:443/s/test#SyntheticKey0001',
    'https://sshx.io/s/test?redirect=evil#SyntheticKey0001', 'javascript:alert(1)',
    'https://sshx.io/s/../test#SyntheticKey0001', 'https://sshx.io/s/test#bad',
    'https://sshx.io/s/test#SyntheticKey0001\n', None,
])
def test_access_link_validation_rejects_wrong_origin_controls_and_unexpected_urls(value):
    with pytest.raises(EngineError):
        sshx.valid_link(value)


@pytest.mark.parametrize('auth', [
    {'method': 'password', 'password': 'secret', 'host': '127.0.0.1'},
    {'method': 'password', 'password': ''}, {'method': 'key', 'private_key': 'x' * 65537},
    {'method': 'agent'}, {'method': 'key', 'private_key': 'x', 'command': 'id'},
])
def test_credentials_schema_cannot_select_hosts_or_commands(auth):
    with pytest.raises(EngineError):
        credentials(auth)

"""Private-key formats and pre-decryption CPU/memory bounds."""
import base64
import io
import json
from unittest.mock import Mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
import paramiko
import pytest

from services import webssh
from tests.test_webssh import browser_ws, connect_guest, live_panel, receive, ssh_server

__all__ = ['live_panel', 'ssh_server']


@pytest.mark.parametrize('kind', ['ed25519', 'rsa', 'ecdsa'])
def test_encrypted_openssh_formats_authenticate_over_real_ssh(live_panel, ssh_server, kind):
    key = {'ed25519': lambda: ed25519.Ed25519PrivateKey.generate(),
           'rsa': lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
           'ecdsa': lambda: ec.generate_private_key(ec.SECP256R1())}[kind]()
    material = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                serialization.BestAvailableEncryption(b'isolated-key-passphrase')).decode()
    classes = {'ed25519': paramiko.Ed25519Key, 'rsa': paramiko.RSAKey, 'ecdsa': paramiko.ECDSAKey}
    ssh_server.client_key = classes[kind].from_private_key(io.StringIO(material), password='isolated-key-passphrase')
    with browser_ws(live_panel) as ws:
        assert connect_guest(ws, live_panel, ssh_server,
                             {'method': 'key', 'private_key': material, 'passphrase': 'isolated-key-passphrase'})['type'] == 'connected'
        ws.send(json.dumps({'type': 'disconnect'}))
        receive(ws, 'disconnected')


@pytest.mark.parametrize('rounds', [0, 257, 2**32 - 1])
def test_malicious_openssh_bcrypt_cost_is_rejected_before_decryption(monkeypatch, rounds):
    def field(data):
        return len(data).to_bytes(4, 'big') + data
    options = field(b'0123456789abcdef') + rounds.to_bytes(4, 'big')
    raw = b'openssh-key-v1\x00' + field(b'aes256-ctr') + field(b'bcrypt') + field(options)
    material = '-----BEGIN OPENSSH PRIVATE KEY-----\n' + base64.b64encode(raw).decode() + '\n-----END OPENSSH PRIVATE KEY-----'
    parser = Mock(side_effect=AssertionError('An unbounded KDF must not run.'))
    for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        monkeypatch.setattr(cls, 'from_private_key', parser)
    with pytest.raises(webssh.SSHError) as error:
        webssh.private_key({'private_key': material, 'passphrase': 'test-only'})
    assert error.value.code == 'key_cost_limit'
    parser.assert_not_called()


def test_declared_key_lengths_cannot_allocate_unbounded_memory():
    raw = b'openssh-key-v1\x00' + (2**32 - 1).to_bytes(4, 'big') + b'x'
    material = '-----BEGIN OPENSSH PRIVATE KEY-----\n' + base64.b64encode(raw).decode() + '\n-----END OPENSSH PRIVATE KEY-----'
    with pytest.raises(webssh.SSHError) as error:
        webssh.private_key({'private_key': material, 'passphrase': ''})
    assert error.value.code == 'invalid_private_key'


def test_oversized_pem_is_rejected_before_expensive_rsa_validation(monkeypatch):
    parser = Mock(side_effect=AssertionError('Large PEM validation must not run.'))
    monkeypatch.setattr(paramiko.RSAKey, 'from_private_key', parser)
    with pytest.raises(webssh.SSHError) as error:
        webssh.private_key({'private_key': 'x' * 8193, 'passphrase': ''})
    assert error.value.code == 'key_cost_limit'
    parser.assert_not_called()

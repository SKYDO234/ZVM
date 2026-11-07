"""Guest enrollment key formats and pre-decryption CPU/memory limits."""
import base64
from unittest.mock import Mock
import paramiko
import pytest
from services import guest_keys as key_parser


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
    with pytest.raises(key_parser.SSHError) as error:
        key_parser.private_key({'private_key': material, 'passphrase': 'test-only'})
    assert error.value.code == 'key_cost_limit'
    parser.assert_not_called()


def test_declared_key_lengths_cannot_allocate_unbounded_memory():
    raw = b'openssh-key-v1\x00' + (2**32 - 1).to_bytes(4, 'big') + b'x'
    material = '-----BEGIN OPENSSH PRIVATE KEY-----\n' + base64.b64encode(raw).decode() + '\n-----END OPENSSH PRIVATE KEY-----'
    with pytest.raises(key_parser.SSHError) as error:
        key_parser.private_key({'private_key': material, 'passphrase': ''})
    assert error.value.code == 'invalid_private_key'


def test_oversized_pem_is_rejected_before_expensive_rsa_validation(monkeypatch):
    parser = Mock(side_effect=AssertionError('Large PEM validation must not run.'))
    monkeypatch.setattr(paramiko.RSAKey, 'from_private_key', parser)
    with pytest.raises(key_parser.SSHError) as error:
        key_parser.private_key({'private_key': 'x' * 8193, 'passphrase': ''})
    assert error.value.code == 'key_cost_limit'
    parser.assert_not_called()

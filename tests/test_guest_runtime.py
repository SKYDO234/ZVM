"""Fail-closed runtime selection; process boundaries are explicitly mocked here."""
from types import SimpleNamespace
from unittest.mock import Mock

import psutil
import pytest

from engines import EngineError
from engines.qemu_engine import QemuEngine
from tests.test_engines import vm_spec


@pytest.mark.parametrize('fault', ['stopped', 'wrong-forward', 'public-forward', 'different-port',
                                    'unowned-listener', 'public-listener', 'paused', 'permission'])
def test_ssh_target_requires_real_qemu_forward_listener_and_running_qmp(app, monkeypatch, fault):
    spec = vm_spec()
    port = spec['ssh_port']
    forward = f'hostfwd=tcp:127.0.0.1:{port}-:22'
    if fault == 'wrong-forward':
        forward += '0'  # Exact components, not substring matching.
    if fault == 'public-forward':
        forward = forward.replace('127.0.0.1', '0.0.0.0')
    if fault == 'different-port':
        forward = forward.replace(str(port), str(port + 1))
    process = Mock()
    process.cmdline.return_value = ['qemu-system-x86_64', '-netdev', 'user,id=net0,' + forward]
    process.net_connections.return_value = [SimpleNamespace(status=psutil.CONN_LISTEN,
        laddr=SimpleNamespace(ip='0.0.0.0' if fault == 'public-listener' else '127.0.0.1', port=port))]
    if fault == 'unowned-listener':
        process.net_connections.return_value = []
    if fault == 'permission':
        process.net_connections.side_effect = psutil.AccessDenied()
    monkeypatch.setattr(QemuEngine, '_process', lambda *_: None if fault == 'stopped' else process)
    monkeypatch.setattr(QemuEngine, '_qmp', lambda *_: {'running': fault != 'paused'})
    dial = Mock()
    monkeypatch.setattr('socket.create_connection', dial)
    with pytest.raises(EngineError):
        QemuEngine().ssh_endpoint(spec)
    dial.assert_not_called()


def test_verified_managed_forward_returns_only_loopback(app, monkeypatch):
    spec = vm_spec()
    process = Mock()
    process.cmdline.return_value = ['qemu-system-x86_64', '-netdev', f'user,id=net0,hostfwd=tcp:127.0.0.1:{spec["ssh_port"]}-:22']
    process.net_connections.return_value = [SimpleNamespace(status=psutil.CONN_LISTEN, laddr=SimpleNamespace(ip='127.0.0.1', port=spec['ssh_port']))]
    monkeypatch.setattr(QemuEngine, '_process', lambda *_: process)
    monkeypatch.setattr(QemuEngine, '_qmp', lambda *_: {'running': True})
    assert QemuEngine().ssh_endpoint(spec) == ('127.0.0.1', spec['ssh_port'])
    process.net_connections.assert_called_once_with(kind='tcp')
    app.config['TEST_MODE'] = True
    with pytest.raises(EngineError, match='test mode'):
        QemuEngine().ssh_endpoint(spec)

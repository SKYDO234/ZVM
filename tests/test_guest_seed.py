"""Inspect cloud-init at a replaced ISO-builder boundary, not a guest boot."""
from pathlib import Path

import pytest
import yaml

from engines.qemu_engine import QemuEngine
from services.guest_ssh import new_key
from services.security import instance_dir
from tests.test_provisioning import spec


@pytest.mark.parametrize('restricted', [True, False])
def test_seed_preserves_owner_key_adds_unique_control_key_and_only_explicit_internet_dependencies(users, monkeypatch, restricted):
    data = spec(users[0]) | {'network_restricted': restricted}
    directory = instance_dir(data['id'])
    directory.mkdir(parents=True)
    _, owner = new_key()
    private, public = new_key()
    observed = {}
    def iso_boundary(command):
        assert command[0] == 'cloud-localds'
        text = Path(command[2]).read_text()
        observed.update(yaml.safe_load(text))
        assert private not in text
        # Test-only output needed for chmod; not passed off as a real ISO/VM.
        Path(command[1]).write_bytes(b'explicit ISO-builder unit boundary')
    monkeypatch.setattr('engines.qemu_engine.run', iso_boundary)
    QemuEngine()._seed(data, {'public_key': owner, 'control_public_key': public})
    assert observed['users'][0]['ssh_authorized_keys'] == [owner, public]
    assert observed['disable_root'] is True and observed['ssh_pwauth'] is False
    if restricted:
        assert 'packages' not in observed
    else:
        assert set(observed['packages']) == {'curl', 'ca-certificates', 'bash', 'tar', 'coreutils', 'util-linux', 'python3'}
    assert not (directory / 'user-data').exists() and not (directory / 'meta-data').exists()

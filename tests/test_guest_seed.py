"""Inspect cloud-init at a replaced ISO-builder boundary, not a guest boot."""
from pathlib import Path
import subprocess

import pytest
import yaml

from engines.qemu_engine import QemuEngine
from services.guest_bootstrap import SSHX_DEPENDENCIES
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
        assert 'packages' not in observed and 'runcmd' not in observed
    else:
        assert 'packages' not in observed  # No unconditional index refresh/upgrade.
        assert observed['runcmd'] == [['sh', '-c', SSHX_DEPENDENCIES]]
        assert SSHX_DEPENDENCIES.index('if ready; then') < SSHX_DEPENDENCIES.index('apt-get -o')
        assert 'pidfd_open' in SSHX_DEPENDENCIES and 'dnf --setopt=timeout=20' in SSHX_DEPENDENCIES
        assert 'sshx.io/get' not in SSHX_DEPENDENCIES  # Only Generate installs SSHX.
        syntax = subprocess.run(['sh', '-n'], input=SSHX_DEPENDENCIES, text=True, capture_output=True, timeout=5)
        assert syntax.returncode == 0, syntax.stderr
    assert not (directory / 'user-data').exists() and not (directory / 'meta-data').exists()

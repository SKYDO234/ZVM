"""Fail-closed process checks: never signal a recycled or unrelated PID."""
import importlib.util
import os
from pathlib import Path
import subprocess
import pytest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('panel_launcher', ROOT / 'scripts/serve-panel.py')
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


def test_missing_or_dead_master_is_not_a_running_panel(tmp_path):
    path = tmp_path / 'panel.pid'
    assert launcher.owned_master(path) is None
    path.write_text(str(2**31 - 1))
    assert launcher.owned_master(path) is None


def test_unrelated_live_process_is_never_treated_as_panel(tmp_path):
    path = tmp_path / 'panel.pid'
    path.write_text(str(os.getpid()))
    with pytest.raises(RuntimeError, match='another process'):
        launcher.owned_master(path)
    os.kill(os.getpid(), 0)  # Existence check only; no signal is sent.


def test_pid_file_symlink_is_refused(tmp_path):
    actual = tmp_path / 'actual'
    actual.write_text(str(os.getpid()))
    path = tmp_path / 'panel.pid'
    path.symlink_to(actual)
    with pytest.raises(RuntimeError, match='symlink'):
        launcher.owned_master(path)


@pytest.mark.parametrize('value', ['0', '-1', '65536', 'wat', '0000000001'])
def test_installer_invalid_port_fails_before_installation(value):
    result = subprocess.run(['bash', str(ROOT / 'install.sh'), '--port', value], capture_output=True, text=True, timeout=5)
    assert result.returncode == 2 and '--port requires' in result.stderr

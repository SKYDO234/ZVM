"""Guest boot readiness: real SSH protocol, explicit QEMU endpoint fixture.

No OS boot, shell, installer or real relay runs here. Native acceptance queues
Generate immediately after QMP Start instead of pre-waiting with an SSH helper.
"""
from datetime import datetime, timedelta
import socket
from unittest.mock import Mock

import pytest

from engines import EngineError, UncertainError
from engines.qemu_engine import QemuEngine
from extensions import db
from models import GuestAccess, GuestLease, Job, SSHXSession
from models.user import utcnow
from services.background import stop_background
from services.guest_access import GuestAuthorityError
from services.guest_ssh import GuestSSHBusyError, GuestSSHNotReadyError
from services.job_control import cancel_queued
from services.provisioning import process_job, queue_action, start_worker
from services.security import decrypt, encrypt
from tests.ssh_helpers import SSHProtocolServer
from tests.test_sshx import PIN, SYNTHETIC_LINK, access, vm
from tests.test_sshx_queue import guest_boundary, wait_status


@pytest.mark.parametrize('failure', ['tcp_refused', 'banner_reset'])
def test_generate_waits_for_guest_boot_without_replaying_the_installer(app, users, monkeypatch, failure):
    with SSHProtocolServer(lambda script: (0, 'SKVM_RUNNING\nSKVM_SECONDS:60\n' + SYNTHETIC_LINK + '\n')) as server:
        # This is the only VM identity boundary replacement; SSH KEX/auth/exec
        # after readiness are real, but the recorded script is never executed.
        monkeypatch.setattr(QemuEngine, 'ssh_endpoint', lambda self, spec: server.endpoint)
        app.config['SSHX_MAX_SECONDS'] = 60
        instance = vm(users[0], username='guest', ssh_port=server.endpoint[1])
        saved = GuestAccess(instance_id=instance.id, private_key_encrypted=encrypt({'private_key': server.private_key()}))
        db.session.add(saved)
        db.session.commit()
        ciphertext = saved.private_key_encrypted
        if failure == 'banner_reset':
            server.unready_connections = 1
        else:
            original = socket.create_connection
            attempts = []

            def refuse_once(address, *args, **kwargs):
                if address == server.endpoint:
                    attempts.append(True)
                    if len(attempts) == 1:
                        raise ConnectionRefusedError('Synthetic pre-boot socket failure; not guest output')
                return original(address, *args, **kwargs)

            monkeypatch.setattr('services.guest_ssh.socket.create_connection', refuse_once)
        now = utcnow()
        monkeypatch.setattr('services.provisioning.utcnow', lambda: now)
        ident = queue_action(users[0], instance, 'sshx_generate').id
        process_job(ident)
        db.session.expire_all()
        job = db.session.get(Job, ident)
        assert job.status == 'queued', 'A pre-auth boot failure must wait, not permanently fail Generate'
        assert 'Waiting for guest SSH' in job.message
        assert server.auth_calls == [] and server.commands == []
        assert db.session.get(SSHXSession, instance.id) is None
        assert db.session.scalar(db.select(db.func.count()).select_from(GuestLease)) == 0
        waiting = decrypt(job.payload)
        assert datetime.fromisoformat(waiting['sshx_ready_deadline']) > now
        assert datetime.fromisoformat(waiting['sshx_retry_at']) > now
        assert 'sshx_started_at' not in waiting
        # A not-yet-due retry must not connect or mark the job Running.
        assert process_job(ident) is False
        assert server.auth_calls == [] and server.commands == []
        # Four minutes of boot waiting must not consume a 60-second client TTL.
        now += timedelta(minutes=4)
        process_job(ident)
        db.session.expire_all()
        job = db.session.get(Job, ident)
        assert job.status == 'completed' and job.payload is None
        assert server.auth_calls == [('key', 'guest')]
        assert server.commands == [b'sh -s'] and len(server.scripts) == 1
        assert 'curl -sSf https://sshx.io/get | sh' in server.scripts[0]
        assert db.session.get(GuestAccess, instance.id).private_key_encrypted == ciphertext
        session = db.session.get(SSHXSession, instance.id)
        assert decrypt(session.link_encrypted) == SYNTHETIC_LINK
        assert session.expires_at == now + timedelta(seconds=60)


@pytest.mark.parametrize('kind', ['sshx_generate', 'sshx_stop'])
@pytest.mark.parametrize('failure', [GuestSSHNotReadyError, GuestSSHBusyError])
def test_boot_wait_has_a_persistent_deadline_independent_of_queue_age(app, users, monkeypatch, kind, failure):
    instance = vm(users[0])
    access(instance)
    _, command = guest_boundary(monkeypatch)
    command.side_effect = failure()
    now = utcnow()
    monkeypatch.setattr('services.provisioning.utcnow', lambda: now)
    job = queue_action(users[0], instance, kind)
    job.created_at = now - timedelta(hours=1)
    db.session.commit()
    process_job(job.id)
    waiting = decrypt(db.session.get(Job, job.id).payload)
    deadline = datetime.fromisoformat(waiting['sshx_ready_deadline'])
    instance_id = instance.id
    assert deadline == now + timedelta(seconds=app.config['SSHX_READY_SECONDS'])
    assert waiting['sshx_ready_attempts'] == 1
    # A new DB session/worker and a changed operator setting do not reset it.
    db.session.remove()
    app.config['SSHX_READY_SECONDS'] = 900
    now += timedelta(seconds=20)
    process_job(job.id)
    waiting = decrypt(db.session.get(Job, job.id).payload)
    assert datetime.fromisoformat(waiting['sshx_ready_deadline']) == deadline
    assert waiting['sshx_ready_attempts'] == 2 and command.call_count == 2
    now = deadline + timedelta(seconds=1)
    process_job(job.id)
    row = db.session.get(Job, job.id)
    assert row.status == 'failed' and row.payload is None
    assert 'Timed out waiting for guest SSH' in row.message
    assert 'No SSHX guest command was sent' in row.message
    assert command.call_count == 2, 'Expired boot work must not dispatch another guest request'
    assert db.session.get(GuestAccess, instance_id) is not None
    assert db.session.get(SSHXSession, instance_id) is None


@pytest.mark.parametrize('error,status', [
    (EngineError('Explicit fixture: host key changed; no authentication'), 'failed'),
    (GuestAuthorityError('Explicit fixture: authority revoked'), 'failed'),
    (EngineError('Explicit fixture: guest key authentication rejected'), 'failed'),
    (EngineError('Explicit fixture: SSHX installer failed'), 'failed'),
    (UncertainError('Explicit fixture: lost exec acknowledgement'), 'uncertain'),
    (RuntimeError('Explicit fixture: unknown outcome after dispatch'), 'uncertain'),
])
def test_security_auth_installer_and_unknown_outcomes_are_never_boot_retried(users, monkeypatch, error, status):
    instance = vm(users[0])
    access(instance)
    _, command = guest_boundary(monkeypatch)
    command.side_effect = error
    ident = queue_action(users[0], instance, 'sshx_generate').id
    process_job(ident)
    row = db.session.get(Job, ident)
    assert row.status == status
    assert (row.payload is not None) == (status == 'uncertain')
    process_job(ident)
    command.assert_called_once()
    assert db.session.get(SSHXSession, instance.id) is None


@pytest.mark.parametrize('failure', ['host_key', 'authentication', 'installer'])
def test_real_protocol_rejections_never_requeue_or_replay_guest_scripts(users, monkeypatch, failure):
    with SSHProtocolServer(lambda script: (1, 'SKVM_ERROR:INSTALL\n')) as server:
        monkeypatch.setattr(QemuEngine, 'ssh_endpoint', lambda self, spec: server.endpoint)
        instance = vm(users[0], username='guest', ssh_port=server.endpoint[1])
        saved = access(instance)
        if failure != 'authentication':
            saved.private_key_encrypted = encrypt({'private_key': server.private_key()})
        if failure == 'host_key':
            saved.host_fingerprint = PIN
        db.session.commit()
        ident = queue_action(users[0], instance, 'sshx_generate').id
        process_job(ident)
        row = db.session.get(Job, ident)
        assert row.status == 'failed' and row.payload is None
        assert len(server.auth_calls) == (0 if failure == 'host_key' else 1)
        assert len(server.commands) == (1 if failure == 'installer' else 0)
        assert len(server.scripts) == (1 if failure == 'installer' else 0)
        process_job(ident)
        assert len(server.scripts) == (1 if failure == 'installer' else 0)


def test_boot_wait_releases_the_sshx_lane_for_another_vm(app, users, monkeypatch):
    booting, ready = vm(users[0]), vm(users[0])
    access(booting)
    access(ready)
    _, command = guest_boundary(monkeypatch)
    booting_id = booting.id

    def dispatch(spec, *args, **kwargs):
        if spec['id'] == booting_id:
            raise GuestSSHNotReadyError()
        return {'state': 'generated', 'link': SYNTHETIC_LINK, 'fingerprint': PIN, 'seconds': 3600}

    command.side_effect = dispatch
    waiting = queue_action(users[0], booting, 'sshx_generate').id
    following = queue_action(users[0], ready, 'sshx_generate').id
    start_worker(app)
    try:
        assert wait_status(following, 'completed'), 'A booting guest must not hold the SSHX lane for ten minutes'
        db.session.expire_all()
        row = db.session.get(Job, waiting)
        assert row.status == 'queued' and 'Waiting for guest SSH' in row.message
        assert decrypt(row.payload)['sshx_ready_attempts'] == 1
    finally:
        assert stop_background(app, 5)
    assert command.call_count == 2


def test_admin_can_cancel_released_boot_wait_without_resetting_the_guest(users, monkeypatch):
    instance = vm(users[0])
    ciphertext = access(instance).private_key_encrypted
    _, command = guest_boundary(monkeypatch)
    command.side_effect = GuestSSHNotReadyError()
    ident = queue_action(users[0], instance, 'sshx_generate').id
    process_job(ident)
    cancel_queued(db.session.get(Job, ident), users[2])
    row = db.session.get(Job, ident)
    assert row.status == 'cancelled' and row.payload is None
    assert 'No guest mutation command was sent' in row.message
    process_job(ident)
    command.assert_called_once()
    assert db.session.get(GuestAccess, instance.id).private_key_encrypted == ciphertext
    assert db.session.get(SSHXSession, instance.id) is None


@pytest.mark.parametrize('revoked', ['disabled', 'password', 'reassigned', 'suspended'])
def test_each_boot_retry_revalidates_current_authority(users, monkeypatch, revoked):
    instance = vm(users[0])
    access(instance)
    _, command = guest_boundary(monkeypatch)
    command.side_effect = GuestSSHNotReadyError()
    now = utcnow()
    monkeypatch.setattr('services.provisioning.utcnow', lambda: now)
    ident = queue_action(users[0], instance, 'sshx_generate').id
    process_job(ident)
    if revoked == 'disabled':
        users[0].enabled = False
    elif revoked == 'password':
        users[0].set_password('Changed-during-guest-boot!')
    elif revoked == 'reassigned':
        instance.owner_id = users[1].id
    else:
        instance.suspended = True
    db.session.commit()
    now += timedelta(seconds=20)
    process_job(ident)
    row = db.session.get(Job, ident)
    assert row.status == 'failed' and row.payload is None
    command.assert_called_once()


@pytest.mark.parametrize('value', [59, 901, True, '600', None])
def test_readiness_window_configuration_is_bounded(app, value):
    from skvm import create_app
    with pytest.raises(RuntimeError, match='SSHX_READY_SECONDS'):
        create_app({'SSHX_READY_SECONDS': value})


def test_identity_failure_does_not_attempt_a_socket_or_boot_retry(users, monkeypatch):
    instance = vm(users[0])
    access(instance)
    endpoint = Mock(side_effect=EngineError('Explicit fixture: QEMU listener identity cannot be proven'))
    dial = Mock(side_effect=AssertionError('An unproven listener must not be contacted'))
    monkeypatch.setattr(QemuEngine, 'ssh_endpoint', endpoint)
    monkeypatch.setattr('services.guest_ssh.socket.create_connection', dial)
    ident = queue_action(users[0], instance, 'sshx_generate').id
    process_job(ident)
    assert db.session.get(Job, ident).status == 'failed'
    dial.assert_not_called()

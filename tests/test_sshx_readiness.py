"""Guest boot readiness: real SSH protocol, explicit QEMU endpoint fixture.

No OS boot, shell, installer or real relay runs here. Native acceptance queues
Generate immediately after QMP Start instead of pre-waiting with an SSH helper.
"""
from datetime import datetime, timedelta
import socket
from unittest.mock import Mock

import paramiko
import pytest

from engines import EngineError, UncertainError
from engines.qemu_engine import QemuEngine
from extensions import db
from models import GuestAccess, GuestLease, Job, SSHXSession
from models.user import utcnow
from services.background import stop_background
from services.guest_access import GuestAuthorityError
from services.guest_ssh import GuestSSH, GuestSSHAuthenticationNotReadyError, GuestSSHBusyError, GuestSSHChannelNotReadyError, GuestSSHNotReadyError
from services.job_control import cancel_queued
from services.provisioning import process_job, queue_action, start_worker
from services.security import decrypt, encrypt
from tests.ssh_helpers import SSHProtocolServer
from tests.test_sshx import PIN, SYNTHETIC_LINK, access, vm
from tests.test_sshx_queue import guest_boundary, wait_status


@pytest.mark.parametrize('failure', ['tcp_refused', 'banner_reset', 'channel_timeout'])
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
        elif failure == 'tcp_refused':
            original = socket.create_connection
            attempts = []

            def refuse_once(address, *args, **kwargs):
                if address == server.endpoint:
                    attempts.append(True)
                    if len(attempts) == 1:
                        raise ConnectionRefusedError('Synthetic pre-boot socket failure; not guest output')
                return original(address, *args, **kwargs)

            monkeypatch.setattr('services.guest_ssh.socket.create_connection', refuse_once)
        else:
            original = paramiko.Transport.open_session
            attempts = []

            def bounded_channel(transport, *args, **kwargs):
                attempts.append(True)
                if len(attempts) == 1:
                    server.channel_delay = .4
                    kwargs['timeout'] = .1
                try:
                    return original(transport, *args, **kwargs)
                finally:
                    server.channel_delay = 0

            monkeypatch.setattr(paramiko.Transport, 'open_session', bounded_channel)
        now = utcnow()
        monkeypatch.setattr('services.provisioning.utcnow', lambda: now)
        ident = queue_action(users[0], instance, 'sshx_generate').id
        process_job(ident)
        db.session.expire_all()
        job = db.session.get(Job, ident)
        assert job.status == 'queued', 'A pre-command boot failure must wait, not permanently fail Generate'
        assert 'Waiting for guest SSH' in job.message
        before_auth = [('key', 'guest')] if failure == 'channel_timeout' else []
        assert server.auth_calls == before_auth and server.commands == []
        assert db.session.get(SSHXSession, instance.id) is None
        assert db.session.scalar(db.select(db.func.count()).select_from(GuestLease)) == 0
        waiting = decrypt(job.payload)
        assert datetime.fromisoformat(waiting['sshx_ready_deadline']) > now
        assert datetime.fromisoformat(waiting['sshx_retry_at']) > now
        assert 'sshx_started_at' not in waiting
        # A not-yet-due retry must not connect or mark the job Running.
        assert process_job(ident) is False
        assert server.auth_calls == before_auth and server.commands == []
        # Four minutes of boot waiting must not consume a 60-second client TTL.
        now += timedelta(minutes=4)
        process_job(ident)
        db.session.expire_all()
        job = db.session.get(Job, ident)
        assert job.status == 'completed' and job.payload is None
        assert server.auth_calls == before_auth + [('key', 'guest')]
        assert server.commands == [b'sh -s'] and len(server.scripts) == 1
        assert 'curl -sSf https://sshx.io/get | sh' in server.scripts[0]
        assert db.session.get(GuestAccess, instance.id).private_key_encrypted == ciphertext
        session = db.session.get(SSHXSession, instance.id)
        assert decrypt(session.link_encrypted) == SYNTHETIC_LINK
        assert session.expires_at == now + timedelta(seconds=60)


@pytest.mark.parametrize('kind', ['sshx_generate', 'sshx_stop'])
@pytest.mark.parametrize('failure', [GuestSSHNotReadyError, GuestSSHAuthenticationNotReadyError, GuestSSHChannelNotReadyError, GuestSSHBusyError])
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
    assert waiting['sshx_ready_stage'] == failure().stage
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
    assert 'Last SSH check:' in row.message
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


@pytest.mark.parametrize('stage,delay', [('banner', 11), ('authentication', 11), ('channel', 6)])
def test_slow_ready_guest_completes_without_discarding_a_valid_ssh_connection(app, users, monkeypatch, stage, delay):
    """Real delayed protocol responses, not a boot or installer simulation.

    These timings exceed the old 10-second greeting/auth and 5-second channel
    cutoffs. A healthy but CPU-constrained TCG guest must get to finish setup,
    rather than having every otherwise-valid connection discarded/requeued.
    """
    with SSHProtocolServer(lambda script: (0, 'SKVM_RUNNING\nSKVM_SECONDS:60\n' + SYNTHETIC_LINK + '\n')) as server:
        setattr(server, {'banner': 'banner_delay', 'authentication': 'auth_delay', 'channel': 'channel_delay'}[stage], delay)
        monkeypatch.setattr(QemuEngine, 'ssh_endpoint', lambda self, spec: server.endpoint)
        app.config['SSHX_MAX_SECONDS'] = 60
        instance = vm(users[0], username='guest', ssh_port=server.endpoint[1])
        db.session.add(GuestAccess(instance_id=instance.id, private_key_encrypted=encrypt({'private_key': server.private_key()})))
        db.session.commit()
        ident = queue_action(users[0], instance, 'sshx_generate').id
        process_job(ident)
        row = db.session.get(Job, ident, populate_existing=True)
        assert row.status == 'completed', f'A valid slow {stage} response was discarded: {row.status}: {row.message}'
        assert row.payload is None
        assert server.auth_calls == [('key', 'guest')] and server.commands == [b'sh -s']
        assert len(server.scripts) == 1 and 'curl -sSf https://sshx.io/get | sh' in server.scripts[0]


@pytest.mark.parametrize('method', ['key', 'password'])
def test_silent_authentication_is_retryable_but_never_sends_a_guest_command(app, monkeypatch, method):
    from services.guest_ssh import fingerprint
    monkeypatch.setattr('services.guest_ssh.SSH_AUTH_SECONDS', .1)
    with SSHProtocolServer() as server:
        server.auth_delay = .4
        monkeypatch.setattr(QemuEngine, 'ssh_endpoint', lambda self, spec: server.endpoint)
        spec = {'id': 'c5cf1ba5-58af-4a7c-b5da-aab363605a84', 'engine': 'qemu', 'username': 'guest', 'ssh_port': server.endpoint[1]}
        auth = ({'method': 'key', 'private_key': server.private_key()} if method == 'key'
                else {'method': 'password', 'password': server.password})
        with GuestSSH(spec, fingerprint(server.key)) as connection:
            with pytest.raises(GuestSSHAuthenticationNotReadyError):
                connection.authenticate(auth)
            assert not connection.transport.is_active()
        assert server.auth_calls == [(method, 'guest')] and server.commands == []
        # Caller credentials are not altered; only the internal validated copy is cleared.
        assert auth['method'] == method


def test_shared_setup_budget_is_not_restarted_for_authentication(app, monkeypatch):
    import time
    monkeypatch.setattr('services.guest_ssh.SSH_SETUP_SECONDS', .25)
    with SSHProtocolServer() as server:
        server.banner_delay, server.auth_delay = .1, .4
        monkeypatch.setattr(QemuEngine, 'ssh_endpoint', lambda self, spec: server.endpoint)
        spec = {'id': 'c5cf1ba5-58af-4a7c-b5da-aab363605a84', 'engine': 'qemu', 'username': 'guest', 'ssh_port': server.endpoint[1]}
        started = time.monotonic()
        with GuestSSH(spec) as connection:
            with pytest.raises(GuestSSHAuthenticationNotReadyError):
                connection.authenticate({'method': 'key', 'private_key': server.private_key()})
        assert time.monotonic() - started < .6
        assert server.commands == []


def test_authority_is_rechecked_while_waiting_for_authentication(app, monkeypatch):
    with SSHProtocolServer() as server:
        server.auth_delay = 1
        monkeypatch.setattr(QemuEngine, 'ssh_endpoint', lambda self, spec: server.endpoint)
        spec = {'id': 'c5cf1ba5-58af-4a7c-b5da-aab363605a84', 'engine': 'qemu', 'username': 'guest', 'ssh_port': server.endpoint[1]}
        def guard():
            if server.auth_calls:
                raise GuestAuthorityError('Explicit protocol fixture: authority revoked during authentication')
        with GuestSSH(spec, check=guard) as connection:
            with pytest.raises(GuestAuthorityError):
                connection.authenticate({'method': 'key', 'private_key': server.private_key()})
            assert not connection.transport.is_active()
        assert server.commands == []


def test_total_request_deadline_includes_setup_and_never_makes_exec_retryable(app, monkeypatch):
    import time
    monkeypatch.setattr('services.guest_ssh.SSH_REQUEST_SECONDS', .4)
    def slow_protocol_output(script):
        time.sleep(.4)
        return 0, 'fixture output only\n'
    with SSHProtocolServer(slow_protocol_output) as server:
        server.auth_delay = .15
        monkeypatch.setattr(QemuEngine, 'ssh_endpoint', lambda self, spec: server.endpoint)
        spec = {'id': 'c5cf1ba5-58af-4a7c-b5da-aab363605a84', 'engine': 'qemu', 'username': 'guest', 'ssh_port': server.endpoint[1]}
        with GuestSSH(spec) as connection:
            connection.authenticate({'method': 'key', 'private_key': server.private_key()})
            started = time.monotonic()
            with pytest.raises(UncertainError):
                connection.execute('# fixed protocol fixture only\n', seconds=130)
            assert time.monotonic() - started < .55
        assert server.commands == [b'sh -s'] and len(server.scripts) == 1


@pytest.mark.parametrize('stage', [None, 3, {}, [], 'secret-from-untrusted-remote-response'])
def test_retry_stage_is_an_enum_never_raw_remote_output(stage):
    from services.guest_ssh import retry_error
    error = retry_error('guest_ssh_not_ready', stage)
    assert error.stage == 'handshake'
    assert 'secret-from-untrusted' not in str(error)


def test_request_budget_fits_the_existing_admission_and_proxy_bounds():
    from engines.node_engine import GUEST_RESPONSE_SECONDS, RESPONSE_SECONDS
    from services.guest_ssh import SSH_LEASE_SECONDS, SSH_SETUP_SECONDS, SSH_REQUEST_SECONDS
    assert SSH_SETUP_SECONDS + 130 <= SSH_REQUEST_SECONDS < GUEST_RESPONSE_SECONDS < 180
    # Include capability-response and TLS-connect overhead before the panel
    # gets to wait for the agent; a live request must not lose its admission.
    assert RESPONSE_SECONDS + 3 + 5 + GUEST_RESPONSE_SECONDS < SSH_LEASE_SECONDS


def test_setup_expiry_after_channel_open_prevents_even_an_exec_request(app, monkeypatch):
    import time
    with SSHProtocolServer() as server:
        monkeypatch.setattr(QemuEngine, 'ssh_endpoint', lambda self, spec: server.endpoint)
        spec = {'id': 'c5cf1ba5-58af-4a7c-b5da-aab363605a84', 'engine': 'qemu', 'username': 'guest', 'ssh_port': server.endpoint[1]}
        with GuestSSH(spec) as connection:
            connection.authenticate({'method': 'key', 'private_key': server.private_key()})
            original = connection.transport.open_session
            def expired_channel(*args, **kwargs):
                channel = original(*args, **kwargs)
                connection.setup_deadline = time.monotonic() - 1
                return channel
            monkeypatch.setattr(connection.transport, 'open_session', expired_channel)
            with pytest.raises(GuestSSHChannelNotReadyError):
                connection.execute('# fixed protocol fixture only\n')
        assert server.auth_calls == [('key', 'guest')] and server.commands == []


def test_last_expiring_attempt_reports_its_actual_stage_not_an_older_guess(app, users, monkeypatch):
    instance = vm(users[0])
    access(instance)
    _, command = guest_boundary(monkeypatch)
    app.config['SSHX_READY_SECONDS'] = 60
    now = utcnow()
    monkeypatch.setattr('services.provisioning.utcnow', lambda: now)
    def expires_during_auth(*args, **kwargs):
        nonlocal now
        now += timedelta(seconds=61)
        raise GuestSSHAuthenticationNotReadyError()
    command.side_effect = expires_during_auth
    ident = queue_action(users[0], instance, 'sshx_generate').id
    process_job(ident)
    row = db.session.get(Job, ident, populate_existing=True)
    assert row.status == 'failed' and row.payload is None
    assert 'Last SSH check: the guest has not answered SSH authentication' in row.message
    command.assert_called_once()

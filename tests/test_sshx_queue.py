"""Real queue threads/locks, explicitly mocked engine and guest SSH boundaries.

These regressions execute no guest, installer, host shell or real SSHX relay.
"""
import threading
import time
from unittest.mock import Mock

import pytest

from extensions import db
from models import Job
from services.background import stop_background
from services.provisioning import process_job, queue_action, start_worker
from services.security import locked
from tests.test_sshx import PIN, SYNTHETIC_LINK, access, vm


def wait_status(ident, status, seconds=2):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        db.session.expire_all()
        if db.session.get(Job, ident).status == status:
            return True
        time.sleep(.02)
    return False


def guest_boundary(monkeypatch):
    engine = Mock()
    engine.metrics.return_value = {'status': 'stopped'}
    engine.start.return_value = {'status': 'running'}
    engine.force_stop.return_value = {'status': 'stopped'}
    monkeypatch.setattr('services.provisioning.engine_for', lambda *a: engine)
    monkeypatch.setattr('services.provisioning.capacity_check', lambda *a, **kw: None)
    command = Mock(return_value={'state': 'generated', 'link': SYNTHETIC_LINK,
                                 'fingerprint': PIN, 'seconds': 3600})
    monkeypatch.setattr('services.sshx.dispatch', command)
    return engine, command


def test_busy_vm_does_not_claim_or_block_the_sshx_job(app, users, monkeypatch):
    instance = vm(users[0])
    access(instance)
    ident = queue_action(users[0], instance, 'sshx_generate').id
    _, command = guest_boundary(monkeypatch)
    finished, outcomes = threading.Event(), []

    def attempt():
        with app.app_context():
            try:
                outcomes.append(process_job(ident))
            finally:
                db.session.remove()
                finished.set()

    with locked(f'control-{instance.id}', blocking=False):
        thread = threading.Thread(target=attempt, daemon=True)
        thread.start()
        returned = finished.wait(.4)
        db.session.expire_all()
        observed = db.session.get(Job, ident).status
        untouched = command.call_count == 0
    thread.join(timeout=3)
    assert not thread.is_alive()
    assert returned, 'Busy VM control must not leave the worker blocked on flock'
    assert outcomes == [False] and observed == 'queued' and untouched


def test_sshx_is_consumed_while_unrelated_provisioning_is_still_running(app, users, monkeypatch):
    busy_vm, terminal_vm = vm(users[0]), vm(users[0])
    access(terminal_vm)
    engine, command = guest_boundary(monkeypatch)
    entered, release = threading.Event(), threading.Event()

    def long_start(*args, **kwargs):
        entered.set()
        assert release.wait(5), 'Test must release its synthetic engine boundary'
        return {'status': 'running'}

    engine.start.side_effect = long_start
    queue_action(users[0], busy_vm, 'start')
    start_worker(app)
    try:
        assert entered.wait(2), 'General worker did not reach the engine boundary'
        ident = queue_action(users[0], terminal_vm, 'sshx_generate').id
        completed = wait_status(ident, 'completed', 1.5)
        still_running = not release.is_set()
    finally:
        release.set()
        assert stop_background(app, 5)
    assert completed and still_running, 'SSHX must not wait behind unrelated provisioning/downloads'
    command.assert_called_once()


@pytest.mark.parametrize('leader,kind', [('worker-leader', 'force_stop'), ('sshx-worker-leader', 'sshx_generate')])
def test_standby_worker_takes_over_after_the_leader_lock_is_released(app, users, monkeypatch, leader, kind):
    instance = vm(users[0])
    access(instance)
    engine, command = guest_boundary(monkeypatch)
    with locked(leader, blocking=False):
        standby = start_worker(app)
        time.sleep(.15)
    try:
        ident = queue_action(users[0], instance, kind).id
        completed = wait_status(ident, 'completed')
    finally:
        assert stop_background(app, 5)
    assert completed, 'A standby must retry election, not leave queued work permanently unconsumed'
    assert not standby.is_alive()
    (command if kind == 'sshx_generate' else engine.force_stop).assert_called_once()


def test_new_leader_does_not_relabel_an_executing_sshx_job_as_interrupted(app, users, monkeypatch):
    instance, other = vm(users[0]), vm(users[0])
    access(instance)
    ident = queue_action(users[0], instance, 'sshx_generate').id
    row = db.session.get(Job, ident)
    row.status = 'running'
    db.session.commit()
    engine, command = guest_boundary(monkeypatch)
    with locked(f'job-{ident}', blocking=False):
        start_worker(app)
        try:
            probe = queue_action(users[0], other, 'force_stop').id
            assert wait_status(probe, 'completed')
            db.session.expire_all()
            observed = db.session.get(Job, ident).status
        finally:
            assert stop_background(app, 5)
    assert observed == 'running', 'A held execution lock is not evidence of a crashed worker'
    engine.force_stop.assert_called_once()
    command.assert_not_called()


def test_consumer_retries_a_transient_startup_failure(app, users, monkeypatch):
    from services import provisioning
    instance = vm(users[0])
    engine, _ = guest_boundary(monkeypatch)
    original = provisioning._consume_jobs
    attempts = []

    def fail_once(application, stop, sshx_only):
        if not sshx_only:
            attempts.append(True)
            if len(attempts) == 1:
                raise RuntimeError('Synthetic startup failure; no resource operation ran')
        return original(application, stop, sshx_only)

    monkeypatch.setattr(provisioning, '_consume_jobs', fail_once)
    ident = queue_action(users[0], instance, 'force_stop').id
    start_worker(app)
    try:
        assert wait_status(ident, 'completed')
    finally:
        assert stop_background(app, 5)
    assert len(attempts) >= 2
    engine.force_stop.assert_called_once()

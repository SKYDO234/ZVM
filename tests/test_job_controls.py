"""Blocked-operation workflows; engine boundaries are explicitly mocked, not native proof."""
from datetime import timedelta
from unittest.mock import Mock
import uuid

import pytest

from engines import EngineError
from extensions import db
from models import AgentInstance, AgentOperation, Audit, Job, Node, SSHXSession, VPS
from models.user import utcnow
from services.node_worker import process_operation
from services.provisioning import process_job, queue_action
from services.security import encrypt, locked
from tests.conftest import post as csrf_post, signin
from tests.test_owner_lifecycle import engine_boundary
from tests.test_provisioning import fixture_vps


PAGES = ('users', 'instances', 'plans', 'nodes', 'images', 'configuration', 'jobs', 'recovery', 'audit')


def post(client, path, data=None, token_path='/profile'):
    # A profile CSRF fetch performs no incidental dashboard engine inspection.
    return csrf_post(client, path, data, token_path=token_path)


def operator_signin(client, users):
    if client.get('/profile').status_code == 200:
        post(client, '/logout', token_path='/profile')
    return signin(client, users[2].email)


def interrupted(instance, kind='stop', status='uncertain', **extra):
    job = Job(owner_id=instance.owner_id, instance_id=instance.id, node_id=instance.node_id,
              engine=instance.engine, kind=kind, status=status,
              payload=encrypt({'spec': instance.spec(), 'actor_id': instance.owner_id}), **extra)
    db.session.add(job)
    db.session.commit()
    return job


def proof(monkeypatch, instance, state='running'):
    engine = engine_boundary(monkeypatch, state)
    engine._process.return_value.cmdline.return_value = [
        'qemu-system-x86_64', '-m', str(instance.ram_mb), '-smp', str(instance.vcpus),
        '-machine', 'type=pc,accel=tcg']
    monkeypatch.setattr('services.job_control.engine_for', lambda *a: engine)
    return engine


@pytest.mark.parametrize('page', PAGES)
def test_each_admin_control_has_a_separate_authorized_page(client, users, page):
    signin(client)
    assert client.get(f'/admin/{page}').status_code == 403
    operator_signin(client, users)
    response = client.get(f'/admin/{page}')
    assert response.status_code == 200
    assert f'data-admin-page="{page}"'.encode() in response.data
    for other in PAGES:
        assert f'href="/admin/{other}"'.encode() in response.data


@pytest.mark.parametrize('section', ['network', 'ownership', 'suspension'])
def test_instance_admin_controls_have_separate_pages_and_remain_admin_only(client, users, section):
    instance = fixture_vps(users[0])
    signin(client)
    assert client.get(f'/admin/instances/{instance.id}/{section}').status_code == 403
    operator_signin(client, users)
    page = client.get(f'/admin/instances/{instance.id}/{section}')
    assert page.status_code == 200 and f'data-instance-control="{section}"'.encode() in page.data


def test_duplicate_power_post_opens_the_existing_job_without_queueing_another(client, users):
    instance = fixture_vps(users[0])
    job = queue_action(users[0], instance, 'stop')
    signin(client)
    response = post(client, f'/vps/{instance.id}/action/stop')
    assert response.location.endswith(f'/vps/jobs/{job.id}')
    assert db.session.scalar(db.select(db.func.count()).select_from(Job)) == 1
    assert b'No additional operation' in client.get(response.location).data


def test_different_active_action_identifies_the_blocker_without_claiming_new_work(client, users, monkeypatch):
    instance = fixture_vps(users[0])
    engine_boundary(monkeypatch, 'running')
    job = interrupted(instance, 'restart', 'running')
    signin(client)
    response = post(client, f'/vps/{instance.id}/action/stop')
    assert response.location.endswith(f'/vps/jobs/{job.id}')
    page = client.get(response.location)
    assert b'Stop was not queued' in page.data
    metric = client.get(f'/api/vps/{instance.id}/metrics').json
    assert metric['blocking_jobs'][0]['id'] == job.id
    assert metric['blocking_jobs'][0]['url'].endswith(f'/vps/jobs/{job.id}')
    assert not metric['blocking_jobs'][0].get('payload')
    assert not metric['controls']['stop']['enabled']
    assert job.status == 'running'


def test_legacy_admin_blocker_does_not_offer_an_owner_a_forbidden_job_link(client, users, monkeypatch):
    instance = fixture_vps(users[0])
    engine_boundary(monkeypatch, 'running')
    job = interrupted(instance)
    job.owner_id = users[2].id
    db.session.commit()
    signin(client)
    metric = client.get(f'/api/vps/{instance.id}/metrics').json
    assert metric['blocking_jobs'][0]['url'] is None
    assert client.get(f'/vps/jobs/{job.id}').status_code == 404


def test_admin_can_cancel_a_queued_job_before_the_worker_claims_it(client, users, monkeypatch):
    instance = fixture_vps(users[0])
    engine = proof(monkeypatch, instance)
    job = interrupted(instance, status='queued')
    operator_signin(client, users)
    response = post(client, f'/admin/jobs/{job.id}/cancel')
    assert response.location.endswith(f'/vps/jobs/{job.id}')
    assert job.status == 'cancelled' and job.payload is None
    process_job(job.id)
    assert engine.method_calls == []
    assert db.session.get(VPS, instance.id).disk_gb == instance.disk_gb
    entry = db.session.scalar(db.select(Audit).where(Audit.action == 'job.cancelled'))
    assert entry.user_id == users[2].id


@pytest.mark.parametrize('status', ['running', 'uncertain', 'completed'])
def test_cancel_never_relabels_started_or_uncertain_work(client, users, status):
    instance = fixture_vps(users[0])
    job = interrupted(instance, status=status)
    ciphertext = job.payload
    operator_signin(client, users)
    post(client, f'/admin/jobs/{job.id}/cancel')
    assert job.status == status and job.payload == ciphertext


@pytest.mark.parametrize('action', ['cancel', 'close-power', 'reconcile'])
def test_recovery_posts_require_admin_and_csrf(client, users, action):
    job = interrupted(fixture_vps(users[0]))
    signin(client)
    assert post(client, f'/admin/jobs/{job.id}/{action}').status_code == 403
    operator_signin(client, users)
    assert client.post(f'/admin/jobs/{job.id}/{action}').status_code == 400
    assert job.status == 'uncertain' and job.payload


@pytest.mark.parametrize('state', ['running', 'stopped'])
def test_closing_interrupted_power_verifies_state_but_never_claims_original_success(client, users, monkeypatch, state):
    instance = fixture_vps(users[0])
    job = interrupted(instance)
    engine = proof(monkeypatch, instance, state)
    session = SSHXSession(instance_id=instance.id, owner_id=instance.owner_id, operation_id=str(uuid.uuid4()),
                          link_encrypted=encrypt('explicitly-synthetic-test-capability'),
                          expires_at=utcnow() + timedelta(minutes=10))
    db.session.add(session)
    db.session.commit()
    ciphertext = session.link_encrypted
    operator_signin(client, users)
    post(client, f'/admin/jobs/{job.id}/close-power')
    assert job.status == 'failed' and job.payload is None
    assert 'not claimed' in job.message and state in job.message
    assert db.session.get(VPS, instance.id) is instance and instance.disk_gb == 20
    assert session.state == ('uncertain' if state == 'running' else 'stopped')
    assert session.link_encrypted == (ciphertext if state == 'running' else None)
    for kind in ('start', 'stop', 'restart', 'force_stop', 'delete', 'resize', 'reinstall'):
        getattr(engine, kind).assert_not_called()
    if state == 'stopped':
        engine._ensure_disk_idle.assert_called_once()
    entry = db.session.scalar(db.select(Audit).where(Audit.action == 'job.power_closed'))
    assert entry.user_id == users[2].id
    assert queue_action(users[0], instance, 'stop').status == 'queued'


@pytest.mark.parametrize('state', ['unknown', 'missing', 'paused'])
def test_unknown_or_unproven_state_keeps_the_blocker_and_context(client, users, monkeypatch, state):
    instance = fixture_vps(users[0])
    job = interrupted(instance)
    ciphertext = job.payload
    proof(monkeypatch, instance, state)
    operator_signin(client, users)
    post(client, f'/admin/jobs/{job.id}/close-power')
    assert job.status == 'uncertain' and job.payload == ciphertext


@pytest.mark.parametrize('kind', ['create', 'delete', 'resize', 'reinstall', 'network', 'assign', 'sshx_generate', 'sshx_stop'])
def test_close_power_is_not_a_storage_reservation_or_guest_access_bypass(client, users, monkeypatch, kind):
    instance = fixture_vps(users[0])
    job = interrupted(instance, kind)
    engine = proof(monkeypatch, instance)
    ciphertext = job.payload
    operator_signin(client, users)
    post(client, f'/admin/jobs/{job.id}/close-power')
    assert job.status == 'uncertain' and job.payload == ciphertext
    assert engine.method_calls == []


@pytest.mark.parametrize('action,status', [('cancel', 'queued'), ('close-power', 'uncertain'), ('reconcile', 'uncertain')])
def test_live_execution_lock_cannot_be_cleared_even_if_database_state_is_stale(client, users, action, status):
    job = interrupted(fixture_vps(users[0]), status=status)
    operator_signin(client, users)
    with locked(f'job-{job.id}', blocking=False):
        post(client, f'/admin/jobs/{job.id}/{action}')
    assert job.status == status and job.payload


def test_nonzero_reservation_cannot_be_closed_as_a_simple_power_request(client, users, monkeypatch):
    instance = fixture_vps(users[0])
    job = interrupted(instance, ram_mb=512)
    engine = proof(monkeypatch, instance)
    operator_signin(client, users)
    post(client, f'/admin/jobs/{job.id}/close-power')
    assert job.status == 'uncertain' and job.ram_mb == 512 and job.payload
    assert engine.method_calls == []


def test_bad_running_qemu_allocation_cannot_release_a_power_blocker(client, users, monkeypatch):
    instance = fixture_vps(users[0])
    job = interrupted(instance)
    engine = proof(monkeypatch, instance)
    engine._process.return_value.cmdline.return_value = ['qemu-system-x86_64', '-m', '9999', '-smp', '1']
    operator_signin(client, users)
    post(client, f'/admin/jobs/{job.id}/close-power')
    assert job.status == 'uncertain' and job.payload


def test_external_running_operation_cannot_be_closed_from_parent_observation(client, users, monkeypatch):
    instance = fixture_vps(users[0])
    node = Node(name='Isolated node', url='https://node.test', token_encrypted=encrypt('test-only'))
    db.session.add(node)
    db.session.flush()
    instance.node_id = node.id
    db.session.commit()
    job = interrupted(instance)
    engine = proof(monkeypatch, instance)
    engine.operation_status.return_value = {'id': job.id, 'status': 'running'}
    operator_signin(client, users)
    post(client, f'/admin/jobs/{job.id}/close-power')
    assert job.status == 'uncertain' and job.payload
    engine.close_power.assert_not_called()


def test_agent_worker_never_reexecutes_a_terminal_operation(users, monkeypatch):
    instance = fixture_vps(users[0])
    engine = Mock()
    monkeypatch.setattr('services.node_worker.engine_for', lambda *a: engine)
    operation = AgentOperation(id=str(uuid.uuid4()), digest='explicit-unit-terminal-operation', status='failed',
                               payload=encrypt({'kind': 'stop', 'spec': instance.spec()}))
    db.session.add(AgentInstance(id=instance.id, spec=instance.spec()))
    db.session.add(operation)
    db.session.commit()
    process_operation(operation.id)
    assert operation.status == 'failed' and operation.payload
    assert engine.method_calls == []


def test_engine_inspection_failure_preserves_the_original_context(client, users, monkeypatch):
    instance = fixture_vps(users[0])
    job = interrupted(instance)
    engine = proof(monkeypatch, instance)
    engine.metrics.side_effect = EngineError('Explicitly isolated unavailable engine boundary.')
    operator_signin(client, users)
    post(client, f'/admin/jobs/{job.id}/close-power')
    assert job.status == 'uncertain' and job.payload


@pytest.mark.parametrize('state', ['queued', 'running', 'completed', 'unknown'])
def test_remote_nonterminal_or_completed_outcomes_are_not_guessed_closed(client, users, monkeypatch, state):
    instance = fixture_vps(users[0])
    node = Node(name='Explicit isolated transport', url='https://node.test', token_encrypted=encrypt('test-only'))
    db.session.add(node)
    db.session.flush()
    instance.node_id = node.id
    db.session.commit()
    job = interrupted(instance)
    engine = proof(monkeypatch, instance)
    engine.operation_status.return_value = {'id': job.id, 'status': state}
    operator_signin(client, users)
    post(client, f'/admin/jobs/{job.id}/close-power')
    assert job.status == 'uncertain' and job.payload
    engine.close_power.assert_not_called()
    engine.metrics.assert_not_called()


def test_parent_only_closes_after_agent_settlement_and_fresh_verified_metrics(client, users, monkeypatch):
    instance = fixture_vps(users[0])
    node = Node(name='Explicit isolated transport', url='https://node.test', token_encrypted=encrypt('test-only'))
    db.session.add(node)
    db.session.flush()
    instance.node_id = node.id
    db.session.commit()
    job = interrupted(instance)
    engine = proof(monkeypatch, instance)
    engine.operation_status.return_value = {'id': job.id, 'status': 'uncertain'}
    engine.close_power.return_value = {'id': job.id, 'status': 'failed'}
    engine.metrics.return_value = {'status': 'unknown'}
    operator_signin(client, users)
    post(client, f'/admin/jobs/{job.id}/close-power')
    assert job.status == 'uncertain' and job.payload
    engine.operation_status.return_value = {'id': job.id, 'status': 'failed'}
    engine.metrics.return_value = {'status': 'running'}
    post(client, f'/admin/jobs/{job.id}/close-power')
    assert job.status == 'failed' and job.payload is None
    assert db.session.get(VPS, instance.id) is not None
    engine.close_power.assert_called_once_with(job.id)


@pytest.mark.parametrize('kind', ['stop', 'delete'])
def test_new_agent_recovery_endpoint_is_authenticated_and_never_replays_actions(tmp_path, monkeypatch, kind):
    from tests.test_node import agent_app
    from tests.test_provisioning import spec
    from models import User
    agent = agent_app(tmp_path)
    agent.config['TEST_MODE'] = False
    data = spec(User(id=1))
    ident = str(uuid.uuid4())
    engine = Mock()
    engine.metrics.return_value = {'status': 'running'}
    engine._process.return_value.cmdline.return_value = ['qemu-system-x86_64', '-m', str(data['ram_mb']),
                                                         '-smp', str(data['vcpus']), '-machine', 'type=pc,accel=tcg']
    monkeypatch.setattr('services.node_worker.engine_for', lambda *a: engine)
    with agent.app_context():
        db.session.add(AgentInstance(id=data['id'], spec=data))
        db.session.add(AgentOperation(id=ident, digest='isolated-test-recovery', status='uncertain',
                                     payload=encrypt({'kind': kind, 'spec': data})))
        db.session.commit()
    client = agent.test_client()
    path = f'/v1/operations/{ident}/close-power'
    headers = {'Authorization': 'Bearer test-only-node-token-at-least-32-chars'}
    assert client.post(path).status_code == 401
    assert client.post(path, headers=headers | {'Origin': 'https://untrusted.test'}).status_code == 403
    response = client.post(path, headers=headers)
    assert response.status_code == (200 if kind == 'stop' else 409)
    with agent.app_context():
        operation = db.session.get(AgentOperation, ident)
        assert operation.status == ('failed' if kind == 'stop' else 'uncertain')
        assert bool(operation.payload) is (kind == 'delete')
        assert db.session.get(AgentInstance, data['id']).spec == data
    for action in ('stop', 'start', 'restart', 'force_stop', 'delete', 'resize'):
        getattr(engine, action).assert_not_called()


@pytest.mark.parametrize('lock', ['execution', 'capacity', 'control'])
def test_agent_recovery_cannot_clear_live_locks(users, monkeypatch, lock):
    from services.node_worker import close_power_operation
    instance = fixture_vps(users[0])
    operation = AgentOperation(id=str(uuid.uuid4()), digest='isolated-busy-agent', status='uncertain',
                               payload=encrypt({'kind': 'stop', 'spec': instance.spec()}))
    db.session.add(AgentInstance(id=instance.id, spec=instance.spec()))
    db.session.add(operation)
    db.session.commit()
    engine = Mock()
    monkeypatch.setattr('services.node_worker.engine_for', lambda *a: engine)
    name = {'execution': f'operation-{operation.id}', 'capacity': 'agent-capacity', 'control': f'control-{instance.id}'}[lock]
    with locked(name, blocking=False), pytest.raises(EngineError, match='live work'):
        close_power_operation(operation.id)
    assert operation.status == 'uncertain' and operation.payload
    assert engine.method_calls == []


def test_running_state_alone_never_falsely_certifies_an_interrupted_restart(users, monkeypatch):
    from services.provisioning import reconcile_job
    instance = fixture_vps(users[0])
    job = interrupted(instance, 'restart')
    engine = proof(monkeypatch, instance)
    with pytest.raises(EngineError, match='cannot prove an interrupted restart'):
        reconcile_job(job)
    assert job.status == 'uncertain' and job.payload
    assert engine.method_calls == []


def test_start_inspection_never_falsely_revokes_a_live_capability(users, monkeypatch):
    from services.provisioning import reconcile_job
    instance = fixture_vps(users[0])
    job = interrupted(instance, 'start')
    engine = proof(monkeypatch, instance)
    row = SSHXSession(instance_id=instance.id, owner_id=instance.owner_id, operation_id=str(uuid.uuid4()),
                      link_encrypted=encrypt('synthetic-inspection-capability'), expires_at=utcnow() + timedelta(minutes=10))
    db.session.add(row)
    db.session.commit()
    ciphertext = row.link_encrypted
    reconcile_job(job)
    assert job.status == 'completed' and 'verified by inspection' in job.message
    assert row.state == 'uncertain' and row.link_encrypted == ciphertext
    engine.start.assert_not_called()
    engine.stop.assert_not_called()

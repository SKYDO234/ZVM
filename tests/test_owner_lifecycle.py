"""Owner lifecycle regressions through real routes/queue/DB, with explicit engine mocks.

These unit boundaries are not VM/container compatibility evidence. Native acceptance
uses ordinary assigned owners as well, with the real QEMU/Docker engines.
"""
from datetime import timedelta
from unittest.mock import Mock
import uuid

import pytest

from engines import EngineError
from extensions import db
from models import AgentInstance, AgentOperation, GuestAccess, Job, Node, SSHXSession, VPS
from models.user import utcnow
from services.node_worker import process_operation
from services.provisioning import process_job, queue_action
from services.security import decrypt, encrypt
from tests.conftest import post, signin
from tests.test_provisioning import fixture_vps


POWER = ('start', 'stop', 'restart', 'force_stop', 'delete')


def engine_boundary(monkeypatch, state='stopped'):
    """Only the engine boundary is mocked; never run guest commands on the host."""
    engine = Mock()
    engine.metrics.return_value = {'status': state, 'usage': {}}
    engine.start.return_value = {'status': 'running'}
    engine.stop.return_value = {'status': 'stopped'}
    engine.force_stop.return_value = {'status': 'stopped'}
    engine.delete.return_value = {'status': 'deleted'}
    monkeypatch.setattr('services.provisioning.engine_for', lambda *a: engine)
    monkeypatch.setattr('services.provisioning.capacity_check', lambda *a, **kw: None)
    monkeypatch.setattr('services.resource_monitor.engine_for', lambda *a: engine)
    return engine


@pytest.mark.parametrize('kind', POWER)
def test_regular_owner_can_run_and_poll_own_lifecycle(client, users, monkeypatch, kind):
    instance = fixture_vps(users[0])
    ident = instance.id
    engine = engine_boundary(monkeypatch)
    signin(client)
    response = post(client, f'/vps/{ident}/action/{kind}')
    assert response.status_code == 302 and '/vps/jobs/' in response.location
    job = db.session.get(Job, response.location.rsplit('/', 1)[1])
    assert job.owner_id == users[0].id
    assert client.get(response.location).status_code == 200
    process_job(job.id)
    assert job.status == 'completed', job.message
    assert job.payload is None
    status = client.get(f'/api/jobs/{job.id}')
    assert status.status_code == 200 and status.json['status'] == 'completed'
    assert status.json['exists'] is (kind != 'delete')
    if kind == 'delete':
        assert db.session.get(VPS, ident) is None
        assert [call[0] for call in engine.method_calls if call[0] != 'metrics'] == ['stop', 'delete']
    elif kind == 'restart':
        engine.stop.assert_called_once()
        engine.start.assert_called_once()
    else:
        getattr(engine, kind).assert_called_once()


@pytest.mark.parametrize('kind', POWER)
def test_regular_user_cannot_control_or_delete_someone_elses_vps(client, users, monkeypatch, kind):
    instance = fixture_vps(users[1])
    engine = engine_boundary(monkeypatch)
    signin(client)
    assert post(client, f'/vps/{instance.id}/action/{kind}').status_code == 404
    assert db.session.scalar(db.select(db.func.count()).select_from(Job)) == 0
    assert db.session.get(VPS, instance.id) is not None
    assert engine.method_calls == []


@pytest.mark.parametrize('kind', POWER)
def test_owner_cannot_queue_lifecycle_without_csrf(client, users, kind):
    instance = fixture_vps(users[0])
    signin(client)
    assert client.post(f'/vps/{instance.id}/action/{kind}').status_code == 400
    assert db.session.scalar(db.select(db.func.count()).select_from(Job)) == 0


@pytest.mark.parametrize('kind', POWER)
def test_admin_requested_power_job_remains_visible_to_assigned_owner(app, users, monkeypatch, kind):
    instance = fixture_vps(users[0])
    engine_boundary(monkeypatch)
    job = queue_action(users[2], instance, kind)
    assert job.owner_id == instance.owner_id
    payload = decrypt(job.payload)
    assert payload['actor_id'] == users[2].id and payload['actor_tag'] == users[2].get_id()
    owner = app.test_client()
    signin(owner)
    assert owner.get(f'/vps/jobs/{job.id}').status_code == 200
    status = owner.get(f'/api/jobs/{job.id}')
    assert status.status_code == 200 and 'payload' not in status.json
    outsider = app.test_client()
    signin(outsider, users[1].email)
    assert outsider.get(f'/vps/jobs/{job.id}').status_code == 404
    assert outsider.get(f'/api/jobs/{job.id}').status_code == 404


def test_start_of_verified_running_vm_is_noop_and_preserves_sshx(users, monkeypatch):
    instance = fixture_vps(users[0])
    session = SSHXSession(instance_id=instance.id, owner_id=instance.owner_id,
                          operation_id=str(uuid.uuid4()), link_encrypted=encrypt('synthetic-capability-unit-only'),
                          expires_at=utcnow() + timedelta(minutes=30))
    db.session.add(session)
    db.session.commit()
    ciphertext = session.link_encrypted
    engine = engine_boundary(monkeypatch, 'running')
    capacity = Mock(side_effect=EngineError('A running VM must not need another VM worth of free RAM.'))
    monkeypatch.setattr('services.provisioning.capacity_check', capacity)
    job = queue_action(users[0], instance, 'start')
    process_job(job.id)
    assert job.status == 'completed', job.message
    assert 'already running' in job.message.lower()
    capacity.assert_not_called()
    engine.start.assert_not_called()
    engine.stop.assert_not_called()
    assert db.session.get(SSHXSession, instance.id).link_encrypted == ciphertext
    assert db.session.get(SSHXSession, instance.id).state == 'generated'


@pytest.mark.parametrize('kind', ['restart', 'delete'])
@pytest.mark.parametrize('failure', ['timeout', 'unproven'])
def test_failed_or_unproven_shutdown_never_restarts_or_deletes(client, users, monkeypatch, kind, failure):
    instance = fixture_vps(users[0])
    db.session.add(GuestAccess(instance_id=instance.id, private_key_encrypted=encrypt({'private_key': 'unit-only'})))
    db.session.add(SSHXSession(instance_id=instance.id, owner_id=instance.owner_id,
                              operation_id=str(uuid.uuid4()), link_encrypted=encrypt('synthetic-capability-unit-only'),
                              expires_at=utcnow() + timedelta(minutes=30)))
    db.session.commit()
    engine = engine_boundary(monkeypatch, 'running')
    if failure == 'timeout':
        engine.stop.side_effect = EngineError('ACPI shutdown timed out; guest is still running.')
    else:
        engine.stop.return_value = {'status': 'running'}
    signin(client)
    response = post(client, f'/vps/{instance.id}/action/{kind}')
    job = db.session.get(Job, response.location.rsplit('/', 1)[1])
    process_job(job.id)
    assert job.status == ('failed' if failure == 'timeout' else 'uncertain'), job.message
    engine.start.assert_not_called()
    engine.delete.assert_not_called()
    engine.force_stop.assert_not_called()
    assert db.session.get(VPS, instance.id) is not None
    assert db.session.get(GuestAccess, instance.id) is not None
    assert db.session.get(SSHXSession, instance.id).link_encrypted is not None


def test_owner_delete_cleans_only_target_secrets_after_proven_shutdown(users, monkeypatch):
    instance = fixture_vps(users[0])
    other = fixture_vps(users[1])
    ident = instance.id
    for item in (instance, other):
        db.session.add(GuestAccess(instance_id=item.id, private_key_encrypted=encrypt({'private_key': 'unit-only'})))
        db.session.add(SSHXSession(instance_id=item.id, owner_id=item.owner_id,
                                  operation_id=str(uuid.uuid4()), link_encrypted=encrypt('synthetic-capability-unit-only'),
                                  expires_at=utcnow() + timedelta(minutes=30)))
    db.session.commit()
    engine = engine_boundary(monkeypatch, 'running')
    job = queue_action(users[0], instance, 'delete')
    process_job(job.id)
    assert job.status == 'completed', job.message
    engine.stop.assert_called_once()
    engine.delete.assert_called_once()
    assert engine.delete.call_args.args[0]['id'] == ident
    for model in (VPS, GuestAccess, SSHXSession):
        assert db.session.get(model, ident) is None
        assert db.session.get(model, other.id) is not None


@pytest.mark.parametrize('kind', POWER)
def test_ownership_is_rechecked_before_a_queued_power_action(users, monkeypatch, kind):
    instance = fixture_vps(users[0])
    engine = engine_boundary(monkeypatch)
    job = queue_action(users[0], instance, kind)
    instance.owner_id = users[1].id
    db.session.commit()
    process_job(job.id)
    assert job.status == 'failed' and 'ownership' in job.message.lower()
    assert engine.method_calls == []


@pytest.mark.parametrize('kind', ['delete', 'restart'])
def test_agent_also_requires_proven_shutdown_before_next_transition(users, monkeypatch, kind):
    instance = fixture_vps(users[0])
    db.session.add(AgentInstance(id=instance.id, spec=instance.spec()))
    operation = AgentOperation(id=str(uuid.uuid4()), digest='isolated-unit-lifecycle-' + kind,
                               payload=encrypt({'kind': kind, 'spec': instance.spec()}))
    db.session.add(operation)
    db.session.commit()
    engine = Mock()
    engine.stop.return_value = {'status': 'running'}
    engine.start.return_value = {'status': 'running'}
    engine.delete.return_value = {'status': 'deleted'}
    monkeypatch.setattr('services.node_worker.engine_for', lambda *a: engine)
    monkeypatch.setattr('services.node_worker.enforce_capacity', lambda *a, **kw: None)
    process_operation(operation.id)
    assert operation.status == 'uncertain'
    engine.start.assert_not_called()
    engine.delete.assert_not_called()
    assert db.session.get(AgentInstance, instance.id) is not None


def test_agent_start_of_running_guest_is_a_verified_noop(users, monkeypatch):
    instance = fixture_vps(users[0])
    db.session.add(AgentInstance(id=instance.id, spec=instance.spec()))
    operation = AgentOperation(id=str(uuid.uuid4()), digest='isolated-unit-noop-start',
                               payload=encrypt({'kind': 'start', 'spec': instance.spec()}))
    db.session.add(operation)
    db.session.commit()
    engine = Mock()
    engine.metrics.return_value = {'status': 'running', 'usage': {}}
    capacity = Mock(side_effect=EngineError('No extra RAM is allocated for a verified no-op.'))
    monkeypatch.setattr('services.node_worker.engine_for', lambda *a: engine)
    monkeypatch.setattr('services.node_worker.enforce_capacity', capacity)
    process_operation(operation.id)
    assert operation.status == 'completed'
    assert operation.result == {'status': 'running', 'already_running': True}
    capacity.assert_not_called()
    engine.start.assert_not_called()


@pytest.mark.parametrize('state,enabled', [
    ('running', {'start': False, 'stop': True, 'restart': True, 'delete': True}),
    ('stopped', {'start': True, 'stop': False, 'restart': False, 'delete': True}),
    ('missing', {'start': False, 'stop': False, 'restart': False, 'delete': True}),
    ('unknown', {'start': False, 'stop': True, 'restart': False, 'delete': False}),
])
def test_owner_buttons_and_live_metrics_match_observed_guest_state(client, users, monkeypatch, state, enabled):
    instance = fixture_vps(users[0])
    engine_boundary(monkeypatch, state)
    signin(client)
    response = client.get(f'/vps/{instance.id}')
    assert response.status_code == 200
    # html5lib is already a project dependency; parse HTML, not text labels alone.
    import html5lib
    document = html5lib.parse(response.data, namespaceHTMLElements=False)
    for kind, allowed in enabled.items():
        forms = [form for form in document.iter('form') if form.attrib.get('action') == f'/vps/{instance.id}/action/{kind}']
        assert forms, kind
        for form in forms:
            button = next(form.iter('button'))
            assert ('disabled' not in button.attrib) is allowed, (state, kind)
            if not allowed:
                assert button.attrib.get('title'), (state, kind)
    metrics = client.get(f'/api/vps/{instance.id}/metrics')
    assert metrics.status_code == 200
    for kind, allowed in enabled.items():
        assert metrics.json['controls'][kind]['enabled'] is allowed


@pytest.mark.parametrize('status', ['queued', 'running', 'uncertain'])
def test_active_or_uncertain_lifecycle_work_disables_conflicting_buttons(client, users, monkeypatch, status):
    instance = fixture_vps(users[0])
    engine_boundary(monkeypatch, 'running')
    job = Job(owner_id=instance.owner_id, instance_id=instance.id, engine='qemu', kind='restart', status=status)
    db.session.add(job)
    db.session.commit()
    signin(client)
    response = client.get(f'/api/vps/{instance.id}/metrics')
    assert response.status_code == 200
    controls = response.json['controls']
    assert all(not value['enabled'] for value in controls.values())
    assert all(value['reason'] for value in controls.values())


def test_owner_can_delete_to_recover_only_uncertain_sshx_work(users, monkeypatch):
    instance = fixture_vps(users[0])
    old = Job(owner_id=instance.owner_id, instance_id=instance.id, engine='qemu', kind='sshx_generate', status='uncertain')
    db.session.add(old)
    db.session.commit()
    engine = engine_boundary(monkeypatch, 'running')
    job = queue_action(users[0], instance, 'delete')
    process_job(job.id)
    assert job.status == 'completed'
    assert old.status == 'failed' and old.payload is None
    engine.stop.assert_called_once()
    engine.delete.assert_called_once()


def test_external_delete_is_one_atomic_agent_operation_not_two_reused_ids(users, monkeypatch):
    instance = fixture_vps(users[0])
    node = Node(name='Unit TLS node', url='https://node.example.test', token_encrypted=encrypt('unit-only-token'))
    db.session.add(node)
    db.session.flush()
    instance.node_id = node.id
    db.session.commit()
    engine = engine_boundary(monkeypatch, 'running')
    job = queue_action(users[0], instance, 'delete')
    process_job(job.id)
    assert job.status == 'completed'
    engine.delete.assert_called_once()
    engine.stop.assert_not_called()
    assert engine.delete.call_args.kwargs['operation_id'] == job.id


def test_suspended_owner_can_delete_but_cannot_start_or_restart(client, users, monkeypatch):
    instance = fixture_vps(users[0])
    instance.suspended = True
    db.session.commit()
    engine = engine_boundary(monkeypatch, 'running')
    signin(client)
    controls = client.get(f'/api/vps/{instance.id}/metrics').json['controls']
    assert controls['delete']['enabled']
    assert not controls['start']['enabled'] and not controls['restart']['enabled']
    response = post(client, f'/vps/{instance.id}/action/delete')
    job = db.session.get(Job, response.location.rsplit('/', 1)[1])
    process_job(job.id)
    assert job.status == 'completed'
    engine.stop.assert_called_once()
    engine.delete.assert_called_once()


@pytest.mark.parametrize('kind', ['stop', 'force_stop'])
def test_docker_not_found_is_stopped_and_owned_orphan_network_can_be_deleted(users, monkeypatch, kind):
    from contextlib import nullcontext
    from docker.errors import NotFound
    from engines.docker_engine import DockerEngine
    instance = fixture_vps(users[0])
    data = instance.spec() | {'engine': 'docker'}
    client = Mock()
    client.containers.get.side_effect = NotFound('Explicit isolated Docker API NotFound boundary.')
    network = Mock(attrs={'Labels': {'skvm.managed': 'true', 'skvm.instance': data['id']}, 'Containers': {}})
    client.networks.get.return_value = network
    monkeypatch.setattr(DockerEngine, '_client', lambda *a, **kw: nullcontext(client))
    engine = DockerEngine()
    assert getattr(engine, kind)(data)['status'] == 'stopped'
    network.remove.assert_not_called()
    assert engine.delete(data)['status'] == 'deleted'
    network.remove.assert_called_once()


def test_agent_retains_metadata_when_deletion_is_not_proven(users, monkeypatch):
    instance = fixture_vps(users[0])
    db.session.add(AgentInstance(id=instance.id, spec=instance.spec()))
    operation = AgentOperation(id=str(uuid.uuid4()), digest='isolated-unit-unproven-delete',
                               payload=encrypt({'kind': 'delete', 'spec': instance.spec()}))
    db.session.add(operation)
    db.session.commit()
    engine = Mock()
    engine.stop.return_value = {'status': 'stopped'}
    engine.delete.return_value = {'status': 'running'}
    monkeypatch.setattr('services.node_worker.engine_for', lambda *a: engine)
    process_operation(operation.id)
    assert operation.status == 'uncertain' and operation.payload is not None
    assert db.session.get(AgentInstance, instance.id) is not None
    engine.stop.assert_called_once()
    engine.delete.assert_called_once()


@pytest.mark.parametrize('unproven', [False, True])
def test_failed_admin_power_jobs_audit_the_requester_not_the_quota_owner(users, monkeypatch, unproven):
    from models import Audit
    instance = fixture_vps(users[0])
    engine = engine_boundary(monkeypatch, 'running')
    if unproven:
        engine.stop.return_value = {'status': 'running'}
    else:
        engine.stop.side_effect = EngineError('Explicit unit shutdown failure.')
    job = queue_action(users[2], instance, 'delete')
    assert job.owner_id == users[0].id
    process_job(job.id)
    kind = 'job.uncertain' if unproven else 'job.failed'
    entry = db.session.scalar(db.select(Audit).where(Audit.action == kind).order_by(Audit.id.desc()))
    assert entry.user_id == users[2].id and entry.instance_id == instance.id
    engine.delete.assert_not_called()

"""SSHX/RBAC persistence tests. Engine/script boundaries are explicit unit fixtures."""
from datetime import timedelta
import hashlib
import uuid
from unittest.mock import Mock

import pytest

from engines import EngineError, UncertainError
from extensions import db
from models import Audit, GuestAccess, Job, Plan, ProvisionTicket, SSHXSession, User, VPS
from models.user import utcnow
from services.guest_access import GuestAuthorityError, GuestGuard
from services.guest_ssh import admission, new_key
from services.provisioning import _apply_result, process_job, queue_action, queue_create, reconcile_job
from services.security import decrypt, encrypt
from services.sshx import save_session, visible_session
from tests.conftest import post, signin
from tests.test_provisioning import spec

SYNTHETIC_LINK = 'https://sshx.io/s/unit-fixture-only#SyntheticKey0001'
PIN = 'SHA256:' + 'A' * 43


def vm(user, **overrides):
    data = spec(user)
    data.pop('forwards')
    data.update({'name': 'unit-' + uuid.uuid4().hex[:8], 'runtime': {'network_restricted': False}} | overrides)
    row = VPS(**data)
    db.session.add(row)
    db.session.commit()
    return row


def access(vps):
    private, _ = new_key()
    row = GuestAccess(instance_id=vps.id, private_key_encrypted=encrypt({'private_key': private}))
    db.session.add(row)
    db.session.commit()
    return row


def creation_form(owner):
    return {'owner_id': owner.id, 'name': 'admin-assigned', 'engine': 'qemu', 'os_id': 'ubuntu-24.04',
            'ram_mb': 512, 'vcpus': 1, 'disk_gb': 8, 'username': 'ubuntu',
            'auth_method': 'password', 'guest_password': 'Enrollment-is-not-panel-login!'}


@pytest.mark.parametrize('path', ['/vps/create', '/vps/provision/' + str(uuid.uuid4())])
def test_users_cannot_create_or_confirm_even_a_preexisting_ticket(client, users, path):
    signin(client)
    assert post(client, path, creation_form(users[0])).status_code == 403
    if path == '/vps/create':
        assert client.get(path).status_code == 403
    assert db.session.scalar(db.select(db.func.count()).select_from(Job)) == 0
    assert db.session.scalar(db.select(db.func.count()).select_from(ProvisionTicket)) == 0


def test_creation_service_cannot_bypass_admin_policy(users):
    with pytest.raises(EngineError, match='Only administrators'):
        queue_create(users[0], spec(users[0]), {})
    assert db.session.scalar(db.select(db.func.count()).select_from(Job)) == 0


def test_admin_review_and_reservations_belong_to_selected_owner(client, users, monkeypatch):
    monkeypatch.setattr('routes.vps.capacity_check', lambda *a, **kw: None)
    monkeypatch.setattr('services.provisioning.capacity_check', lambda *a, **kw: None)
    signin(client, users[2].email)
    review = post(client, '/vps/create', creation_form(users[0]))
    assert review.status_code == 200 and users[0].email.encode() in review.data
    assert b'Enrollment-is-not-panel-login!' not in review.data
    ticket = db.session.scalar(db.select(ProvisionTicket))
    assert ticket.owner_id == users[2].id
    submitted = post(client, f'/vps/provision/{ticket.id}')
    assert submitted.status_code == 302 and '/vps/jobs/' in submitted.location
    job = db.session.scalar(db.select(Job))
    data = decrypt(job.payload)
    assert job.owner_id == users[0].id and data['actor_id'] == users[2].id
    assert data['spec']['owner_id'] == users[0].id
    assert 'PRIVATE KEY' in data['control_private_key']
    assert 'PRIVATE KEY' not in job.payload
    assert data['credentials']['control_public_key'].startswith('ssh-ed25519 ')
    assert 'Enrollment-is-not-panel-login!' not in str(data)
    assert db.session.scalar(db.select(db.func.count()).select_from(VPS)) == 0


def test_target_plan_is_enforced_not_administrator_plan(client, users, monkeypatch):
    plan = Plan(name='Small target', max_instances=1, ram_mb=512, vcpus=1, disk_gb=8)
    users[0].plan = plan
    db.session.add(plan)
    db.session.commit()
    monkeypatch.setattr('routes.vps.capacity_check', lambda *a, **kw: None)
    signin(client, users[2].email)
    response = post(client, '/vps/create', creation_form(users[0]) | {'ram_mb': 1024})
    assert response.status_code == 200 and b'RAM allocation' in response.data
    assert db.session.scalar(db.select(db.func.count()).select_from(ProvisionTicket)) == 0


def test_disabled_target_cannot_be_assigned(client, users):
    users[0].enabled = False
    db.session.commit()
    signin(client, users[2].email)
    response = post(client, '/vps/create', creation_form(users[0]))
    assert b'enabled account' in response.data
    assert db.session.scalar(db.select(db.func.count()).select_from(Job)) == 0


@pytest.mark.parametrize('revoked', ['role', 'disabled', 'password', 'target_disabled'])
def test_worker_revalidates_admin_and_target_before_engine_mutation(users, monkeypatch, revoked):
    monkeypatch.setattr('services.provisioning.capacity_check', lambda *a, **kw: None)
    job = queue_create(users[2], spec(users[0]), {'public_key': 'unit-boundary-public-key'})
    if revoked == 'role':
        users[2].role = 'user'
    elif revoked == 'disabled':
        users[2].enabled = False
    elif revoked == 'password':
        users[2].set_password('Changed-before-worker-password!')
    else:
        users[0].enabled = False
    db.session.commit()
    engine = Mock()
    monkeypatch.setattr('services.provisioning.engine_for', lambda *a: engine)
    process_job(job.id)
    engine.create.assert_not_called()
    assert db.session.get(Job, job.id).status == 'failed'
    assert db.session.get(VPS, job.instance_id) is None


def test_unique_management_keys_activate_only_after_proven_seed_success(users, monkeypatch):
    monkeypatch.setattr('services.provisioning.capacity_check', lambda *a, **kw: None)
    first = queue_create(users[2], spec(users[0]), {'public_key': 'unit-owner-public-key'})
    other_spec = spec(users[1]) | {'name': 'unit-other'}
    second = queue_create(users[2], other_spec, {'public_key': 'unit-other-public-key'})
    first_data, second_data = decrypt(first.payload), decrypt(second.payload)
    assert first_data['control_private_key'] != second_data['control_private_key']
    assert not db.session.get(GuestAccess, first.instance_id)
    runtime = {'provisioned': True, 'network_restricted': True,
               'control_key_sha256': hashlib.sha256(first_data['credentials']['control_public_key'].encode()).hexdigest()}
    _apply_result(first, first_data, {'status': 'stopped', 'runtime': runtime, 'ssh_port': 22555})
    saved = db.session.get(GuestAccess, first.instance_id)
    assert decrypt(saved.private_key_encrypted)['private_key'] == first_data['control_private_key']
    assert 'PRIVATE KEY' not in saved.private_key_encrypted
    assert 'PRIVATE KEY' not in str(db.session.get(VPS, first.instance_id).spec())
    assert first.payload is None


def test_unproven_management_seed_never_activates_private_key(users, monkeypatch):
    monkeypatch.setattr('services.provisioning.capacity_check', lambda *a, **kw: None)
    job = queue_create(users[2], spec(users[0]), {})
    with pytest.raises(UncertainError, match='management public key'):
        _apply_result(job, decrypt(job.payload), {'status': 'stopped', 'runtime': {'provisioned': True}})
    assert not db.session.get(GuestAccess, job.instance_id)
    assert job.payload is not None


def test_users_have_separate_area_and_no_create_links_or_other_owner_data(client, users):
    own, other = vm(users[0]), vm(users[1])
    signin(client)
    page = client.get('/user')
    assert page.status_code == 200 and own.name.encode() in page.data and other.name.encode() not in page.data
    for path in ('/user', '/dashboard', '/vps', '/settings', f'/vps/{own.id}'):
        response = client.get(path)
        assert response.status_code == 200
        assert b'href="/vps/create"' not in response.data
        assert b'Host environment' not in response.data
    assert client.get(f'/vps/{other.id}').status_code == 404
    assert 'host' not in client.get('/api/metrics').json


@pytest.mark.parametrize('path', ['/vps/console', '/webssh', '/api/webssh/not-a-vm',
                                 '/vps/{id}/console', '/webssh/{id}', '/api/vps/{id}/console'])
def test_console_and_webssh_are_removed_even_for_administrator(client, users, path):
    instance = vm(users[0])
    signin(client, users[2].email)
    url = path.format(id=instance.id)
    assert client.get(url).status_code == 404
    assert post(client, url).status_code in (404, 405)


def test_link_is_encrypted_and_visible_only_to_owner_or_admin(app, client, users, monkeypatch, caplog):
    instance = vm(users[0])
    access(instance)
    save_session(instance, str(uuid.uuid4()), {'state': 'generated', 'link': SYNTHETIC_LINK,
                                              'fingerprint': PIN, 'seconds': 3600})
    db.session.commit()
    row = db.session.get(SSHXSession, instance.id)
    assert SYNTHETIC_LINK not in row.link_encrypted
    monkeypatch.setattr('services.resource_monitor.engine_for', lambda *a: Mock(metrics=lambda s: {'status': 'running', 'usage': {}}))
    signin(client)
    page = client.get(f'/vps/{instance.id}')
    assert page.status_code == 200 and SYNTHETIC_LINK.encode() in page.data
    assert b'rel="noopener noreferrer"' in page.data and b'referrerpolicy="no-referrer"' in page.data
    assert page.headers['Cache-Control'] == 'no-store'
    assert SYNTHETIC_LINK not in str(client.get('/api/metrics').json)
    other = app.test_client()
    signin(other, users[1].email)
    assert other.get(f'/vps/{instance.id}').status_code == 404
    assert post(other, f'/vps/{instance.id}/sshx/generate').status_code == 404
    assert other.get(f'/vps/{instance.id}/sshx/enroll').status_code == 404
    admin = app.test_client()
    signin(admin, users[2].email)
    assert SYNTHETIC_LINK.encode() in admin.get(f'/vps/{instance.id}').data
    assert SYNTHETIC_LINK not in caplog.text


def test_stale_expired_or_transferred_links_are_not_revealed(users):
    instance = vm(users[0])
    save_session(instance, str(uuid.uuid4()), {'state': 'generated', 'link': SYNTHETIC_LINK, 'fingerprint': PIN, 'seconds': 60})
    db.session.commit()
    assert visible_session(instance)['link'] == SYNTHETIC_LINK
    row = db.session.get(SSHXSession, instance.id)
    row.expires_at = utcnow() - timedelta(seconds=1)
    assert visible_session(instance) is None
    row.expires_at = utcnow() + timedelta(minutes=1)
    instance.owner_id = users[1].id
    assert visible_session(instance) is None


@pytest.mark.parametrize('action', ['network', 'assign'])
def test_owner_cannot_bypass_admin_network_or_assignment_controls(client, users, action):
    instance = vm(users[0])
    signin(client)
    assert post(client, f'/vps/{instance.id}/action/{action}', {'network_mode': 'internet', 'owner_id': users[1].id}).status_code == 403
    with pytest.raises(EngineError, match='administrator'):
        queue_action(users[0], instance, action)


def test_network_is_explicit_and_never_silently_relaxed(client, users):
    instance = vm(users[0], runtime={'network_restricted': True})
    access(instance)
    signin(client)
    post(client, f'/vps/{instance.id}/sshx/generate')
    assert db.session.scalar(db.select(db.func.count()).select_from(Job)) == 0
    assert instance.runtime['network_restricted'] is True
    admin = client.application.test_client()
    signin(admin, users[2].email)
    response = post(admin, f'/vps/{instance.id}/action/network', {'network_mode': 'internet'})
    assert response.status_code == 302
    assert db.session.scalar(db.select(db.func.count()).select_from(Job)) == 0
    assert instance.runtime['network_restricted'] is True


def test_incoming_assignment_reserves_new_owner_and_preserves_guest_key(users, monkeypatch):
    instance = vm(users[0])
    saved = access(instance).private_key_encrypted
    job = queue_action(users[2], instance, 'assign', {'owner_id': users[1].id, 'guest_credentials_reviewed': True})
    assert job.owner_id == users[1].id
    assert (job.ram_mb, job.vcpus, job.disk_gb) == (instance.ram_mb, instance.vcpus, instance.disk_gb)
    assert decrypt(job.payload)['actor_id'] == users[2].id
    engine = Mock()
    engine.assign.return_value = {'status': 'stopped', 'owner_id': users[1].id}
    monkeypatch.setattr('services.provisioning.engine_for', lambda *a: engine)
    process_job(job.id)
    db.session.expire_all()
    assert db.session.get(VPS, instance.id).owner_id == users[1].id
    assert db.session.get(GuestAccess, instance.id).private_key_encrypted == saved
    engine.assign.assert_called_once()


def test_failed_reinstall_keeps_current_management_key(users, monkeypatch):
    instance = vm(users[0])
    original = access(instance).private_key_encrypted
    job = queue_action(users[0], instance, 'reinstall', {'spec': instance.spec(), 'credentials': {'public_key': 'unit-owner'}})
    data = decrypt(job.payload)
    assert data['control_private_key'] != decrypt(original)['private_key']
    engine = Mock()
    engine.reinstall.side_effect = EngineError('Explicit unit boundary: preparation failed; old disk restored.')
    monkeypatch.setattr('services.provisioning.engine_for', lambda *a: engine)
    process_job(job.id)
    assert db.session.get(GuestAccess, instance.id).private_key_encrypted == original
    assert db.session.get(Job, job.id).status == 'failed'


def test_uncertain_sshx_allows_proven_guest_stop_but_not_new_mutations(users, monkeypatch):
    instance = vm(users[0])
    access(instance)
    unknown = Job(owner_id=users[0].id, instance_id=instance.id, kind='sshx_generate', engine='qemu', status='uncertain',
                  payload=encrypt({'spec': instance.spec()}))
    db.session.add(unknown)
    db.session.commit()
    with pytest.raises(EngineError, match='uncertain job'):
        queue_action(users[0], instance, 'sshx_generate')
    stop = queue_action(users[0], instance, 'force_stop')
    engine = Mock()
    engine.force_stop.return_value = {'status': 'stopped'}
    monkeypatch.setattr('services.provisioning.engine_for', lambda *a: engine)
    process_job(stop.id)
    assert db.session.get(Job, stop.id).status == 'completed'
    assert db.session.get(Job, unknown.id).status == 'failed'
    assert db.session.get(Job, unknown.id).payload is None


def test_sshx_recovery_inspects_operation_never_replays_installer(users, monkeypatch):
    instance = vm(users[0])
    access(instance)
    job = Job(owner_id=users[0].id, instance_id=instance.id, kind='sshx_generate', engine='qemu', status='uncertain',
              payload=encrypt({'spec': instance.spec(), 'actor_id': users[0].id}))
    db.session.add(job)
    db.session.commit()
    monkeypatch.setattr('services.provisioning.engine_for', lambda *a: Mock(metrics=lambda s: {'status': 'running'}))
    inspect = Mock(return_value={'state': 'generated', 'link': SYNTHETIC_LINK, 'fingerprint': PIN, 'seconds': 3600})
    monkeypatch.setattr('services.sshx.dispatch', inspect)
    reconcile_job(job)
    assert inspect.call_args.args[1] == 'inspect'
    assert db.session.get(Job, job.id).status == 'completed'
    assert visible_session(instance)['link'] == SYNTHETIC_LINK
    assert all(SYNTHETIC_LINK not in a.message for a in db.session.scalars(db.select(Audit)))


def test_fresh_guard_rejects_disabled_owner_and_reassignment(users):
    instance = vm(users[0])
    guard = GuestGuard(instance.spec(), users[0])
    guard(force=True)
    users[0].enabled = False
    db.session.commit()
    with pytest.raises(GuestAuthorityError):
        guard(force=True)


def test_cross_worker_admission_and_rate_limit(app, users):
    ident = str(uuid.uuid4())
    with admission('user:1', ident), admission('user:1', ident):
        with pytest.raises(EngineError, match='admission/rate'):
            with admission('user:1', ident):
                pytest.fail('Per-principal limit bypassed.')
    for _ in range(8):
        with admission('user:1', ident):
            pass
    with pytest.raises(EngineError, match='admission/rate'):
        with admission('user:1', ident):
            pytest.fail('Rate limit bypassed.')


@pytest.mark.parametrize('kind', ['create', 'sshx_generate'])
def test_admin_actor_cannot_be_deleted_while_working_for_another_owner(client, users, monkeypatch, kind):
    # Add a second administrator, since self-deletion is independently prohibited.
    actor = User(name='Other operator', email='other-operator@example.test', role='admin')
    actor.set_password('Other-operator-password!')
    db.session.add(actor)
    db.session.commit()
    monkeypatch.setattr('services.provisioning.capacity_check', lambda *a, **kw: None)
    if kind == 'create':
        queue_create(actor, spec(users[0]), {})
    else:
        instance = vm(users[0]); access(instance)
        queue_action(actor, instance, kind)
    signin(client, users[2].email)
    response = post(client, f'/admin/users/{actor.id}/delete', {'confirmation': actor.email})
    assert response.status_code == 302 and db.session.get(User, actor.id) is not None


@pytest.mark.parametrize('failure', ['enroll', 'verify', 'storage'])
def test_failed_enrollment_never_resets_guest_or_replaces_durable_saved_key(client, users, monkeypatch, failure):
    from sqlalchemy.exc import SQLAlchemyError
    instance = vm(users[0])
    saved = access(instance)
    previous, previous_pin = saved.private_key_encrypted, saved.host_fingerprint
    signin(client)
    secret = 'test-only-transient-guest-password-' + uuid.uuid4().hex
    seen = []
    def dispatch(spec, mode, **kwargs):
        assert spec['id'] == instance.id
        seen.append(mode)
        if mode == failure:
            raise EngineError('Synthetic guest boundary failure; no raw output.')
        if failure == 'storage' and mode == 'verify':
            monkeypatch.setattr(db.session, 'commit', lambda: (_ for _ in ()).throw(SQLAlchemyError('Synthetic storage failure')))
        if mode == 'enroll':
            assert kwargs['auth']['password'] == secret
            assert kwargs['public_key'].startswith('ssh-ed25519 ')
        return {'fingerprint': PIN, 'state': {'enroll': 'enrolled', 'verify': 'verified', 'probe': 'probed'}[mode]}
    monkeypatch.setattr('routes.sshx.sshx.dispatch', dispatch)
    if failure == 'storage':
        commit = db.session.commit
    response = post(client, f'/vps/{instance.id}/sshx/enroll', {'method': 'password', 'guest_password': secret,
                                                            'host_fingerprint': PIN, 'trust_host': '1'})
    if failure == 'storage':
        monkeypatch.setattr(db.session, 'commit', commit)
    assert response.status_code == 302 and response.location.endswith('/sshx/enroll')
    db.session.expire_all()
    row = db.session.get(GuestAccess, instance.id)
    assert row.private_key_encrypted == previous and row.host_fingerprint == previous_pin
    assert seen == (['enroll'] if failure == 'enroll' else ['enroll', 'verify'])
    assert db.session.scalar(db.select(db.func.count()).select_from(Job)) == 0
    messages = ' '.join(db.session.scalars(db.select(Audit.message)))
    leaked = secret in messages or secret.encode() in response.data
    assert not leaked, 'Transient guest credential was exposed.'


def test_unproven_engine_stop_cannot_retire_an_external_access_link(users):
    instance = vm(users[0])
    access(instance)
    save_session(instance, str(uuid.uuid4()), {'state': 'generated', 'fingerprint': PIN,
                                            'link': SYNTHETIC_LINK, 'seconds': 3600})
    job = Job(id=str(uuid.uuid4()), owner_id=users[0].id, instance_id=instance.id, kind='stop', engine='qemu')
    with pytest.raises(UncertainError, match='did not prove'):
        _apply_result(job, {'spec': instance.spec()}, {'status': 'running'})
    assert db.session.get(SSHXSession, instance.id).state == 'generated'
    assert visible_session(instance)['link'] == SYNTHETIC_LINK


@pytest.mark.parametrize('kind', ['sshx_generate', 'sshx_stop'])
def test_assigned_owner_can_poll_admin_requested_sshx_without_exposing_it_to_others(client, users, kind):
    instance = vm(users[0]); access(instance)
    job = queue_action(users[2], instance, kind)
    assert job.owner_id == users[0].id and decrypt(job.payload)['actor_id'] == users[2].id
    signin(client)
    assert client.get(f'/vps/jobs/{job.id}').status_code == 200
    status = client.get(f'/api/jobs/{job.id}')
    assert status.status_code == 200 and status.json['status'] == 'queued'
    assert 'payload' not in status.json and 'link' not in status.json
    outsider = client.application.test_client(); signin(outsider, users[1].email)
    assert outsider.get(f'/api/jobs/{job.id}').status_code == 404
    assert outsider.get(f'/vps/jobs/{job.id}').status_code == 404

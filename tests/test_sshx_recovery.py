"""Reinstall recovery with an explicit observational engine boundary, not native disks."""
import hashlib
from unittest.mock import Mock
import uuid

import pytest

from engines import EngineError
from extensions import db
from models import AgentInstance, AgentOperation
from services.guest_ssh import new_key
from services.node_worker import reconcile_operation
from services.recovery import inspect_outcome
from services.security import encrypt, instance_dir
from tests.test_provisioning import spec


@pytest.mark.parametrize('matching', [True, False])
def test_reinstall_needs_pending_unique_seed_key_not_previous_guest_generation(users, monkeypatch, matching):
    original = spec(users[0])
    requested = original | {'os_id': 'debian-12'}
    _, public = new_key()
    digest = hashlib.sha256(public.encode()).hexdigest()
    value = {'status': 'stopped', 'runtime': {'control_key_sha256': digest if matching else 'old-generation'},
             'ssh_port': original['ssh_port']}
    observe = Mock(return_value=value)
    monkeypatch.setattr('services.recovery._qemu_create', observe)
    payload = {'spec': requested, 'credentials': {'control_public_key': public}}
    if matching:
        assert inspect_outcome('reinstall', original, payload, Mock()) == value
    else:
        with pytest.raises(EngineError, match='unique key generation'):
            inspect_outcome('reinstall', original, payload, Mock())
    assert observe.call_args.args[1] == requested


def test_partial_reinstall_backup_is_never_reconciled_as_success(users, monkeypatch):
    original = spec(users[0])
    backup = instance_dir(original['id']).with_name(original['id'] + '.reinstall-backup')
    backup.mkdir(parents=True)
    observe = Mock()
    monkeypatch.setattr('services.recovery._qemu_create', observe)
    with pytest.raises(EngineError, match='backup still exists'):
        inspect_outcome('reinstall', original, {'spec': original, 'credentials': {'control_public_key': 'explicit-unused-boundary'}}, Mock())
    observe.assert_not_called()


def test_agent_reinstall_recovery_updates_existing_row_from_requested_not_old_spec(app, users, monkeypatch):
    app.config['TEST_MODE'] = False
    original = spec(users[0])
    requested = original | {'os_id': 'debian-12'}
    payload = {'kind': 'reinstall', 'spec': requested, 'credentials': {'control_public_key': 'test-observational-boundary'}}
    instance = AgentInstance(id=original['id'], spec=original)
    operation = AgentOperation(id=str(uuid.uuid4()), digest='0' * 64, payload=encrypt(payload), status='uncertain')
    db.session.add_all([instance, operation])
    db.session.commit()
    result = {'status': 'stopped', 'runtime': {'control_key_sha256': 'explicit-observation-fixture'}, 'ssh_port': original['ssh_port']}
    observe = Mock(return_value=result)
    engine = Mock()
    monkeypatch.setattr('services.recovery.inspect_outcome', observe)
    monkeypatch.setattr('services.node_worker.engine_for', lambda *_: engine)
    reconcile_operation(operation.id)
    assert observe.call_args.args == ('reinstall', requested, payload, engine)
    assert instance.spec['os_id'] == 'debian-12'
    assert instance.spec['runtime'] == result['runtime']
    assert db.session.scalar(db.select(db.func.count()).select_from(AgentInstance)) == 1
    assert operation.status == 'completed' and operation.payload is None

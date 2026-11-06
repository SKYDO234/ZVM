"""Admin workflows operate only on isolated temporary account/resource fixtures."""
from datetime import timedelta
import uuid
import pytest
from extensions import db
from models import Audit, Job, Plan, ProvisionTicket, User
from models.user import utcnow
from services.security import encrypt, settings
from services.validation import user_limits
from tests.conftest import signin, post
from tests.test_provisioning import fixture_vps


def test_delete_empty_account_preserves_audits_and_reused_id_revokes_old_session(app,client,users):
    ident=users[0].id
    signin(client)
    db.session.add(Audit(user_id=ident,action='account.fixture',message='Retained isolated audit.'))
    db.session.add(Job(owner_id=ident,instance_id=str(uuid.uuid4()),kind='create',engine='qemu',status='failed'))
    db.session.add(ProvisionTicket(owner_id=ident,payload=encrypt({}),expires_at=utcnow()+timedelta(minutes=1)))
    db.session.commit()
    admin=app.test_client();signin(admin,'operator@example.test')
    assert post(admin,f'/admin/users/{ident}/delete',{'confirmation':'alice@example.test'}).status_code==302
    assert db.session.get(User,ident) is None
    retained=db.session.scalar(db.select(Audit).where(Audit.action=='account.fixture'))
    assert retained and retained.user_id is None
    assert not list(db.session.scalars(db.select(Job).where(Job.owner_id==ident)))
    assert not list(db.session.scalars(db.select(ProvisionTicket).where(ProvisionTicket.owner_id==ident)))
    replacement=User(id=ident,email='replacement@example.test',name='Replacement')
    replacement.set_password('Test-only-password-123!')
    db.session.add(replacement);db.session.commit()
    assert client.get('/api/metrics').status_code==401
    fresh=app.test_client();signin(fresh,'replacement@example.test')
    assert fresh.get('/api/metrics').status_code==200


@pytest.mark.parametrize('resource',['instance','uncertain_job'])
def test_account_deletion_refuses_owned_resources_or_uncertain_work(client,users,resource):
    if resource=='instance':
        fixture_vps(users[0])
    else:
        db.session.add(Job(owner_id=users[0].id,instance_id=str(uuid.uuid4()),kind='create',engine='qemu',status='uncertain',payload=encrypt({})))
        db.session.commit()
    signin(client,'operator@example.test')
    response=post(client,f'/admin/users/{users[0].id}/delete',{'confirmation':users[0].email})
    assert response.status_code==302
    assert db.session.get(User,users[0].id)


def test_account_deletion_requires_confirmation_and_protects_current_admin(client,users):
    signin(client,'operator@example.test')
    post(client,f'/admin/users/{users[0].id}/delete')
    assert db.session.get(User,users[0].id)
    post(client,f'/admin/users/{users[2].id}/delete',{'confirmation':users[2].email})
    assert db.session.get(User,users[2].id).is_admin
    assert client.get('/admin').status_code==200


def test_admin_plan_assignment_and_persistent_settings_are_connected(client,users):
    signin(client,'operator@example.test')
    response=post(client,'/admin/plans',{'name':'Small workspace','max_instances':2,'ram_mb':1024,'vcpus':2,'disk_gb':16})
    assert response.status_code==302
    plan=db.session.scalar(db.select(Plan).where(Plan.name=='Small workspace'))
    assert plan
    post(client,f'/admin/users/{users[0].id}',{'enabled':'1','role':'user','plan_id':plan.id})
    assert user_limits(db.session.get(User,users[0].id))=={'max_instances':2,'ram_mb':1024,'vcpus':2,'disk_gb':16}
    s=settings()
    keys=['max_instances_per_user','max_ram_mb_per_user','max_vcpus_per_user','max_disk_gb_per_user',
          'max_instance_ram_mb','max_instance_vcpus','max_instance_disk_gb','max_instances_per_node','host_storage_reserve_gb']
    data={k:s[k] for k in keys}
    data.update(max_instances_per_user=2,registration_enabled='1',qemu_enabled='1',docker_enabled='1',restrict_guest_network='1')
    assert post(client,'/admin/settings',data).status_code==302
    assert settings()['max_instances_per_user']==2
    assert client.get('/admin').status_code==200


def test_ordinary_user_cannot_delete_any_account(client,users):
    signin(client)
    assert post(client,f'/admin/users/{users[1].id}/delete',{'confirmation':users[1].email}).status_code==403
    assert db.session.get(User,users[1].id)

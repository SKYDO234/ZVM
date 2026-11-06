import uuid
from unittest.mock import Mock
import pytest
from engines import EngineError
from extensions import db
from models import Job, VPS
from services.provisioning import process_job, queue_create
from services.security import encrypt
from services.validation import clean_spec, quota_check
from tests.conftest import signin, post


def spec(user):
    return {'id':str(uuid.uuid4()), 'owner_id':user.id, 'name':'TEST-01', 'engine':'qemu', 'os_id':'ubuntu-24.04',
            'ram_mb':2048, 'vcpus':2, 'disk_gb':20, 'username':'ubuntu', 'ssh_port':22555, 'runtime':{}, 'forwards':[]}


def fixture_vps(user):
    data = spec(user)
    data.pop('forwards')
    vps = VPS(**data)
    db.session.add(vps); db.session.commit()
    return vps


def test_ownership_on_every_access_path(client, users):
    vps = fixture_vps(users[1])
    signin(client)
    for path in [f'/vps/{vps.id}', f'/vps/{vps.id}/console', f'/api/vps/{vps.id}/metrics', f'/api/vps/{vps.id}/console']:
        assert client.get(path).status_code == 404
    assert post(client, f'/vps/{vps.id}/action/delete').status_code == 404


def test_allocation_is_never_host_capacity(client, users, monkeypatch):
    vps = fixture_vps(users[0])
    monkeypatch.setattr('services.resource_monitor.engine_for', lambda *a: Mock(metrics=lambda s:{'status':'stopped','usage':{'disk_actual_bytes':12345}}))
    signin(client)
    result = client.get('/api/metrics').json
    assert result['instances'][0]['allocation'] == {'ram_mb':2048,'vcpus':2,'disk_gb':20}
    assert result['totals']['ram_mb'] == 2048 and result['totals']['disk_gb'] == 20
    assert result['host']['ram_total_mb'] > 0
    assert result['instances'][0]['usage']['disk_actual_bytes'] == 12345
    assert client.get(f'/vps/{vps.id}').status_code == 200


def test_quota_includes_uncertain_and_pending_jobs(users):
    for _ in range(3):
        db.session.add(Job(owner_id=users[0].id, instance_id=str(uuid.uuid4()), kind='create',engine='qemu',
                           status='uncertain',ram_mb=512,vcpus=1,disk_gb=8,payload=encrypt({})))
    db.session.commit()
    with pytest.raises(EngineError, match='quota reached'):
        quota_check(users[0], spec(users[0]))


def test_per_user_ram_and_disk_quota(users):
    s = spec(users[0]); s['ram_mb'] = 8192
    with pytest.raises(EngineError, match='RAM allocation'):
        quota_check(users[0],s)
    s['ram_mb']=512;s['disk_gb']=100
    with pytest.raises(EngineError, match='Disk allocation'):
        quota_check(users[0],s)


def test_strict_inputs_and_guest_password_hashing(users):
    data={'name':'safe-vm','engine':'qemu','os_id':'ubuntu-24.04','ram_mb':'1024','vcpus':'1','disk_gb':'10',
          'username':'ubuntu','auth_method':'password','guest_password':'Never-store-me-123!'}
    cleaned, creds = clean_spec(data,users[0].id)
    assert cleaned['ram_mb'] == 1024 and creds['password_hash'].startswith('$6$')
    assert 'Never-store-me' not in str(creds)
    for key,value in [('name','../../etc/passwd'),('vcpus','1;rm -rf /'),('ram_mb','0'),('username','root'),('forwards','123:bad')]:
        with pytest.raises(EngineError):
            clean_spec(data | {key:value},users[0].id)


def test_test_mode_cannot_create_records(app, users):
    app.config['TEST_MODE'] = True
    with pytest.raises(EngineError,match='Test mode'):
        queue_create(users[0],spec(users[0]),{})
    assert db.session.scalar(db.select(db.func.count()).select_from(VPS)) == 0
    assert db.session.scalar(db.select(db.func.count()).select_from(Job)) == 0


def test_real_boundary_failure_never_creates_vps(users,monkeypatch):
    data=spec(users[0]);job=Job(id=str(uuid.uuid4()),owner_id=users[0].id,instance_id=data['id'],kind='create',engine='qemu',
                               ram_mb=2048,vcpus=2,disk_gb=20,payload=encrypt({'spec':data,'credentials':{}}))
    db.session.add(job);db.session.commit()
    monkeypatch.setattr('services.provisioning.capacity_check',lambda *a,**kw:None)
    engine=Mock();engine.create.side_effect=EngineError('Actual engine could not run.')
    monkeypatch.setattr('services.provisioning.engine_for',lambda *a:engine)
    process_job(job.id)
    assert db.session.get(Job,job.id).status == 'failed'
    assert db.session.get(VPS,data['id']) is None


def test_record_is_inserted_only_after_explicit_mock_boundary_success(users,monkeypatch):
    # Unit-only fake engine boundary. Not a demo mode and never used by the running application.
    data=spec(users[0]);job=Job(id=str(uuid.uuid4()),owner_id=users[0].id,instance_id=data['id'],kind='create',engine='qemu',
                               ram_mb=2048,vcpus=2,disk_gb=20,payload=encrypt({'spec':data,'credentials':{}}))
    db.session.add(job);db.session.commit()
    monkeypatch.setattr('services.provisioning.capacity_check',lambda *a,**kw:None)
    engine=Mock();engine.create.return_value={'status':'stopped','runtime':{'provisioned':True},'ssh_port':22555}
    monkeypatch.setattr('services.provisioning.engine_for',lambda *a:engine)
    process_job(job.id)
    vps=db.session.get(VPS,data['id'])
    assert vps and (vps.ram_mb,vps.vcpus,vps.disk_gb)==(2048,2,20)
    assert db.session.get(Job,job.id).status=='completed'
    assert db.session.get(Job,job.id).payload is None


def test_missing_dependency_error_is_visible_without_fake_vps(client,users,monkeypatch):
    monkeypatch.setattr('engines.qemu_engine.shutil.which',lambda name:None)
    signin(client)
    response=post(client,'/vps/create',{'name':'not-created','engine':'qemu','os_id':'ubuntu-24.04','ram_mb':512,'vcpus':1,
                  'disk_gb':8,'username':'ubuntu','auth_method':'password','guest_password':'Valid-guest-password!'},token_path='/vps/create')
    assert response.status_code==200
    assert b'Missing userspace dependencies' in response.data
    assert db.session.scalar(db.select(db.func.count()).select_from(VPS))==0


def test_database_persistence(app,users):
    from skvm import create_app
    uri=app.config['SQLALCHEMY_DATABASE_URI'];data=app.config['DATA_DIR']
    db.session.remove()
    second=create_app({'TESTING':True,'DATA_DIR':data,'SQLALCHEMY_DATABASE_URI':uri,'START_WORKER':False})
    with second.app_context():
        from models import User
        assert db.session.scalar(db.select(db.func.count()).select_from(User))==3

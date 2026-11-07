"""Read-only recovery uses explicit mocked OS boundaries, never real guests."""
import copy
import json
import hashlib
import uuid
from unittest.mock import Mock
import pytest
from docker.errors import NotFound
from engines import EngineError
from extensions import db
from models import AgentInstance, AgentOperation, Job, VPS
from services.image_manager import ImageManager
from services.node_worker import process_operation, reconcile_operation
from services.provisioning import process_job, reconcile_job
from services.recovery import inspect_outcome
from services.security import atomic_json, encrypt, instance_dir
from tests.test_provisioning import spec

pytestmark=pytest.mark.usefixtures('app')


def proof_files(data):
    directory=instance_dir(data['id']);directory.mkdir(exist_ok=True)
    (directory/'disk.qcow2').write_bytes(b'unit-boundary-no-real-qcow2')
    seed=bytearray(17*2048);seed[16*2048:16*2048+7]=b'\x01CD001\x01'
    seed[16*2048+40:16*2048+72]=b'cidata'.ljust(32,b' ')
    (directory/'seed.iso').write_bytes(seed)
    saved=copy.deepcopy(data)
    saved['runtime']={'provisioned':True,'storage_enforced':True,'accel':'tcg','network_restricted':True,'forwards':[]}
    atomic_json(directory/'config.json',saved)
    return directory,saved


def uncertain(user,data,kind='create',extra=None):
    payload={'spec':data,**(extra or {})}
    job=Job(owner_id=user.id,instance_id=data['id'],kind=kind,engine=data['engine'],status='uncertain',
            ram_mb=data['ram_mb'] if kind=='create' else 0,vcpus=data['vcpus'] if kind=='create' else 0,
            disk_gb=data['disk_gb'] if kind=='create' else 10,payload=encrypt(payload))
    db.session.add(job);db.session.commit();return job


def mock_qcow(monkeypatch,capacity):
    monkeypatch.setattr(ImageManager,'inspect',lambda path:{'format':'qcow2','virtual-size':capacity*2**30})
    reader=Mock(return_value='No errors were found.')
    monkeypatch.setattr('services.recovery.run',reader)
    return reader


def record(data):
    data={k:v for k,v in data.items() if k not in ('forwards','allow_unenforced_storage')}
    result=VPS(**data);db.session.add(result);db.session.commit();return result


def test_create_recovery_requires_actual_disk_seed_and_matching_manifest(users,monkeypatch):
    data=spec(users[0]);proof_files(data);job=uncertain(users[0],data)
    reader=mock_qcow(monkeypatch,20);engine=Mock()
    monkeypatch.setattr('services.provisioning.engine_for',lambda *a:engine)
    reconcile_job(job)
    assert db.session.get(VPS,data['id']).ram_mb==2048
    assert job.status=='completed' and job.payload is None
    assert reader.call_args.args[0][:2]==['qemu-img','check']
    engine.create.assert_not_called();engine.start.assert_not_called()


@pytest.mark.parametrize('damage',['missing-disk','invalid-seed','foreign-id','wrong-ram','wrong-capacity'])
def test_incomplete_or_mismatched_creation_keeps_uncertain_reservation(users,monkeypatch,damage):
    data=spec(users[0]);directory,saved=proof_files(data);job=uncertain(users[0],data)
    if damage=='missing-disk':(directory/'disk.qcow2').unlink()
    if damage=='invalid-seed':(directory/'seed.iso').write_bytes(b'not an iso')
    if damage=='foreign-id':saved['id']=str(uuid.uuid4());atomic_json(directory/'config.json',saved)
    if damage=='wrong-ram':saved['ram_mb']=True;atomic_json(directory/'config.json',saved)
    mock_qcow(monkeypatch,30 if damage=='wrong-capacity' else 20)
    engine=Mock();monkeypatch.setattr('services.provisioning.engine_for',lambda *a:engine)
    with pytest.raises(EngineError):reconcile_job(job)
    assert job.status=='uncertain' and job.payload
    assert db.session.get(VPS,data['id']) is None
    engine.create.assert_not_called();engine.delete.assert_not_called()


def test_resize_recovery_observes_target_and_only_synchronizes_metadata(users,monkeypatch):
    data=spec(users[0]);directory,_=proof_files(data);instance=record(data)
    job=uncertain(users[0],data,'resize',{'disk_gb':30})
    reader=mock_qcow(monkeypatch,30);engine=Mock()
    monkeypatch.setattr('services.provisioning.engine_for',lambda *a:engine)
    reconcile_job(job)
    assert instance.disk_gb==30 and job.status=='completed'
    assert json.loads((directory/'config.json').read_text())['disk_gb']==30
    assert all(call.args[0][1]!='resize' for call in reader.call_args_list)
    engine.resize.assert_not_called()


def test_resize_not_applied_is_not_replayed_or_reported_success(users,monkeypatch):
    data=spec(users[0]);directory,_=proof_files(data);instance=record(data)
    job=uncertain(users[0],data,'resize',{'disk_gb':30});mock_qcow(monkeypatch,20)
    engine=Mock();monkeypatch.setattr('services.provisioning.engine_for',lambda *a:engine)
    with pytest.raises(EngineError,match='Actual QCOW2'):
        reconcile_job(job)
    assert instance.disk_gb==20 and job.status=='uncertain'
    assert json.loads((directory/'config.json').read_text())['disk_gb']==20
    engine.resize.assert_not_called()


def test_running_state_recovery_validates_actual_qemu_allocations_and_accelerator(users,monkeypatch):
    data=spec(users[0]);instance=record(data);job=uncertain(users[0],data,'start')
    engine=Mock();engine.metrics.return_value={'status':'running'}
    engine._process.return_value.cmdline.return_value=['qemu-system-x86_64','-m','2048','-smp','2','-machine','type=pc,accel=kvm']
    monkeypatch.setattr('services.provisioning.engine_for',lambda *a:engine)
    reconcile_job(job)
    assert job.status=='completed' and instance.runtime['accel']=='kvm'
    engine.start.assert_not_called();engine.stop.assert_not_called()


def test_suspend_recovery_does_not_claim_a_running_guest_is_stopped(users,monkeypatch):
    data=spec(users[0]);instance=record(data);job=uncertain(users[0],data,'suspend')
    engine=Mock();engine.metrics.return_value={'status':'running'}
    monkeypatch.setattr('services.provisioning.engine_for',lambda *a:engine)
    with pytest.raises(EngineError,match='does not prove'):
        reconcile_job(job)
    assert not instance.suspended and job.status=='uncertain'
    engine.stop.assert_not_called()


def test_delete_recovery_checks_absence_without_deleting_anything(users,monkeypatch):
    data=spec(users[0]);record(data);job=uncertain(users[0],data,'delete')
    engine=Mock();monkeypatch.setattr('services.provisioning.engine_for',lambda *a:engine)
    reconcile_job(job)
    assert job.status=='completed' and db.session.get(VPS,data['id']) is None
    engine.delete.assert_not_called()


def docker_boundary(data):
    name=f'skvm-net-{data["id"]}'
    container=Mock(id='test-container',status='running',attrs={
        'Image':'sha256:test-image','Config':{'User':'1000:1000','Labels':{'skvm.managed':'true','skvm.os_id':data['os_id']}},
        'HostConfig':{'Memory':data['ram_mb']*2**20,'MemorySwap':data['ram_mb']*2**20,'NanoCpus':data['vcpus']*10**9,
                      'Privileged':False,'CapDrop':['ALL'],'PidsLimit':128,'SecurityOpt':['no-new-privileges:true']},
        'NetworkSettings':{'Networks':{name:{}}}})
    client=Mock();client.__enter__=Mock(return_value=client);client.__exit__=Mock(return_value=False)
    client.networks.get.return_value=Mock(attrs={'Internal':True,'Labels':{'skvm.instance':data['id'],'skvm.managed':'true'}})
    engine=Mock();engine._client.return_value=client;engine._container.return_value=container
    return engine,client,container


def test_docker_recovery_preserves_real_running_state_and_isolated_network(users):
    data=spec(users[0])|{'engine':'docker','allow_unenforced_storage':True}
    engine,client,container=docker_boundary(data)
    result=inspect_outcome('create',data,{'spec':data},engine)
    assert result['status']=='running' and result['runtime']['network']==f'skvm-net-{data["id"]}'
    assert result['runtime']['storage_enforced'] is False
    container.start.assert_not_called();client.containers.create.assert_not_called()


@pytest.mark.parametrize('mismatch',['memory','host-mount','public-network','pid-limit','device','shared-namespace'])
def test_docker_recovery_refuses_configuration_drift(users,mismatch):
    data=spec(users[0])|{'engine':'docker','allow_unenforced_storage':True}
    engine,client,container=docker_boundary(data)
    if mismatch=='memory':container.attrs['HostConfig']['Memory']=1
    if mismatch=='host-mount':container.attrs['HostConfig']['Binds']=['/:/host']
    if mismatch=='public-network':client.networks.get.return_value.attrs['Internal']=False
    if mismatch=='pid-limit':container.attrs['HostConfig']['PidsLimit']=0
    if mismatch=='device':container.attrs['HostConfig']['Devices']=[{'PathOnHost':'/dev/kvm'}]
    if mismatch=='shared-namespace':container.attrs['HostConfig']['PidMode']='container:foreign'
    with pytest.raises(EngineError):inspect_outcome('create',data,{},engine)
    container.remove.assert_not_called()


def test_delete_recovery_does_not_erase_an_orphan_network(users):
    data=spec(users[0])|{'engine':'docker'}
    engine,client,_=docker_boundary(data);engine._container.return_value=None
    with pytest.raises(EngineError,match='network still exists'):
        inspect_outcome('delete',data,{},engine)
    client.networks.get.return_value.remove.assert_not_called()
    client.networks.get.side_effect=NotFound('absent')
    assert inspect_outcome('delete',data,{},engine)['status']=='deleted'


@pytest.mark.parametrize('agent',[False,True])
def test_lost_commit_ack_does_not_downgrade_durable_completion(users,monkeypatch,agent):
    data=spec(users[0]);ident=str(uuid.uuid4())
    model=AgentOperation if agent else Job
    if agent:
        row=AgentOperation(id=ident,digest='isolated-commit-test',payload=encrypt({'kind':'create','spec':data,'credentials':{}}))
    else:
        row=Job(id=ident,owner_id=users[0].id,instance_id=data['id'],kind='create',engine='qemu',ram_mb=2048,vcpus=2,disk_gb=20,
                payload=encrypt({'spec':data,'credentials':{},'actor_id':users[2].id}))
    db.session.add(row);db.session.commit()
    module='services.node_worker' if agent else 'services.provisioning'
    monkeypatch.setattr(module+'.engine_for',lambda *a:Mock(create=lambda s,c,**kw:{'runtime':{'test_boundary':True, **({'control_key_sha256':hashlib.sha256(c['control_public_key'].encode()).hexdigest()} if c.get('control_public_key') else {})},'status':'stopped','ssh_port':22555}))
    if agent:monkeypatch.setattr(module+'.enforce_capacity',lambda *a,**kw:None)
    else:
        monkeypatch.setattr(module+'.capacity_check',lambda *a,**kw:None)
        monkeypatch.setattr(module+'.validate_ports',lambda *a,**kw:None)
    real=db.session.commit;lost=[]
    def commit():
        completed=db.session.get(model,ident).status=='completed'
        real()
        if completed and not lost:
            lost.append(True);raise OSError('simulated acknowledgement lost AFTER actual SQLite commit')
    monkeypatch.setattr(db.session,'commit',commit)
    (process_operation if agent else process_job)(ident)
    db.session.expire_all()
    assert lost and db.session.get(model,ident).status=='completed'
    assert db.session.get(model,ident).payload is None
    assert db.session.get(AgentInstance if agent else VPS,data['id'])


def test_agent_recovery_updates_disk_metadata_without_repeating_resize(users,monkeypatch):
    data=spec(users[0]);proof_files(data);mock_qcow(monkeypatch,30)
    db.session.add(AgentInstance(id=data['id'],spec=data))
    ident=str(uuid.uuid4())
    db.session.add(AgentOperation(id=ident,digest='test',status='uncertain',payload=encrypt({'kind':'resize','spec':data,'disk_gb':30})))
    db.session.commit();engine=Mock()
    monkeypatch.setattr('services.node_worker.engine_for',lambda *a:engine)
    reconcile_operation(ident)
    db.session.expire_all()
    assert db.session.get(AgentInstance,data['id']).spec['disk_gb']==30
    assert db.session.get(AgentOperation,ident).status=='completed'
    engine.resize.assert_not_called()

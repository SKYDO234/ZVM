import json
import uuid
from pathlib import Path
from unittest.mock import Mock
import pytest
from engines import EngineError
from engines.docker_engine import DockerEngine
from engines.qemu_engine import QemuEngine
from extensions import db
from models import AgentInstance, AgentOperation, Job, OSImage, ProvisionTicket, VPS
from services.image_manager import ImageManager
from services.node_worker import process_operation
from services.security import encrypt, instance_dir, ssh_key
from services.validation import capacity_check
from tests.conftest import signin, post
from tests.test_provisioning import spec


def test_confirmation_is_one_time_and_does_not_create_fake_record(client,users,monkeypatch):
    monkeypatch.setattr('routes.vps.capacity_check',lambda *a,**kw:None)
    monkeypatch.setattr('services.provisioning.capacity_check',lambda *a,**kw:None)
    signin(client,'operator@example.test')
    response=post(client,'/vps/create',{'name':'review-only','engine':'qemu','os_id':'ubuntu-24.04','ram_mb':512,'vcpus':1,
                   'disk_gb':8,'username':'ubuntu','auth_method':'password','guest_password':'Valid-guest-password!'},token_path='/vps/create')
    assert response.status_code==200 and b'Confirm & provision' in response.data
    assert b'Valid-guest-password!' not in response.data
    ticket=db.session.scalar(db.select(ProvisionTicket))
    assert ticket and 'Valid-guest-password' not in ticket.payload
    assert db.session.scalar(db.select(db.func.count()).select_from(VPS))==0
    submitted=post(client,f'/vps/provision/{ticket.id}')
    assert submitted.status_code==302 and '/vps/jobs/' in submitted.location
    assert db.session.scalar(db.select(db.func.count()).select_from(Job))==1
    post(client,f'/vps/provision/{ticket.id}')
    assert db.session.scalar(db.select(db.func.count()).select_from(Job))==1
    assert db.session.scalar(db.select(db.func.count()).select_from(VPS))==0


def test_qemu_creation_makes_independent_copy_and_stopped_manifest(app,users,monkeypatch,tmp_path):
    data=spec(users[0]);data['forwards']=[{'host':22501,'guest':80}]
    monkeypatch.setattr(QemuEngine,'capabilities',lambda self:{'available':True,'accel':'tcg'})
    monkeypatch.setattr(ImageManager,'obtain',lambda self,image:tmp_path/'base.qcow2')
    monkeypatch.setattr(ImageManager,'inspect',lambda path:{'virtual-size':2*2**30,'format':'qcow2'})
    calls=[]
    def boundary(args,**kw):
        calls.append([str(a) for a in args])
        if args[1]=='convert':Path(args[-1]).write_bytes(b'unit-test-only-disk')
        if args[0]=='cloud-localds':Path(args[1]).write_bytes(b'unit-test-only-seed')
        return ''
    monkeypatch.setattr('engines.qemu_engine.run',boundary)
    result=QemuEngine().create(data,{'password_hash':'$6$test-only'})
    directory=instance_dir(data['id'])
    assert result['status']=='stopped' and (directory/'disk.qcow2').exists()
    convert=next(c for c in calls if c[1]=='convert')
    assert convert[2:6]==['-f','qcow2','-O','qcow2'] and '-b' not in convert
    saved=json.loads((directory/'config.json').read_text())
    assert (saved['ram_mb'],saved['vcpus'],saved['disk_gb'])==(2048,2,20)
    assert saved['runtime']['forwards']==[{'host':22501,'guest':80}]
    assert db.session.scalar(db.select(db.func.count()).select_from(VPS))==0


def test_docker_sdk_applies_limits_without_privilege_or_socket(app,users,monkeypatch):
    data=spec(users[0])|{'engine':'docker','username':None,'ssh_port':None,'allow_unenforced_storage':True}
    client=Mock();client.__enter__=Mock(return_value=client);client.__exit__=Mock(return_value=False)
    image=Mock(id='sha256:unit-test-image',attrs={'RepoDigests':['ubuntu@sha256:unit-test']})
    client.images.pull.return_value=image
    client.networks.get.return_value=Mock(name='unit-test-internal',attrs={'Internal':True,'Labels':{'skvm.managed':'true','skvm.instance':data['id']}})
    client.containers.create.return_value=Mock(id='unit-test-container-id')
    monkeypatch.setattr(DockerEngine,'capabilities',lambda self:{'available':True,'storage_limits':False})
    monkeypatch.setattr(DockerEngine,'_client',lambda *a,**kw:client)
    monkeypatch.setattr(DockerEngine,'_container',lambda *a:None)
    result=DockerEngine().create(data)
    config=client.containers.create.call_args.kwargs
    assert config['mem_limit']=='2048m' and config['nano_cpus']==2_000_000_000
    assert config['cap_drop']==['ALL'] and config['privileged'] is False
    assert config['user']=='1000:1000' and 'volumes' not in config
    assert config['security_opt']==['no-new-privileges:true']
    assert config['storage_opt'] is None and not result['runtime']['storage_enforced']
    assert result['ssh_port'] is None and result['status']=='stopped'


def test_docker_refuses_fake_hard_storage_limit(app,users,monkeypatch):
    monkeypatch.setattr(DockerEngine,'capabilities',lambda self:{'available':True,'storage_limits':False})
    with pytest.raises(EngineError,match='no verified size quotas'):
        DockerEngine().create(spec(users[0])|{'engine':'docker','allow_unenforced_storage':False})


def test_docker_rejects_unauthenticated_tcp(app,monkeypatch):
    monkeypatch.setenv('DOCKER_HOST','tcp://docker.example.test:2375')
    monkeypatch.delenv('DOCKER_TLS_VERIFY',raising=False)
    with pytest.raises(EngineError,match='panel-host capacity'):
        with DockerEngine()._client():pytest.fail('Remote direct daemon must be rejected')


def test_actual_host_capacity_can_deny_a_plan_permitted_request(app,users,monkeypatch):
    monkeypatch.setattr('services.validation.engine_for',lambda *a:Mock(capabilities=lambda:{'available':True}))
    host={'ram_total_mb':4096,'ram_available_mb':3500,'cpu_capacity':2,'disk_free_gb':15}
    monkeypatch.setattr('services.validation.host_metrics',lambda:host)
    with pytest.raises(EngineError,match='storage'):
        capacity_check(spec(users[0]))
    host['disk_free_gb']=100;host['cpu_capacity']=1
    with pytest.raises(EngineError,match='vCPU'):
        capacity_check(spec(users[0]))
    host['cpu_capacity']=2;host['ram_available_mb']=1024
    with pytest.raises(EngineError,match='currently available'):
        capacity_check(spec(users[0]))


def test_image_check_records_actual_failure_and_success(app,monkeypatch):
    image=db.session.get(OSImage,'ubuntu-24.04')
    monkeypatch.setattr(ImageManager,'_request',Mock(side_effect=EngineError('HTTPS network is blocked')))
    with pytest.raises(EngineError):ImageManager().verify(image)
    assert image.verification=='unavailable' and 'blocked' in image.verification_message
    response=Mock();response.__enter__=Mock(return_value=response);response.__exit__=Mock(return_value=False)
    response.iter_content.return_value=iter([b'QFI\xfb'])
    monkeypatch.setattr(ImageManager,'_request',Mock(return_value=response))
    ImageManager().verify(image)
    assert image.verification=='verified' and image.verified_at


def test_agent_test_mode_never_creates_instances(app,users):
    app.config['TEST_MODE']=True
    ident=str(uuid.uuid4());data={'id':ident,'kind':'create','spec':spec(users[0]),'credentials':{}}
    operation=AgentOperation(id=ident,digest='unit-test-digest',payload=encrypt(data))
    db.session.add(operation);db.session.commit();process_operation(ident)
    assert db.session.get(AgentOperation,ident).status=='failed'
    assert db.session.scalar(db.select(db.func.count()).select_from(AgentInstance))==0


def test_ssh_public_key_parser_rejects_fake_or_option_prefixed_keys():
    for value in ['ssh-ed25519 AAAA', 'command="sudo whoami" ssh-ed25519 AAAA', 'ssh-rsa '+('A'*100)]:
        with pytest.raises(EngineError):ssh_key(value)


def test_ssh_public_key_parser_accepts_real_ed25519():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
    key=Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.OpenSSH,PublicFormat.OpenSSH).decode()
    assert ssh_key(key+' testing@example')==key


def test_log_maintenance_bounds_files_without_following_symlinks(tmp_path):
    from services.maintenance import trim_log
    log=tmp_path/'serial.log';log.write_bytes(b'old content'*500+b'latest bytes')
    trim_log(log,maximum=1024,keep=100)
    assert log.stat().st_size==100 and log.read_bytes().endswith(b'latest bytes')
    target=tmp_path/'untouched';target.write_bytes(b'keep me'*100)
    link=tmp_path/'link';link.symlink_to(target)
    trim_log(link,maximum=10,keep=1)
    assert target.read_bytes()==b'keep me'*100


def test_secret_initialization_is_private_and_stable(tmp_path):
    from config import private_file
    path=tmp_path/'session-secret'
    assert private_file(path,lambda:'first-secret')=='first-secret'
    assert private_file(path,lambda:'should-not-replace')=='first-secret'
    assert path.stat().st_mode & 0o777 == 0o600


def test_agent_resize_persists_changed_disk_despite_engine_mutating_spec(app,users,monkeypatch):
    data=spec(users[0])
    db.session.add(AgentInstance(id=data['id'],spec=data))
    ident=str(uuid.uuid4())
    db.session.add(AgentOperation(id=ident,digest='unit-test-only',payload=encrypt({'id':ident,'kind':'resize','spec':{'id':data['id']},'disk_gb':30})))
    db.session.commit()
    monkeypatch.setattr('services.node_worker.enforce_capacity',lambda *a,**kw:None)
    def resize_boundary(s,size):
        s['disk_gb']=size  # Mirrors the real QEMU manifest update.
        return {'disk_gb':size}
    monkeypatch.setattr('services.node_worker.engine_for',lambda *a:Mock(resize=resize_boundary))
    process_operation(ident)
    db.session.expire_all()
    assert db.session.get(AgentInstance,data['id']).spec['disk_gb']==30
    assert db.session.get(AgentOperation,ident).status=='completed'


def test_docker_delete_retries_orphan_network_cleanup_even_without_container(app,users,monkeypatch):
    data=spec(users[0])|{'engine':'docker'}
    client=Mock();client.__enter__=Mock(return_value=client);client.__exit__=Mock(return_value=False)
    network=Mock(attrs={'Labels':{'skvm.managed':'true','skvm.instance':data['id']},'Containers':{}})
    client.networks.get.return_value=network
    monkeypatch.setattr(DockerEngine,'_client',lambda *a,**kw:client)
    monkeypatch.setattr(DockerEngine,'_container',lambda *a:None)
    assert DockerEngine().delete(data)['status']=='deleted'
    network.remove.assert_called_once()


def test_docker_known_create_rejection_cleans_its_network(app,users,monkeypatch):
    from docker.errors import APIError
    data=spec(users[0])|{'engine':'docker','allow_unenforced_storage':True}
    client=Mock();client.__enter__=Mock(return_value=client);client.__exit__=Mock(return_value=False)
    network=Mock(attrs={'Internal':True,'Labels':{'skvm.managed':'true','skvm.instance':data['id']},'Containers':{}})
    client.networks.get.return_value=network
    client.containers.create.side_effect=APIError('quota rejected',response=Mock(status_code=400,reason='Bad Request'),explanation='quota rejected')
    monkeypatch.setattr(DockerEngine,'_client',lambda *a,**kw:client)
    monkeypatch.setattr(DockerEngine,'_container',lambda *a:None)
    monkeypatch.setattr(DockerEngine,'capabilities',lambda self:{'available':True,'storage_limits':False})
    with pytest.raises(EngineError,match='quota rejected'):
        DockerEngine().create(data)
    network.remove.assert_called_once()


def test_even_tls_remote_docker_uses_agent_for_correct_host_capacity(app,monkeypatch):
    monkeypatch.setenv('DOCKER_HOST','tcp://remote-docker.example.test:2376')
    monkeypatch.setenv('DOCKER_TLS_VERIFY','1')
    cap=DockerEngine().capabilities()
    assert not cap['available'] and 'panel-host capacity' in cap['reason']


def test_worker_audit_without_request_context(app):
    from services.security import audit
    from models import Audit
    audit('worker.unit-test','Real audit insertion in an isolated temporary database.')
    db.session.commit()
    row=db.session.scalar(db.select(Audit))
    assert row.action=='worker.unit-test' and row.user_id is None


@pytest.mark.parametrize('state',['queued','uncertain'])
def test_disk_growth_reservations_survive_uncertainty_and_admin_actor(app,users,monkeypatch,state):
    from services.provisioning import queue_action
    from services.validation import quota_check
    from tests.test_provisioning import fixture_vps
    instance=fixture_vps(users[0])
    monkeypatch.setattr('services.provisioning.capacity_check',lambda *a,**kw:None)
    job=queue_action(users[2],instance,'resize',{'disk_gb':30})
    assert job.owner_id==users[2].id and job.disk_gb==10
    job.status=state;db.session.commit()
    candidate=spec(users[0])|{'name':'different','ram_mb':512,'vcpus':1,'disk_gb':40}
    with pytest.raises(EngineError,match='Disk allocation'):
        quota_check(users[0],candidate)
    monkeypatch.setattr('services.validation.engine_for',lambda *a:Mock(capabilities=lambda:{'available':True}))
    monkeypatch.setattr('services.validation.host_metrics',lambda:{'ram_total_mb':8192,'ram_available_mb':8192,'cpu_capacity':8,'disk_free_gb':50})
    with pytest.raises(EngineError,match='host storage'):
        capacity_check(candidate|{'disk_gb':20})


def test_agent_reserves_uncertain_disk_growth(app,users,monkeypatch):
    from services.node_worker import enforce_capacity
    data=spec(users[0])|{'ram_mb':512,'vcpus':1}
    db.session.add(AgentInstance(id=data['id'],spec=data))
    db.session.add(AgentOperation(id=str(uuid.uuid4()),digest='test-growth',status='uncertain',
                   payload=encrypt({'kind':'resize','spec':{'id':data['id']},'disk_gb':30})))
    db.session.commit()
    monkeypatch.setattr('services.node_worker.host_metrics',lambda:{'ram_total_mb':8192,'ram_available_mb':8192,'cpu_capacity':8,'disk_free_gb':50})
    with pytest.raises(EngineError,match='storage budget'):
        enforce_capacity(data|{'id':str(uuid.uuid4())})


def test_docker_cpu_uses_measured_counter_history_when_one_shot_omits_previous():
    from engines.docker_engine import _cpu_percent
    ident='isolated-cpu-'+str(uuid.uuid4())
    assert _cpu_percent(ident,{'cpu_usage':{'total_usage':1000},'system_cpu_usage':5000,'online_cpus':2},{}) is None
    assert _cpu_percent(ident,{'cpu_usage':{'total_usage':3000},'system_cpu_usage':10000,'online_cpus':2},{})==80.0
    assert _cpu_percent(ident,{'cpu_usage':{'total_usage':0},'system_cpu_usage':10001,'online_cpus':2},{}) is None


def test_docker_force_stop_handles_paused_state_without_fake_stopped_result(app,users,monkeypatch):
    data=spec(users[0])|{'engine':'docker'}
    client=Mock();client.__enter__=Mock(return_value=client);client.__exit__=Mock(return_value=False)
    container=Mock(status='paused')
    container.reload.side_effect=lambda:setattr(container,'status','exited')
    monkeypatch.setattr(DockerEngine,'_client',lambda *a,**kw:client)
    monkeypatch.setattr(DockerEngine,'_container',lambda *a:container)
    assert DockerEngine().force_stop(data)['status']=='stopped'
    container.unpause.assert_called_once();container.kill.assert_called_once()


def test_restart_checks_available_ram_after_graceful_stop_not_before(app,users,monkeypatch):
    from services.provisioning import process_job,queue_action
    from tests.test_provisioning import fixture_vps
    instance=fixture_vps(users[0]);job=queue_action(users[0],instance,'restart')
    events=[]
    def capacity(*a,**kw):
        if kw.get('require_available_ram',True):
            assert 'stop' in events
            events.append('memory-recheck')
    engine=Mock()
    engine.stop.side_effect=lambda *a,**kw:events.append('stop') or {'status':'stopped'}
    engine.start.side_effect=lambda *a,**kw:events.append('start') or {'status':'running'}
    monkeypatch.setattr('services.provisioning.capacity_check',capacity)
    monkeypatch.setattr('services.provisioning.engine_for',lambda *a:engine)
    process_job(job.id)
    assert job.status=='completed' and events==['stop','memory-recheck','start']
    engine.restart.assert_not_called()


@pytest.mark.parametrize('observed',['paused','restarting','dead','removing'])
def test_docker_does_not_claim_stopped_after_an_unverified_action(app,users,monkeypatch,observed):
    monkeypatch.setattr('engines.docker_engine.time.sleep',lambda _:None)
    from engines import UncertainError
    client=Mock();client.__enter__=Mock(return_value=client);client.__exit__=Mock(return_value=False)
    container=Mock(status=observed)
    monkeypatch.setattr(DockerEngine,'_client',lambda *a,**kw:client)
    monkeypatch.setattr(DockerEngine,'_container',lambda *a:container)
    with pytest.raises(UncertainError,match='observed state'):
        DockerEngine().stop(spec(users[0])|{'engine':'docker'})


def test_restart_stays_stopped_if_post_shutdown_memory_check_fails(app,users,monkeypatch):
    from services.provisioning import process_job,queue_action
    from tests.test_provisioning import fixture_vps
    instance=fixture_vps(users[0]);job=queue_action(users[0],instance,'restart')
    def capacity(*a,**kw):
        if kw.get('require_available_ram',True):raise EngineError('RAM is no longer available after shutdown.')
    engine=Mock();engine.stop.return_value={'status':'stopped'}
    monkeypatch.setattr('services.provisioning.capacity_check',capacity)
    monkeypatch.setattr('services.provisioning.engine_for',lambda *a:engine)
    process_job(job.id)
    assert job.status=='failed' and 'RAM' in job.message
    engine.stop.assert_called_once();engine.start.assert_not_called()


def test_agent_restart_checks_ram_after_stop(app,users,monkeypatch):
    from models import AgentInstance,AgentOperation
    from services.node_worker import process_operation
    from services.security import encrypt
    data=spec(users[0]);instance=AgentInstance(id=data['id'],spec=data)
    operation=AgentOperation(id=str(uuid.uuid4()),digest='test-restart-only',payload=encrypt({'kind':'restart','spec':data}))
    db.session.add_all([instance,operation]);db.session.commit()
    events=[]
    def capacity(*a,**kw):
        if kw.get('require_available_ram',True):
            assert events==['stop'];events.append('memory-recheck')
    engine=Mock()
    engine.stop.side_effect=lambda *a,**kw:events.append('stop') or {'status':'stopped'}
    engine.start.side_effect=lambda *a,**kw:events.append('start') or {'status':'running'}
    monkeypatch.setattr('services.node_worker.engine_for',lambda *a:engine)
    monkeypatch.setattr('services.node_worker.enforce_capacity',capacity)
    process_operation(operation.id)
    assert operation.status=='completed' and events==['stop','memory-recheck','start']


@pytest.mark.parametrize('agent',[False,True])
def test_stopped_disk_growth_does_not_require_the_guest_ram_to_be_available(app,users,monkeypatch,agent):
    from models import AgentInstance
    from services.node_worker import enforce_capacity
    from services.validation import capacity_check
    from tests.test_provisioning import fixture_vps
    instance=fixture_vps(users[0]);data=instance.spec()
    host={'capacity_known':True,'ram_total_mb':4096,'ram_available_mb':0,'cpu_capacity':2,'disk_free_gb':100}
    if agent:
        db.session.add(AgentInstance(id=data['id'],spec=data));db.session.commit()
        monkeypatch.setattr('services.node_worker.host_metrics',lambda:host)
        check=lambda **kw:enforce_capacity(data,exclude=data['id'],**kw)
    else:
        monkeypatch.setattr('services.validation.host_metrics',lambda:host)
        monkeypatch.setattr('services.validation.engine_for',lambda *a:Mock(capabilities=lambda:{'available':True}))
        check=lambda **kw:capacity_check(data,resize_of=instance,**kw)
    check(require_available_ram=False)
    with pytest.raises(EngineError,match='available'):
        check()


def test_docker_force_stop_waits_for_actual_task_exit_after_daemon_ack(app,users,monkeypatch):
    client=Mock();client.__enter__=Mock(return_value=client);client.__exit__=Mock(return_value=False)
    container=Mock(status='running');observed=iter(['running','exited'])
    container.reload.side_effect=lambda:setattr(container,'status',next(observed))
    monkeypatch.setattr('engines.docker_engine.time.sleep',lambda _:None)
    monkeypatch.setattr(DockerEngine,'_client',lambda *a,**kw:client)
    monkeypatch.setattr(DockerEngine,'_container',lambda *a:container)
    assert DockerEngine().force_stop(spec(users[0])|{'engine':'docker'})['status']=='stopped'
    assert container.reload.call_count==2

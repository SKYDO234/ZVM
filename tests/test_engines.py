import json
import os
import uuid
from pathlib import Path
from unittest.mock import Mock
import psutil
import pytest
import yaml
from engines import EngineError
from engines.qemu_engine import QemuEngine
from engines.docker_engine import DockerEngine
from services.security import instance_dir, run, validate_url


pytestmark = pytest.mark.usefixtures('app')

def vm_spec():
    return {'id':str(uuid.uuid4()),'owner_id':1,'name':'safe-vm','engine':'qemu','os_id':'ubuntu-24.04','ram_mb':2048,
            'vcpus':2,'disk_gb':20,'username':'ubuntu','ssh_port':22500,
            'runtime':{'forwards':[{'host':22501,'guest':80}],'network_restricted':True}}


def test_qemu_dependency_detection(app,monkeypatch):
    monkeypatch.setattr('engines.qemu_engine.shutil.which',lambda b:None)
    caps=QemuEngine().capabilities()
    assert not caps['available'] and caps['accel']=='tcg'
    assert set(caps['missing'])=={'qemu-system-x86_64','qemu-img','cloud-localds'}


def test_kvm_requires_explicit_opt_in_and_probe(app,monkeypatch):
    monkeypatch.setattr('engines.qemu_engine.shutil.which',lambda b:'/usr/bin/'+b)
    monkeypatch.setattr('engines.qemu_engine.os.access',lambda *a:True)
    probe=Mock(return_value=(True,'actual probe boundary mocked'))
    monkeypatch.setattr(QemuEngine,'_probe',probe)
    app.config['USE_KVM']=False
    assert QemuEngine().capabilities()['accel']=='tcg'
    probe.assert_called_once_with('tcg')
    app.config['USE_KVM']=True
    assert QemuEngine().capabilities()['accel']=='kvm'
    assert probe.call_args.args==('kvm',)


def test_docker_absence_is_not_faked(monkeypatch):
    from docker.errors import DockerException
    monkeypatch.setattr('engines.docker_engine.docker.from_env',Mock(side_effect=DockerException('no daemon')))
    assert not DockerEngine().capabilities()['available']


def test_qemu_command_preserves_allocations_and_fixes_forwarding(monkeypatch):
    monkeypatch.setattr('engines.qemu_engine.instance_dir', lambda ident: Path('/tmp/skvm-test') / ident)
    s=vm_spec();cmd=QemuEngine()._command(s,'tcg')
    assert cmd[cmd.index('-m')+1]=='2048'
    assert cmd[cmd.index('-smp')+1]=='2' and '-S' in cmd
    assert 'type=pc,accel=tcg' in cmd and '-enable-kvm' not in cmd
    network=cmd[cmd.index('-netdev')+1]
    assert network.count('hostfwd=')==2 and '127.0.0.1:22500-:22' in network and '22501-:80' in network
    assert cmd.count('-netdev')==1 and 'restrict=on' in network
    assert 'readonly=on' in ' '.join(cmd)


def test_cloud_init_secure_and_per_vm(app,monkeypatch):
    s=vm_spec();directory=instance_dir(s['id']);directory.mkdir()
    captured={}
    def fake_run(args,**kwargs):
        captured['user']=yaml.safe_load((directory/'user-data').read_text())
        captured['meta']=yaml.safe_load((directory/'meta-data').read_text())
        (directory/'seed.iso').write_bytes(b'test-only-seed-boundary')
        return ''
    monkeypatch.setattr('engines.qemu_engine.run',fake_run)
    QemuEngine()._seed(s,{'password_hash':'$6$test-only-hash'})
    user=captured['user']
    assert user['disable_root'] is True and user['users'][0]['passwd']=='$6$test-only-hash'
    assert 'list' not in user['chpasswd']
    assert captured['meta']['instance-id']==s['id']
    assert not (directory/'user-data').exists() and not (directory/'meta-data').exists()
    assert (directory/'seed.iso').stat().st_mode & 0o777 == 0o600


def test_duplicate_process_is_not_started(monkeypatch):
    monkeypatch.setattr(QemuEngine,'_process',lambda *a:Mock())
    with pytest.raises(EngineError,match='already running'):
        QemuEngine().start(vm_spec())


def test_pid_reuse_never_targets_an_unrelated_process(monkeypatch):
    s=vm_spec();directory=instance_dir(s['id']);directory.mkdir()
    (directory/'process.json').write_text(json.dumps({'pid':os.getpid(),'created':0}))
    assert QemuEngine()._process(s) is None


def test_stop_does_not_silently_kill_guest(monkeypatch):
    process=Mock();process.wait.side_effect=psutil.TimeoutExpired(180)
    monkeypatch.setattr(QemuEngine,'_process',lambda *a:process)
    qmp=Mock(return_value={});monkeypatch.setattr(QemuEngine,'_qmp',qmp)
    with pytest.raises(EngineError,match='ACPI shutdown'):
        QemuEngine().stop(vm_spec())
    process.kill.assert_not_called();process.terminate.assert_not_called()
    process.wait.assert_called_once_with(timeout=180)
    assert qmp.call_args.args[-1]=='system_powerdown'


def test_disk_resize_grows_only_and_blocks_running(monkeypatch):
    s=vm_spec();instance_dir(s['id']).mkdir()
    monkeypatch.setattr(QemuEngine,'_process',lambda *a:None)
    called=Mock(return_value='');monkeypatch.setattr('engines.qemu_engine.run',called)
    with pytest.raises(EngineError,match='Only disk growth'):
        QemuEngine().resize(s,10)
    result=QemuEngine().resize(s,30)
    assert result['disk_gb']==30 and called.call_args.args[0][-1]=='30G'
    monkeypatch.setattr(QemuEngine,'_process',lambda *a:Mock())
    with pytest.raises(EngineError,match='Stop the VM'):
        QemuEngine().resize(s,40)


def test_subprocess_arguments_never_use_shell(monkeypatch):
    runner=Mock(return_value=Mock(returncode=0,stdout='ok',stderr=''))
    monkeypatch.setattr('services.security.subprocess.run',runner)
    assert run(['qemu-img','info','some;literal.qcow2'])=='ok'
    assert runner.call_args.args[0][-1]=='some;literal.qcow2'
    assert 'shell' not in runner.call_args.kwargs
    assert runner.call_args.kwargs['timeout']>0


def test_url_allowlist_blocks_ssrf_and_credentials():
    for url in ['http://cloud.debian.org/a','https://127.0.0.1/a','https://user:pass@cloud.debian.org/a','https://cloud.debian.org:444/a']:
        with pytest.raises(EngineError):
            validate_url(url,['cloud.debian.org'])


def test_path_traversal_is_not_possible():
    with pytest.raises(EngineError):instance_dir('../vms/other')


def test_docker_console_is_allowlisted():
    with pytest.raises(EngineError,match='allowed container diagnostics'):
        DockerEngine().console_input(vm_spec(),'rm -rf /')


@pytest.mark.parametrize('resume_reply_lost',[False,True])
def test_start_waits_for_monitor_and_never_kills_a_possibly_resumed_guest(monkeypatch,resume_reply_lost):
    from engines import UncertainError
    s=vm_spec();directory=instance_dir(s['id']);directory.mkdir()
    for filename in ('disk.qcow2','seed.iso','config.json'):
        (directory/filename).write_bytes(b'explicit-unit-boundary-only')
    engine=QemuEngine();process=Mock(pid=12345);process.poll.return_value=None
    monkeypatch.setattr(engine,'_process',lambda *a:None)
    monkeypatch.setattr(engine,'capabilities',lambda:{'available':True,'accel':'tcg'})
    monkeypatch.setattr(engine,'_command',lambda *a:['unit-boundary-not-executed'])
    monkeypatch.setattr('engines.qemu_engine.psutil.Process',lambda pid:Mock(create_time=lambda:123.0))
    monkeypatch.setattr('engines.qemu_engine.time.sleep',lambda seconds:None)
    def spawn_boundary(*args,**kwargs):
        (directory/'qmp.sock').touch()
        return process
    monkeypatch.setattr('engines.qemu_engine.subprocess.Popen',spawn_boundary)
    if resume_reply_lost:
        qmp=Mock(side_effect=[{'running':False},EngineError('reply lost after resume request')])
    else:
        qmp=Mock(side_effect=[EngineError('socket not listening yet'),{'running':False},{},{'running':True}])
    monkeypatch.setattr(engine,'_qmp',qmp)
    if resume_reply_lost:
        with pytest.raises(UncertainError,match='NOT force-stopped'):
            engine.start(s)
    else:
        assert engine.start(s)['status']=='running'
        assert qmp.call_count==4
    qmp.assert_any_call(s,'cont')
    process.terminate.assert_not_called();process.kill.assert_not_called()


@pytest.mark.parametrize('failure',[None,'body','ping'])
def test_real_docker_sdk_client_is_explicitly_closed_without_assumed_context_protocol(app,monkeypatch,failure):
    import docker
    from docker.errors import DockerException
    # A genuine SDK client, with no daemon connection. Only its network boundary is replaced.
    client=docker.DockerClient(base_url='unix:///nonexistent-skvm-test.sock',version='1.44')
    assert not hasattr(client,'__enter__')
    client.ping=Mock(side_effect=DockerException('fixture ping failure') if failure=='ping' else None,return_value=True)
    client.close=Mock(wraps=client.close)
    monkeypatch.setattr('engines.docker_engine.docker.from_env',lambda **kwargs:client)
    def consume():
        with DockerEngine()._client() as actual:
            assert actual is client
            if failure=='body':raise DockerException('fixture mutation interruption')
    if failure=='ping':
        with pytest.raises(EngineError,match='daemon unavailable'):consume()
    elif failure=='body':
        # A post-acquisition disconnect must NOT be misreported as a harmless failed ping.
        with pytest.raises(DockerException,match='mutation interruption'):consume()
    else:consume()
    client.close.assert_called_once()


@pytest.mark.parametrize('state',['running','created'])
def test_docker_metrics_use_supported_sdk_method_signatures_and_own_measured_size(app,monkeypatch,state):
    import docker
    from unittest.mock import create_autospec
    data=vm_spec()|{'engine':'docker','runtime':{'container_id':'a'*64,'storage_enforced':False}}
    client=docker.DockerClient(base_url='unix:///nonexistent-skvm-test.sock',version='1.44')
    client.api.close()
    client.api=create_autospec(docker.APIClient,instance=True)
    client.api.inspect_container.return_value={'Id':'a'*64,'State':{'Status':state},
        'Config':{'Labels':{'skvm.instance':data['id'],'skvm.owner':str(data['owner_id'])}}}
    client.api.containers.return_value=[{'Id':'unrelated','SizeRw':999999},{'Id':'a'*64,'SizeRw':12345}]
    client.api.stats.return_value={'memory_stats':{'usage':2**20,'stats':{}},'cpu_stats':{},'precpu_stats':{}}
    monkeypatch.setattr('engines.docker_engine.docker.from_env',lambda **kwargs:client)
    result=DockerEngine().metrics(data)
    assert result['usage']['disk_actual_bytes']==12345 and result['storage_enforced'] is False
    assert result['status']==('running' if state=='running' else 'stopped')
    assert result['usage']['process_rss_mb']==(1.0 if state=='running' else 0)
    client.api.inspect_container.assert_called_once_with('a'*64)
    client.api.containers.assert_called_once_with(all=True,size=True,filters={'id':'a'*64})
    client.api.close.assert_called_once()

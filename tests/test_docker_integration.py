"""Opt-in real Docker lifecycle/cgroup test on a dedicated, accessible daemon.

Never starts a privileged container or a daemon, and never touches production DB.
"""
import os
import time
import uuid
import pytest
from engines.docker_engine import DockerEngine
from extensions import db
from models import VPS
from services.recovery import inspect_outcome
from tests.native_helpers import NativePanel

pytestmark=[pytest.mark.integration,
            pytest.mark.skipif(os.getenv('SKVM_RUN_DOCKER_INTEGRATION')!='1',reason='Opt-in real Docker image pull/container test; no daemon is assumed.')]


def test_real_docker_lifecycle_limits_and_writable_layer(app):
    app.config['TEST_MODE']=False
    engine=DockerEngine();capability=engine.capabilities()
    assert capability['available'],capability.get('reason')
    panel=NativePanel(app)
    spec={'id':str(uuid.uuid4()),'owner_id':1,'name':'skvm-docker-check','engine':'docker','os_id':'ubuntu-24.04',
          'ram_mb':128,'vcpus':1,'disk_gb':1,'username':None,'ssh_port':None,'runtime':{},
          'allow_unenforced_storage':True,'forwards':[]}
    try:
        spec=panel.create({'name':spec['name'],'engine':'docker','os_id':'ubuntu-24.04','ram_mb':128,'vcpus':1,'disk_gb':1,
                           'allow_unenforced_storage':'1'})
        spec['allow_unenforced_storage']=True
        assert panel.metrics()['status']=='stopped' and spec['ssh_port'] is None
        assert inspect_outcome('create',spec,{'spec':spec},engine)['status']=='stopped'
        panel.action('start')
        assert panel.metrics()['status']=='running'
        identity=engine.console_input(spec,'identity')
        assert identity['exit_code']==0 and 'uid=1000' in identity['output']
        with engine._client() as client:
            container=engine._container(client,spec)
            assert container.attrs['HostConfig']['Privileged'] is False
            assert not container.attrs['HostConfig'].get('Binds')
            assert not container.attrs.get('Mounts')
            assert not container.attrs['NetworkSettings'].get('Ports')
            limits=container.exec_run(['sh','-c',
                'if [ -r /sys/fs/cgroup/memory.max ]; then '
                'cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/cpu.max /sys/fs/cgroup/pids.max; '
                'else cat /sys/fs/cgroup/memory/memory.limit_in_bytes; '
                'printf "%s %s\\n" "$(cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us)" "$(cat /sys/fs/cgroup/cpu/cpu.cfs_period_us)"; '
                'cat /sys/fs/cgroup/pids/pids.max; fi'],user='1000:1000',privileged=False)
            assert limits.exit_code==0,limits.output.decode(errors='replace')
            memory,cpu,pids=limits.output.decode().splitlines()
            assert int(memory)==128*2**20 and int(pids)==128
            quota,period=map(int,cpu.split());assert quota/period==1
            network=client.networks.get(spec['runtime']['network'])
            assert network.attrs['Internal'] is True
            marker='persist-'+uuid.uuid4().hex
            write=container.exec_run(['sh','-c',f"printf '%s' '{marker}' > /tmp/skvm-persistence; sync"],user='1000:1000',privileged=False)
            assert write.exit_code==0
        first=engine.metrics(spec);time.sleep(.3);second=engine.metrics(spec)
        assert first['status']==second['status']=='running'
        assert second['usage']['process_rss_mb']>=0
        assert second['usage']['process_cpu_percent'] is not None
        assert second['usage']['disk_actual_bytes'] is None or second['usage']['disk_actual_bytes']>=0
        panel.action('stop')
        assert panel.metrics()['status']=='stopped'
        panel.action('start')
        assert panel.metrics()['status']=='running'
        with engine._client() as client:
            persisted=engine._container(client,spec).exec_run(['cat','/tmp/skvm-persistence'],user='1000:1000',privileged=False)
            assert persisted.exit_code==0 and persisted.output.decode()==marker
        panel.action('restart')
        assert panel.metrics()['status']=='running'
        panel.action('force_stop')
        assert panel.metrics()['status']=='stopped'
        panel.action('delete')
        assert engine.metrics(spec)['status']=='missing'
        assert db.session.scalar(db.select(db.func.count()).select_from(VPS))==0
    finally:
        panel.close()
        if panel.ident:
            spec['id']=panel.ident
            existing=db.session.get(VPS,panel.ident)
            if existing:spec=existing.spec()
        # Match this generated UUID/owner only. Never prune images or unrelated networks.
        with engine._client() as client:
            remaining=engine._container(client,spec)
        if remaining is not None:engine.force_stop(spec)
        engine.delete(spec)

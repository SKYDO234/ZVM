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
    spec={'id':str(uuid.uuid4()),'owner_id':panel.owner.id,'name':'skvm-docker-check','engine':'docker','os_id':'ubuntu-24.04',
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
        panel.interrupted_power_recovery()
        with engine._client() as client:
            container=engine._container(client,spec)
            identity=container.exec_run(['id'],user='1000:1000',privileged=False)
            assert identity.exit_code==0 and b'uid=1000' in identity.output
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
        panel.action('start')
        assert panel.owner.role=='user' and panel.metrics()['status']=='running'
        panel.action('delete')  # Ordinary owner: graceful stop then actual resource/network deletion.
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


def test_real_external_node_tls_panel_queue_and_docker_guest(app,tmp_path,monkeypatch):
    """Separate DBs/worker threads, real HTTPS/bearer API, and real Docker resources.

    Only TCP dialing is redirected to an ephemeral loopback port. CA/hostname
    validation, authenticated HTTP, operations, engines and resources are genuine.
    """
    import secrets
    import socket
    import threading
    import urllib3.connection
    from werkzeug.serving import make_server
    from engines.node_engine import NodeEngine
    from models import AgentInstance,AgentOperation,Node
    from services.background import stop_background
    from services.node_worker import start_agent_worker
    from skvm import create_app
    from tests.test_node_tls import certificates
    app.config.update(TEST_MODE=False,NODE_HOSTS=['node.test'])
    token=secrets.token_urlsafe(32)
    agent=create_app({'TESTING':True,'NODE_AGENT':True,'NODE_TOKEN':token,'TEST_MODE':False,'START_WORKER':False,
                      'DATA_DIR':tmp_path/'node-data','SQLALCHEMY_DATABASE_URI':f'sqlite:///{tmp_path/"node.db"}'})
    ca,cert,key=certificates(tmp_path)
    app.config['NODE_CA_BUNDLE']=str(ca)
    server=make_server('127.0.0.1',0,agent,threaded=True,ssl_context=(str(cert),str(key)))
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    start_agent_worker(agent)
    original=urllib3.connection.HTTPSConnection._new_conn
    def route_test_tcp(connection):
        if connection.host=='node.test':
            return socket.create_connection(('127.0.0.1',server.server_port),timeout=connection.timeout)
        return original(connection)
    monkeypatch.setattr(urllib3.connection.HTTPSConnection,'_new_conn',route_test_tcp)
    panel=NativePanel(app);data=None
    try:
        registered=panel.post('/admin/nodes',{'name':'Isolated native Docker node','url':'https://node.test','token':token})
        assert registered.status_code==302
        node=db.session.scalar(db.select(Node));assert node is not None,'Real TLS/authenticated registration failed.'
        node_engine=NodeEngine(node)
        initial=node_engine.capabilities()
        assert initial['docker']['available'] and initial['instances']==[] and initial['host']['capacity_known']
        data=panel.create({'name':'skvm-node-check','engine':'docker','os_id':'ubuntu-24.04','ram_mb':128,'vcpus':1,
                           'disk_gb':1,'allow_unenforced_storage':'1','node_id':str(node.id)})
        instance=db.session.get(VPS,panel.ident)
        assert instance.node_id==node.id and panel.metrics()['status']=='stopped'
        inventory=node_engine.capabilities()['instances']
        assert len(inventory)==1 and inventory[0]['id']==panel.ident
        with agent.app_context():
            assert db.session.get(AgentInstance,panel.ident) is not None
            assert db.session.scalar(db.select(db.func.count()).select_from(AgentOperation).where(AgentOperation.status=='completed'))==1
        panel.action('start');assert panel.metrics()['status']=='running'
        interrupted_id=panel.interrupted_power_recovery(agent=agent)
        with DockerEngine()._client() as native_client:
            result=DockerEngine()._container(native_client,data).exec_run(['id'],user='1000:1000',privileged=False)
            assert result.exit_code==0 and b'uid=1000' in result.output
        panel.action('stop');assert panel.metrics()['status']=='stopped'
        panel.action('start');panel.action('restart')
        assert panel.owner.role=='user' and panel.metrics()['status']=='running'
        panel.action('delete')  # One remote operation, with the node worker proving stop first.
        assert db.session.get(VPS,panel.ident) is None and node_engine.capabilities()['instances']==[]
        with agent.app_context():
            assert db.session.get(AgentInstance,panel.ident) is None
            assert db.session.scalar(db.select(db.func.count()).select_from(AgentOperation).where(AgentOperation.status!='completed',AgentOperation.id!=interrupted_id))==0
    finally:
        panel.close()
        assert stop_background(agent),'Do not tear down an agent while its real resource mutation is active.'
        server.shutdown();server.server_close();thread.join(timeout=5)
        if panel.ident:
            # Dispose only this test UUID/owner; never prune shared images/networks.
            data=data or {'id':panel.ident,'owner_id':panel.owner.id,'runtime':{}}
            docker=DockerEngine()
            with docker._client() as client:remaining=docker._container(client,data)
            if remaining is not None:docker.force_stop(data)
            docker.delete(data)
        with agent.app_context():db.session.remove();db.engine.dispose()

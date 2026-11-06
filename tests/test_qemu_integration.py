"""Actual disk/process integration on equipped hosts. NEVER creates VPS database records.
A blank disk is intentionally not described as a successfully booted operating system.
"""
import shutil
import tempfile
import uuid
from pathlib import Path
import pytest
from engines import EngineError
from engines.qemu_engine import QemuEngine
from services.security import atomic_json, instance_dir, run
from extensions import db
from models import VPS

MISSING = any(not shutil.which(b) for b in ('qemu-system-x86_64','qemu-img','cloud-localds'))


@pytest.mark.integration
@pytest.mark.skipif(MISSING, reason='Real QEMU/cloud-localds binaries absent; no compatibility success claimed.')
def test_real_qcow2_tcg_qmp_lifecycle_without_os_boot(app):
    with tempfile.TemporaryDirectory(prefix='skvm-qemu-') as temp:
        app.config['DATA_DIR'] = Path(temp)
        app.config['USE_KVM'] = False
        (Path(temp)/'vms').mkdir()
        spec={'id':str(uuid.uuid4()),'owner_id':1,'name':'diskless-test','engine':'qemu','os_id':'ubuntu-24.04',
              'ram_mb':256,'vcpus':1,'disk_gb':1,'username':'tester','ssh_port':22999,
              'runtime':{'accel':'tcg','network_restricted':True,'forwards':[]}}
        directory=instance_dir(spec['id']);directory.mkdir()
        run(['qemu-img','create','-f','qcow2',directory/'disk.qcow2','1G'])
        engine=QemuEngine()
        engine._seed(spec,{})
        atomic_json(directory/'config.json',spec)
        try:
            result=engine.start(spec)
            assert result['status']=='running'  # QMP process state only, not a guest OS boot.
            assert engine.metrics(spec)['usage']['pid']
            with pytest.raises(EngineError,match='already running'):engine.start(spec)
        finally:
            engine.force_stop(spec)
        assert engine.metrics(spec)['status']=='stopped'
        engine.resize(spec,2)
        import json
        info=json.loads(run(['qemu-img','info','-f','qcow2','--output=json',directory/'disk.qcow2']))
        assert info['virtual-size']==2*2**30
        engine.delete(spec)
        assert not directory.exists()
        assert db.session.scalar(db.select(db.func.count()).select_from(VPS))==0

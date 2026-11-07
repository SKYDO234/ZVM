"""Opt-in real Ubuntu/cloud-init/SSH acceptance. Downloads a pinned vendor image.

Not a mock and not run by the default test suite. No production database is used.
"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import uuid
import pytest
from engines.qemu_engine import QemuEngine
from extensions import db
from models import OSImage, VPS
from services.provisioning import allocate_port
from services.recovery import inspect_outcome
from services.security import instance_dir, ssh_key
from tests.native_helpers import NativePanel

REQUIRED=('qemu-system-x86_64','qemu-img','cloud-localds','ssh','ssh-keygen')
pytestmark=[pytest.mark.integration,pytest.mark.os_boot,
            pytest.mark.skipif(os.getenv('SKVM_RUN_OS_BOOT')!='1',reason='Opt-in pinned cloud OS/SSH boot; set SKVM_RUN_OS_BOOT=1 explicitly.'),
            pytest.mark.skipif(any(not shutil.which(binary) for binary in REQUIRED),reason='Real QEMU, cloud-localds and OpenSSH tools are required.')]


def _ssh(key,port,command,timeout=30):
    return subprocess.run(['ssh','-T','-i',str(key),'-p',str(port),'-o','BatchMode=yes','-o','IdentitiesOnly=yes',
                           '-o','StrictHostKeyChecking=accept-new','-o',f'UserKnownHostsFile={key.parent/"known_hosts"}',
                           '-o','LogLevel=ERROR','-o','ConnectTimeout=5','-o','ConnectionAttempts=1',
                           '-o','ServerAliveInterval=5','-o','ServerAliveCountMax=2','skvmcheck@127.0.0.1',command],
                          capture_output=True,text=True,timeout=timeout,check=False)


def _host_fingerprints(key,port):
    result=_ssh(key,port,'for key in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf "$key" -E sha256; done')
    assert result.returncode==0,result.stderr
    fingerprints=set(re.findall(r'SHA256:[A-Za-z0-9+/]{43}',result.stdout))
    assert fingerprints
    return fingerprints


def _wait_for_ssh(key,port,deadline=420):
    end=time.monotonic()+deadline;reason='SSH has not responded.'
    while time.monotonic()<end:
        try:
            result=_ssh(key,port,'id -un',timeout=15)
            if result.returncode==0 and result.stdout.strip()=='skvmcheck':return
            reason=result.stderr[-600:]
        except subprocess.TimeoutExpired:
            reason='SSH handshake timed out.'
        time.sleep(3)
    pytest.fail('The real guest did not accept its configured SSH key: '+reason)


def test_real_ubuntu_cloud_init_ssh_and_persistence(app):
    pin=os.getenv('SKVM_BOOT_IMAGE_SHA256','').lower()
    assert re.fullmatch(r'[0-9a-f]{64}',pin),'Supply SKVM_BOOT_IMAGE_SHA256 from the authenticated vendor checksum manifest; no unpinned image is accepted.'
    root=Path(tempfile.mkdtemp(prefix='skvm-os-'))
    app.config.update(DATA_DIR=root,USE_KVM=False,TEST_MODE=False)
    for folder in ('vms','images','locks','logs'):(root/folder).mkdir()
    image=db.session.get(OSImage,'ubuntu-24.04');image.sha256=pin;db.session.commit()
    engine=QemuEngine();panel=NativePanel(app)
    data={'id':str(uuid.uuid4()),'owner_id':1,'name':'skvm-real-boot','engine':'qemu','os_id':image.id,
          'ram_mb':768,'vcpus':1,'disk_gb':10,'username':'skvmcheck','ssh_port':allocate_port(),
          'runtime':{},'forwards':[]}
    report={'test':'real Ubuntu 24.04 boot','started_at':datetime.now(timezone.utc).isoformat(),'phase':'preflight','passed':False,'image_sha256':pin,'accel':'tcg','allocation':{'ram_mb':768,'vcpus':1,'disk_gb':10}}
    key=root/'disposable-client-key'
    try:
        subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True,capture_output=True)
        public=ssh_key(key.with_suffix('.pub').read_text())
        data=panel.create({'name':data['name'],'engine':'qemu','os_id':image.id,'ram_mb':768,'vcpus':1,'disk_gb':10,
                           'username':'skvmcheck','ssh_port':data['ssh_port'],'auth_method':'key','public_key':public,'network_mode':'internet','accept_network_risk':'1'})
        assert panel.metrics()['status']=='stopped' and data['runtime']['accel']=='tcg'
        # This also validates native qemu-img check and a real cloud-localds CIDATA seed.
        assert inspect_outcome('create',data,{'spec':data},engine)['status']=='stopped'
        report['phase']='disk-and-seed-created'
        panel.action('start');data=panel.spec()
        assert panel.metrics()['status']=='running'
        report['phase']='qmp-running'
        _wait_for_ssh(key,data['ssh_port']);report['phase']='ssh-authenticated'
        cloud=_ssh(key,data['ssh_port'],'sudo -n cloud-init status --wait --format=json',timeout=300)
        assert cloud.returncode==0,cloud.stdout[-3000:]+cloud.stderr[-1000:]
        status=json.loads(cloud.stdout)
        assert status.get('status')=='done' and not status.get('errors'),status
        report['phase']='cloud-init-complete'
        report['phase']='sshx-guest-install-and-link-verification'
        panel.sshx(_host_fingerprints(key,data['ssh_port']), guest=lambda command: _ssh(key,data['ssh_port'],command))
        assert panel.metrics()['status']=='running'
        report['sshx']={'guest_installer':True,'actual_link_displayed':True,'verified_host_key':True,'client_stopped':True,'unrelated_process_preserved':True,'guest_identity':'skvmcheck'}
        report['cloud_init']={'status':status['status'],'errors':status.get('errors',[])}
        guest=_ssh(key,data['ssh_port'],"id -un; getconf _NPROCESSORS_ONLN; grep '^MemTotal:' /proc/meminfo; cat /etc/os-release")
        assert guest.returncode==0 and guest.stdout.splitlines()[:2]==['skvmcheck','1']
        assert 640*1024 <= int(guest.stdout.splitlines()[2].split()[1]) <= 768*1024
        assert 'ID=ubuntu' in guest.stdout and 'VERSION_ID="24.04"' in guest.stdout
        marker='persist-'+uuid.uuid4().hex
        written=_ssh(key,data['ssh_port'],f"printf '%s' '{marker}' > ~/skvm-persistence-check; sync")
        assert written.returncode==0,written.stderr
        panel.action('suspend')  # Genuine ACPI stop, plus panel suspension policy.
        assert panel.metrics()['status']=='stopped'
        denied=panel.post(f'/vps/{panel.ident}/action/start')
        assert denied.status_code==302 and '/vps/jobs/' not in denied.location
        panel.action('unsuspend')
        assert panel.metrics()['status']=='stopped'
        report['phase']='gracefully-stopped'
        panel.action('resize',{'disk_gb':11});data=panel.spec()
        assert data['disk_gb']==11
        panel.action('start');data=panel.spec()
        assert panel.metrics()['status']=='running'
        _wait_for_ssh(key,data['ssh_port'])
        persisted=_ssh(key,data['ssh_port'],'cat ~/skvm-persistence-check')
        assert persisted.returncode==0 and persisted.stdout==marker
        block=_ssh(key,data['ssh_port'],'sudo -n blockdev --getsize64 /dev/vda')
        assert block.returncode==0 and int(block.stdout.strip())==11*2**30
        report['resized_guest_block_bytes']=int(block.stdout.strip())
        report['phase']='restarted-and-persistence-verified'
        panel.action('stop')
        # Reinstall must replace only this guest, clear old data, and accept its key.
        panel.action('reinstall',{'os_id':image.id,'username':'skvmcheck','auth_method':'key','public_key':public})
        data=panel.spec();(key.parent/'known_hosts').unlink(missing_ok=True)
        panel.action('start');_wait_for_ssh(key,data['ssh_port'])
        report['phase']='sshx-reinstall-management-key-verification'
        panel.sshx(_host_fingerprints(key,data['ssh_port']), guest=lambda command: _ssh(key,data['ssh_port'],command), orphan=True)
        report['sshx']['reinstall_new_management_key_verified']=True
        report['sshx']['orphan_client_stopped']=True
        absent=_ssh(key,data['ssh_port'],'test ! -e ~/skvm-persistence-check')
        assert absent.returncode==0
        report['phase']='reinstall-verified'
        panel.action('force_stop')
        assert panel.metrics()['status']=='stopped'
        panel.action('delete')
        assert not instance_dir(data['id']).exists()
        assert db.session.scalar(db.select(db.func.count()).select_from(VPS))==0
        report.update(phase='deleted',passed=True)
    finally:
        panel.close()
        destination=os.getenv('SKVM_BOOT_REPORT_DIR')
        if destination:
            target=Path(destination);target.mkdir(parents=True,exist_ok=True)
            for filename in ('qemu.log','serial.log'):
                source=instance_dir(data['id'])/filename
                if source.is_file():
                    with source.open('rb') as handle:
                        handle.seek(max(0,source.stat().st_size-65536))
                        tail=handle.read(65536)
                        (target/filename).write_bytes(tail)
                        if os.getenv('GITHUB_ACTIONS')=='true' and not report['passed']:
                            from importlib.util import spec_from_file_location,module_from_spec
                            module_spec=spec_from_file_location('skvm_ci_reporter',Path(__file__).parents[1]/'scripts/report-ci.py')
                            reporter=module_from_spec(module_spec);module_spec.loader.exec_module(reporter)
                            reporter.annotation('notice','Real QEMU failure: '+filename,tail[-3000:].decode(errors='replace'))
            (target/'result.json').write_text(json.dumps(report,indent=2))
        # Explicit cleanup of ONLY this disposable test UUID; never a broad kill.
        if panel.ident:
            data['id']=panel.ident
            existing=db.session.get(VPS,panel.ident)
            if existing:data=existing.spec()
        if engine._process(data):engine.force_stop(data)
        if engine._process(data) is None:shutil.rmtree(root)

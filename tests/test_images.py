"""Image/HTTP trust-boundary regressions. Native qemu-img is tested separately."""
import hashlib
import importlib.util
import io
from pathlib import Path
from unittest.mock import Mock
import pytest
import requests
import urllib3
from engines import EngineError, UncertainError
from extensions import db
from models import OSImage
from services.image_manager import ImageManager
from tests.test_node_protocol import response as node_response, transport


def reply(body=b'QFI\xfb',status=200,headers=None):
    result=requests.Response();result.status_code=status
    result.headers.update(headers or {})
    result.raw=urllib3.response.HTTPResponse(body=io.BytesIO(body),preload_content=False)
    result.close=Mock(wraps=result.close)
    return result


def session(monkeypatch,*responses):
    result=Mock();result.request.side_effect=responses
    monkeypatch.setattr('services.image_manager.requests.Session',lambda:result)
    monkeypatch.setattr('services.security.socket.getaddrinfo',lambda *a,**k:[(2,1,6,'',('1.1.1.1',443))])
    return result


def cached(app,image,body):
    key=hashlib.sha256((image.qemu_url+(image.sha256 or '')).encode()).hexdigest()
    path=Path(app.config['DATA_DIR'])/'images'/f'{key}.qcow2'
    path.write_bytes(body)
    return path


@pytest.mark.parametrize('consumer_fails',[False,True])
def test_image_request_always_closes_response_and_session(app,monkeypatch,consumer_fails):
    response=reply();client=session(monkeypatch,response)
    manager=ImageManager()
    def consume():
        with manager._request('https://cloud-images.ubuntu.com/test',stream=True):
            if consumer_fails:raise RuntimeError('Explicit test consumer failure')
    if consumer_fails:
        with pytest.raises(RuntimeError):consume()
    else:consume()
    response.close.assert_called_once();client.close.assert_called_once()
    assert client.trust_env is False
    assert client.request.call_args.kwargs['allow_redirects'] is False


def test_image_redirect_is_closed_and_unallowlisted_destination_never_requested(app,monkeypatch):
    response=reply(status=302,headers={'Location':'https://internal.example.test/admin'})
    client=session(monkeypatch,response)
    with pytest.raises(EngineError,match='allowlist'):
        with ImageManager()._request('https://cloud-images.ubuntu.com/test'):pytest.fail('Unsafe redirect accepted')
    assert client.request.call_count==1
    response.close.assert_called_once();client.close.assert_called_once()


def test_http_rejection_closes_both_resources(app,monkeypatch):
    response=reply(status=404);client=session(monkeypatch,response)
    with pytest.raises(EngineError,match='HTTP 404'):
        with ImageManager()._request('https://cloud-images.ubuntu.com/test'):pytest.fail('HTTP error accepted')
    response.close.assert_called_once();client.close.assert_called_once()


def test_cached_pin_is_rehashed_and_native_qcow2_check_is_required(app,monkeypatch):
    image=db.session.get(OSImage,'ubuntu-24.04');body=b'explicit cached-image test fixture'
    image.sha256=hashlib.sha256(body).hexdigest();target=cached(app,image,body)
    manager=ImageManager();inspect=Mock();command=Mock(return_value='')
    monkeypatch.setattr(manager,'inspect',inspect);monkeypatch.setattr('services.image_manager.run',command)
    assert manager.obtain(image)==target
    inspect.assert_called_once_with(target)
    assert command.call_args.args[0]==['qemu-img','check','-f','qcow2',target]
    target.write_bytes(b'changed cache after prior successful inspection')
    command.reset_mock()
    with pytest.raises(EngineError,match='Cached image SHA256 mismatch'):manager.obtain(image)
    command.assert_not_called()


def test_cache_symlink_is_rejected_before_native_tool_invocation(app,monkeypatch,tmp_path):
    image=db.session.get(OSImage,'ubuntu-24.04');target=cached(app,image,b'')
    target.unlink();outside=tmp_path/'outside';outside.write_bytes(b'do not read or mutate')
    target.symlink_to(outside)
    inspect=Mock();monkeypatch.setattr(ImageManager,'inspect',inspect)
    with pytest.raises(EngineError,match='cache symlink'):ImageManager().obtain(image)
    inspect.assert_not_called();assert outside.read_bytes()==b'do not read or mutate'


@pytest.mark.parametrize('interrupted',[False,True])
def test_failed_download_removes_partial_disk_and_closes_http(app,monkeypatch,interrupted):
    image=db.session.get(OSImage,'ubuntu-24.04');image.sha256='a'*64
    response=reply(b'QFI\xfbintentionally not a valid pinned image')
    if interrupted:
        response.raw.read1=Mock(side_effect=urllib3.exceptions.ReadTimeoutError(None,'/test','fixture stream timeout'))
    client=session(monkeypatch,response)
    manager=ImageManager();monkeypatch.setattr(manager,'verify',lambda image:True)
    with pytest.raises(EngineError,match='unreachable' if interrupted else 'SHA256 mismatch'):manager.obtain(image)
    assert not list((Path(app.config['DATA_DIR'])/'images').glob('*.part'))
    assert not list((Path(app.config['DATA_DIR'])/'images').glob('*.qcow2'))
    response.close.assert_called_once();client.close.assert_called_once()


def test_node_raw_socket_timeout_remains_an_uncertain_operation(app,monkeypatch):
    response=node_response({})
    response.raw.read1=Mock(side_effect=urllib3.exceptions.ReadTimeoutError(None,'/test','fixture stream timeout'))
    engine,_=transport(app,monkeypatch,response)
    with pytest.raises(UncertainError,match='actual state is unknown'):engine._request('POST','/v1/operations',{})


def test_node_transfer_deadline_is_checked_between_small_reads(app,monkeypatch):
    engine,_=transport(app,monkeypatch,node_response({'still':'not trusted until completely read'}))
    timer=Mock(side_effect=[0,31]);monkeypatch.setattr('engines.node_engine.time.monotonic',timer)
    with pytest.raises(UncertainError,match='size/time limit'):engine.capabilities()


def test_signed_manifest_parser_requires_a_unique_exact_image_entry():
    spec=importlib.util.spec_from_file_location('skvm_checksum_script',Path(__file__).parents[1]/'scripts/verified-ubuntu-checksum.py')
    script=importlib.util.module_from_spec(spec);spec.loader.exec_module(script)
    name='noble-server-cloudimg-amd64.img';digest='b'*64
    assert script.checksum_entry(f'{digest} *{name}\n',name)==digest
    for manifest in ('',f'{digest} ../{name}',f'{digest} {name}\n{digest} {name}\n',f'{digest} {name}.other'):
        with pytest.raises(ValueError,match='exactly one'):script.checksum_entry(manifest,name)


def test_obsolete_factory_fedora_url_migrates_but_custom_operator_configuration_is_preserved(app):
    from services.image_manager import CATALOG,seed_images
    image=db.session.get(OSImage,'fedora-40')
    current=next(row[3] for row in CATALOG if row[0]==image.id)
    image.qemu_url=current.replace('Fedora-Cloud-Base-Generic.x86_64-40-1.14.qcow2','Fedora-Cloud-Base-40-1.14.x86_64.qcow2')
    image.sha256='b'*64;image.verification='unavailable';db.session.commit()
    seed_images();assert image.qemu_url==current and image.sha256=='b'*64 and image.verification=='unchecked'
    image.qemu_url='https://operator.example.test/custom-pinned-fedora.qcow2';db.session.commit()
    seed_images();assert image.qemu_url=='https://operator.example.test/custom-pinned-fedora.qcow2' and image.sha256=='b'*64

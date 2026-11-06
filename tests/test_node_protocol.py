"""Transport fixtures never contact a live node or pretend one was deployed."""
import copy
import json
import io
import urllib3
import uuid
from unittest.mock import Mock
import pytest
import requests
from engines import EngineError, UncertainError
from engines.node_engine import NodeEngine
from extensions import db
from models import AgentOperation, Node
from services import node_protocol
from services.security import encrypt
from tests.test_node import agent_app
from tests.test_provisioning import spec

TOKEN='isolated-test-token-012345678901234567890'
pytestmark=pytest.mark.usefixtures('app')


def caps():
    return {'protocol_version':1,'host':{'ram_total_mb':4096,'ram_available_mb':2048,'cpu_capacity':2,'disk_free_gb':20,'capacity_known':True},
            'qemu':{'available':True,'reason':'explicit mocked probe'},'docker':{'available':False,'reason':'no test daemon'},
            'instances':[],'reserved_ports':[]}


def response(body,status=200,headers=None):
    result=requests.Response();result.status_code=status;result.url='https://compute.example.test/v1/test'
    result._content=body if isinstance(body,bytes) else json.dumps(body).encode()
    result._content_consumed=False;result.headers.update(headers or {})
    result.raw=urllib3.response.HTTPResponse(body=io.BytesIO(result._content),preload_content=False)
    return result


def transport(app,monkeypatch,reply):
    app.config['NODE_HOSTS']=['compute.example.test']
    node=Node(name='test',url='https://compute.example.test',token_encrypted=encrypt(TOKEN))
    request=Mock(return_value=reply)
    monkeypatch.setattr(requests.Session,'request',request)
    return NodeEngine(node),request


def test_valid_versioned_capacity_uses_tls_and_never_follows_redirects(app,monkeypatch):
    engine,request=transport(app,monkeypatch,response(caps()))
    assert engine.capabilities()['host']['cpu_capacity']==2
    kwargs=request.call_args.kwargs
    assert kwargs['verify'] is True and kwargs['allow_redirects'] is False and kwargs['stream'] is True
    assert kwargs['headers']['Authorization']=='Bearer '+TOKEN


@pytest.mark.parametrize('bad',[-1,True,float('nan'),10**400])
def test_invalid_node_capacity_is_rejected_not_substituted_with_panel_resources(bad):
    data=caps();data['host']['cpu_capacity']=bad
    with pytest.raises(EngineError,match='invalid host capacity'):
        node_protocol.capabilities(data)


def test_old_unversioned_agent_is_rejected_with_upgrade_reason():
    data=caps();data.pop('protocol_version')
    with pytest.raises(EngineError,match='Upgrade'):
        node_protocol.capabilities(data)


def test_metric_cannot_overwrite_panel_identity_or_allocation(users):
    data=spec(users[0]);metric={'id':data['id'],'status':'running','allocation':{k:data[k] for k in ('ram_mb','vcpus','disk_gb')},
                             'usage':{'process_cpu_percent':None,'process_rss_mb':12},'name':'do-not-trust','node':'fake-host'}
    validated=node_protocol.metric(metric,data)
    assert set(validated)=={'status','usage'}
    changed=copy.deepcopy(metric);changed['allocation']['ram_mb']=999999
    with pytest.raises(EngineError,match='allocations differ'):
        node_protocol.metric(changed,data)


def test_wrong_operation_id_never_causes_duplicate_submission(app,monkeypatch,users):
    engine,request=transport(app,monkeypatch,response({'id':str(uuid.uuid4()),'status':'completed','result':{'status':'stopped'}}))
    with pytest.raises(UncertainError,match='different ID'):
        engine.create(spec(users[0]),{},operation_id=str(uuid.uuid4()))
    assert request.call_count==1 and request.call_args.args[0]=='GET'


@pytest.mark.parametrize('status',[500,502,503])
def test_http_server_failure_is_uncertain_even_for_non_json_body(app,monkeypatch,status):
    engine,_=transport(app,monkeypatch,response(b'proxy failure after request acceptance',status))
    with pytest.raises(UncertainError,match=f'HTTP {status}'):
        engine._request('POST','/v1/operations',{'id':str(uuid.uuid4())})


def test_bounded_node_response_rejects_oversize_or_invalid_json(app,monkeypatch):
    engine,request=transport(app,monkeypatch,response(b' '* (2**20+1)))
    with pytest.raises(UncertainError,match='size/time'):
        engine._request('GET','/v1/capabilities')
    request.return_value=response(b'not API JSON')
    with pytest.raises(UncertainError,match='invalid API JSON'):
        engine._request('GET','/v1/capabilities')


def test_node_error_never_echoes_stored_bearer_token(app,monkeypatch):
    engine,_=transport(app,monkeypatch,response({'error':'rejected credential '+TOKEN},401))
    with pytest.raises(EngineError) as caught:engine.capabilities()
    assert TOKEN not in str(caught.value) and '[redacted]' in str(caught.value)


def test_redirect_does_not_forward_bearer(app,monkeypatch):
    engine,request=transport(app,monkeypatch,response({},302,{'Location':'https://other.example/v1/capabilities'}))
    with pytest.raises(EngineError,match='redirect'):engine.capabilities()
    assert request.call_count==1


def test_agent_reconciliation_endpoint_is_authenticated_and_read_only(tmp_path,monkeypatch):
    app=agent_app(tmp_path);app.config['TEST_MODE']=False
    ident,guest=str(uuid.uuid4()),str(uuid.uuid4())
    with app.app_context():
        db.session.add(AgentOperation(id=ident,digest='isolated-test',status='uncertain',
                       payload=encrypt({'kind':'delete','spec':{'id':guest,'engine':'qemu'}})))
        db.session.commit()
    engine=Mock();monkeypatch.setattr('services.node_worker.engine_for',lambda *a:engine)
    with app.test_client() as client:
        assert client.post(f'/v1/operations/{ident}/reconcile').status_code==401
        result=client.post(f'/v1/operations/{ident}/reconcile',headers={'Authorization':'Bearer test-only-node-token-at-least-32-chars'})
        assert result.status_code==200 and result.json['status']=='completed'
        assert result.json['result']['status']=='deleted'
    engine.delete.assert_not_called();engine.force_stop.assert_not_called()

import uuid
import pytest
from engines import EngineError
from engines.node_engine import NodeEngine
from extensions import db
from models import AgentOperation, Node
from services.security import encrypt
from skvm import create_app


def agent_app(tmp_path):
    return create_app({'TESTING':True,'NODE_AGENT':True,'NODE_TOKEN':'test-only-node-token-at-least-32-chars',
                       'DATA_DIR':tmp_path/'agent','SQLALCHEMY_DATABASE_URI':f'sqlite:///{tmp_path/"agent.db"}',
                       'START_WORKER':False,'TEST_MODE':True})


def test_agent_has_no_default_password_or_token(tmp_path):
    with pytest.raises(RuntimeError,match='require a random'):
        create_app({'NODE_AGENT':True,'NODE_TOKEN':None,'DATA_DIR':tmp_path/'no-token',
                    'SQLALCHEMY_DATABASE_URI':f'sqlite:///{tmp_path/"no-token.db"}'})


def test_agent_requires_bearer_and_has_no_panel_routes(tmp_path):
    app=agent_app(tmp_path)
    with app.test_client() as client:
        assert client.get('/v1/capabilities').status_code==401
        assert client.get('/dashboard').status_code==404
        assert client.get('/v1/capabilities',headers={'Authorization':'Bearer wrong'}).status_code==401
        result=client.get('/v1/capabilities',headers={'Authorization':'Bearer test-only-node-token-at-least-32-chars'})
        assert result.status_code==200 and result.json['instances']==[]
        assert not result.json['qemu']['available']


def test_agent_operation_ids_are_idempotent(tmp_path):
    app=agent_app(tmp_path);ident=str(uuid.uuid4())
    with app.test_client() as client:
        headers={'Authorization':'Bearer test-only-node-token-at-least-32-chars'}
        payload={'id':ident,'kind':'stop','spec':{'id':str(uuid.uuid4())}}
        first=client.post('/v1/operations',json=payload,headers=headers)
        second=client.post('/v1/operations',json=payload,headers=headers)
        assert first.status_code==202 and second.status_code==200
        assert second.json['id']==ident
        assert client.post('/v1/operations',json=payload|{'kind':'delete'},headers=headers).status_code==409
    with app.app_context():
        assert db.session.scalar(db.select(db.func.count()).select_from(AgentOperation))==1


def test_node_transport_rejects_unallowlisted_host(app):
    node=Node(name='test-only',url='https://unallowlisted.invalid',token_encrypted=encrypt('test-only-token'))
    with pytest.raises(EngineError,match='allowlist'):
        NodeEngine(node).capabilities()


def test_admin_node_token_rotation_keeps_node_associations(app,client,users,monkeypatch):
    from services.security import decrypt
    from tests.conftest import signin,post
    node=Node(name='test-node',url='https://compute.example.test',token_encrypted=encrypt('old-test-token-01234567890123456789'))
    db.session.add(node);db.session.commit();ident=node.id
    monkeypatch.setattr(NodeEngine,'capabilities',lambda self:{'host':{},'qemu':{},'docker':{}})
    signin(client,'operator@example.test')
    assert client.get('/admin').status_code==200
    token='new-test-token-01234567890123456789'
    response=post(client,f'/admin/nodes/{ident}/rotate',{'token':token})
    assert response.status_code==302
    assert decrypt(db.session.get(Node,ident).token_encrypted)==token
    assert db.session.get(Node,ident).name=='test-node'

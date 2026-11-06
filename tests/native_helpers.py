"""Real panel routes + queue consumer for explicitly enabled native acceptance.

No fake engine, production database, public default credentials or resource mocks.
"""
import secrets
import time
from extensions import db
from models import Job, ProvisionTicket, User, VPS
from services.provisioning import start_worker
from services.background import stop_background
from services.security import decrypt
from tests.conftest import csrf_token


class NativePanel:
    def __init__(self,app):
        self.app=app
        password=secrets.token_urlsafe(24)
        self.owner=User(name='Native acceptance operator',email='native-operator@example.test',role='admin')
        self.owner.set_password(password);db.session.add(self.owner);db.session.commit()
        self.client=app.test_client()
        result=self.client.post('/login',data={'csrf_token':csrf_token(self.client),'email':self.owner.email,'password':password})
        assert result.status_code==302
        self.ident=None
        start_worker(app)

    def post(self,url,data=None):
        return self.client.post(url,data={'csrf_token':csrf_token(self.client,'/dashboard'),**(data or {})})

    def finish(self,response,expect='completed'):
        assert response.status_code==302,response.data.decode()[-1000:]
        assert '/vps/jobs/' in response.location,response.location
        ident=response.location.rstrip('/').rsplit('/',1)[1]
        deadline=time.monotonic()+1500
        while time.monotonic()<deadline:
            db.session.expire_all();job=db.session.get(Job,ident)
            if job.status not in ('queued','running'):break
            time.sleep(.1)
        db.session.expire_all();job=db.session.get(Job,ident)
        assert job.status==expect,f'{job.kind}: {job.status}: {job.message}'
        return job

    def create(self,form):
        before=db.session.scalar(db.select(db.func.count()).select_from(VPS))
        review=self.post('/vps/create',form)
        assert review.status_code==200 and b'Confirm &' in review.data,review.data.decode()[-1500:]
        ticket=db.session.scalar(db.select(ProvisionTicket).where(ProvisionTicket.consumed.is_(False)).order_by(ProvisionTicket.expires_at.desc()))
        assert ticket is not None
        self.ident=decrypt(ticket.payload)['spec']['id']
        assert db.session.get(VPS,self.ident) is None
        queued=self.post(f'/vps/provision/{ticket.id}')
        assert db.session.scalar(db.select(db.func.count()).select_from(VPS))==before
        count=db.session.scalar(db.select(db.func.count()).select_from(Job))
        duplicate=self.post(f'/vps/provision/{ticket.id}')
        assert duplicate.status_code==302 and db.session.scalar(db.select(db.func.count()).select_from(Job))==count
        self.finish(queued)
        assert db.session.get(VPS,self.ident) is not None
        return self.spec()

    def spec(self):
        db.session.expire_all()
        return db.session.get(VPS,self.ident).spec()

    def action(self,kind,data=None,expect='completed'):
        return self.finish(self.post(f'/vps/{self.ident}/action/{kind}',data),expect)

    def metrics(self):
        response=self.client.get(f'/api/vps/{self.ident}/metrics')
        assert response.status_code==200
        return response.json

    def webssh(self, key, expected_fingerprints, expect_changed=False):
        """Actual native guest -> SSH PTY -> panel WS, with no endpoint mocks."""
        import json
        import re
        import threading
        from werkzeug.serving import make_server
        from websockets.sync.client import connect
        from services.node_webssh import WIRE_LOGGER
        page=self.client.get(f'/webssh/{self.ident}')
        assert page.status_code==200 and b'data-available="true"' in page.data
        token=re.search(rb'name="csrf-token" content="([^"]+)"',page.data)[1].decode()
        cookie=self.client.get_cookie(self.app.config['SESSION_COOKIE_NAME']).value
        server=make_server('127.0.0.1',0,self.app,threaded=True)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        origin=f'http://127.0.0.1:{server.server_port}'
        try:
            with connect(origin.replace('http:','ws:')+f'/api/webssh/{self.ident}',origin=origin,
                         additional_headers={'Cookie':self.app.config['SESSION_COOKIE_NAME']+'='+cookie},
                         user_agent_header=self.client.environ_base['HTTP_USER_AGENT'],
                         proxy=None,compression=None,close_timeout=2,logger=WIRE_LOGGER) as ws:
                ws.send(json.dumps({'type':'connect','csrf_token':token,'cols':90,'rows':28,
                                    'credentials':{'method':'key','private_key':key.read_text(),'passphrase':''}}))
                event=json.loads(ws.recv(timeout=20))
                assert event['type']=='host_key' and event['changed'] is expect_changed,event
                # Cross-check before trust/auth against public keys obtained
                # through the independently tested native guest SSH connection.
                fingerprint=event['fingerprint']
                assert fingerprint in expected_fingerprints
                ws.send(json.dumps({'type':'trust','fingerprint':fingerprint,'accept':True,'confirm_changed':expect_changed}))
                ready=json.loads(ws.recv(timeout=20))
                assert ready['type']=='connected' and ready['username']=='skvmcheck',ready
                ws.send(json.dumps({'type':'resize','cols':111,'rows':37}))
                ws.send(json.dumps({'type':'input','data':"printf '\\nSKVM_WEBSSH_OK:%s\\n' \"$(id -un)\"; stty size\r"}))
                output='';deadline=time.monotonic()+30
                while time.monotonic()<deadline:
                    event=json.loads(ws.recv(timeout=10))
                    assert event['type']!='error',event
                    if event['type']=='output':output+=event['data']
                    if 'SKVM_WEBSSH_OK:skvmcheck' in output and '37 111' in output:break
                assert 'SKVM_WEBSSH_OK:skvmcheck' in output and '37 111' in output,output[-3000:]
                ws.send(json.dumps({'type':'disconnect'}))
                while json.loads(ws.recv(timeout=10))['type']!='disconnected':pass
                return fingerprint
        finally:
            server.shutdown();server.server_close();thread.join(timeout=3)

    def close(self):
        assert stop_background(self.app),'The actual worker is still running; do not remove its data.'

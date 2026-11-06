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

    def close(self):
        assert stop_background(self.app),'The actual worker is still running; do not remove its data.'

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

    def sshx(self, expected_fingerprints, guest=None, orphan=False):
        """Actual guest installer/client, encrypted management key and real output link."""
        from models import GuestAccess, SSHXSession
        from services.sshx import valid_link
        self.action('sshx_generate')
        db.session.expire_all()
        access=db.session.get(GuestAccess,self.ident)
        assert access.host_fingerprint in expected_fingerprints
        row=db.session.get(SSHXSession,self.ident)
        assert row and row.state=='generated'
        link=valid_link(decrypt(row.link_encrypted))
        secrets_protected = link not in row.link_encrypted and 'PRIVATE KEY' not in access.private_key_encrypted
        assert secrets_protected, 'SSHX secrets were not encrypted.'
        page=self.client.get(f'/vps/{self.ident}')
        displayed = page.status_code==200 and link.encode() in page.data
        assert displayed, 'The actual guest link was not displayed; secret output intentionally omitted.'
        assert b'referrerpolicy="no-referrer"' in page.data
        assert self.client.get(f'/vps/{self.ident}/console').status_code==404
        assert self.client.get(f'/webssh/{self.ident}').status_code==404
        blocker = None
        if guest is not None:
            # Deliberately corrupt the guest PID record with our harmless sleep,
            # or remove timeout while leaving the real SSHX child orphaned. Only
            # the disposable GUEST runs these acceptance commands, never host OS.
            state = f'"$HOME/.local/state/skvm-sshx-{self.ident}"'
            script = (f'state={state}; pid=$(cat "$state/pid"); '
                      + 'children=$(cat "/proc/$pid/task/$pid/children"); set -- $children; '
                      + '[ "$#" = 1 ] || exit 1; client=$1; '
                      + ('kill -KILL "$pid"; rm -f "$state/pid"; ' if orphan else '')
                      + 'sleep 120 </dev/null >/dev/null 2>&1 & blocker=$!; '
                      + ('' if orphan else 'printf \'%s\n\' "$blocker" > "$state/pid"; ')
                      + 'printf \'%s %s\' "$blocker" "$client"')
            response = guest(script)
            numbers = response.stdout.split()
            assert response.returncode == 0 and len(numbers) == 2 and all(value.isdecimal() for value in numbers)
            blocker, client_pid = map(int, numbers)
        try:
            self.action('sshx_stop')
            if blocker is not None:
                response = guest(f'kill -0 {int(blocker)}')
                assert response.returncode == 0, 'SSHX stop signalled an unrelated guest process.'
                # Independent OS observation, not just the cleared panel row.
                response = guest(f'test ! -e /proc/{client_pid}/exe')
                assert response.returncode == 0, 'The actual SSHX client remained live after Stop SSHX.'
        finally:
            if blocker is not None:
                guest(f'kill {int(blocker)}')
        db.session.expire_all()
        assert db.session.get(SSHXSession,self.ident).link_encrypted is None
        return access.host_fingerprint

    def close(self):
        assert stop_background(self.app),'The actual worker is still running; do not remove its data.'

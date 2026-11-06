"""Real loopback TLS/client/API integration; no live external host or guests.

Only TCP dialing is routed to an ephemeral local port because binding production
443 requires privileges. HTTPS, CA/hostname checks, bearer auth and JSON are real.
"""
from datetime import datetime, timedelta, timezone
import os
import socket
import threading
import pytest
import urllib3.connection
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from werkzeug.serving import make_server
from engines import EngineError, UncertainError
from engines.node_engine import NodeEngine
from extensions import db
from models import Node
from services.security import encrypt
from tests.test_node import agent_app


def certificates(root):
    now=datetime.now(timezone.utc)
    ca_key=ec.generate_private_key(ec.SECP256R1())
    ca_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'SKVM isolated TLS test CA')])
    ca=(x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True).sign(ca_key,hashes.SHA256()))
    key=ec.generate_private_key(ec.SECP256R1())
    cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'node.test')]))
          .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1))
          .add_extension(x509.SubjectAlternativeName([x509.DNSName('node.test')]),critical=False)
          .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),critical=False).sign(ca_key,hashes.SHA256()))
    ca_path,cert_path,key_path=[root/name for name in ('ca.pem','server.pem','server.key')]
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    os.chmod(key_path,0o600)
    return ca_path,cert_path,key_path


def test_real_tls_rejects_untrusted_ca_wrong_hostname_and_bad_bearer(app,tmp_path,monkeypatch):
    agent=agent_app(tmp_path)
    ca,cert,key=certificates(tmp_path)
    server=make_server('127.0.0.1',0,agent,threaded=True,ssl_context=(str(cert),str(key)))
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    original=urllib3.connection.HTTPSConnection._new_conn
    def route_test_tcp(connection):
        if connection.host in ('node.test','wrong-node.test'):
            return socket.create_connection(('127.0.0.1',server.server_port),timeout=connection.timeout)
        return original(connection)
    monkeypatch.setattr(urllib3.connection.HTTPSConnection,'_new_conn',route_test_tcp)
    app.config.update(NODE_HOSTS=['node.test','wrong-node.test'],NODE_CA_BUNDLE=None)
    node=Node(name='local-TLS-test',url='https://node.test',token_encrypted=encrypt('test-only-node-token-at-least-32-chars'))
    engine=NodeEngine(node)
    try:
        with pytest.raises(UncertainError,match='TLS validation'):
            engine.capabilities()  # Test CA is not in the platform trust store.
        app.config['NODE_CA_BUNDLE']=str(ca)
        result=engine.capabilities()
        assert result['protocol_version']==1 and result['instances']==[]
        assert result['host']['ram_total_mb']>=0 and type(result['host']['capacity_known']) is bool
        assert not result['qemu']['available'] and not result['docker']['available']  # Real agent test-mode refusal.
        node.url='https://wrong-node.test'
        with pytest.raises(UncertainError,match='TLS validation'):
            engine.capabilities()
        node.url='https://node.test';node.token_encrypted=encrypt('wrong-test-token-01234567890123456789')
        with pytest.raises(EngineError,match='HTTP 401'):
            engine.capabilities()
        with agent.app_context():
            from models import AgentInstance
            assert db.session.scalar(db.select(db.func.count()).select_from(AgentInstance))==0
    finally:
        server.shutdown();server.server_close();thread.join(timeout=5)
        with agent.app_context():
            db.session.remove();db.engine.dispose()

"""TLS-authenticated external agent transport. Remote timeouts are NOT reported as success."""
import time
import json
from urllib.parse import urlsplit
import uuid
import requests
from urllib3.exceptions import HTTPError
from flask import current_app
from engines import EngineError, UncertainError
from services.security import decrypt, validate_url
from services import node_protocol

RESPONSE_SECONDS = 30


class NodeEngine:
    def __init__(self, node):
        self.node = node

    def _request(self, method, path, payload=None, missing_ok=False):
        if self.node.enabled is False:
            raise EngineError('External node is disabled.')
        validate_url(self.node.url, current_app.config['NODE_HOSTS'], public=False)
        origin = urlsplit(self.node.url)
        if origin.path not in ('', '/') or origin.query:
            raise EngineError('External node URLs must be exact HTTPS origins without paths or query strings.')
        token = decrypt(self.node.token_encrypted)
        session = requests.Session()
        session.trust_env = False
        try:
            read_only = method == 'GET' and path.startswith(('/v1/capabilities', '/v1/instances'))
            timeout = (3, 5) if read_only else (5, 20)
            with session.request(method, self.node.url.rstrip('/') + path, json=payload,
                                 headers={'Authorization': f'Bearer {token}'}, timeout=timeout, stream=True, allow_redirects=False, verify=current_app.config.get('NODE_CA_BUNDLE') or True) as response:
                if response.status_code == 404 and missing_ok:
                    return None
                if response.is_redirect:
                    raise EngineError('External nodes may not redirect authenticated requests.')
                if response.status_code >= 500:
                    raise UncertainError(f'External node HTTP {response.status_code}; its operation outcome is unknown. Reconcile before retrying.')
                # Bound decoded response size and total transfer time, not just socket inactivity.
                body = bytearray()
                started = time.monotonic()
                while chunk := response.raw.read1(65536, decode_content=True):
                    body.extend(chunk)
                    if len(body) > 2**20 or time.monotonic() - started > RESPONSE_SECONDS:
                        raise UncertainError('External response exceeded the safe size/time limit. Actual operation state is unknown.')
                try:
                    data = json.loads(body)
                except (ValueError, RecursionError):
                    if response.status_code >= 400:
                        raise EngineError(f'External node HTTP {response.status_code}; its response was not valid API JSON.')
                    raise UncertainError('External node returned invalid API JSON. Inspect the operation before retrying.')
                if isinstance(data, dict) and isinstance(data.get('error'), str):
                    data['error'] = data['error'].replace(token, '[redacted]')
                if response.status_code >= 400:
                    detail = str(data.get('error', 'Request was rejected.'))[:1000] if isinstance(data, dict) else 'Request was rejected.'
                    detail = detail.replace(token, '[redacted]')
                    raise EngineError(f'External node HTTP {response.status_code}: {detail}')
                return data
        except (requests.RequestException, HTTPError, ValueError, OSError) as exc:
            raise UncertainError('External node unreachable or TLS validation failed. Its actual state is unknown; the operation may still be running. Reconcile before retrying.') from exc
        finally:
            session.close()

    def capabilities(self):
        return node_protocol.capabilities(self._request('GET', '/v1/capabilities'))

    def operation_status(self, ident, missing_ok=False):
        data = self._request('GET', f'/v1/operations/{ident}', missing_ok=missing_ok)
        return None if data is None else node_protocol.operation(data, ident)

    def reconcile(self, ident):
        return node_protocol.operation(self._request('POST', f'/v1/operations/{ident}/reconcile'), ident)

    def _operate(self, kind, spec, operation_id=None, **kwargs):
        ident = operation_id or str(uuid.uuid4())
        result = self.operation_status(ident, missing_ok=True)
        if result is None:
            result = node_protocol.operation(self._request('POST', '/v1/operations', {'id': ident, 'kind': kind, 'spec': spec, **kwargs}), ident)
        deadline = time.monotonic() + 1500
        while time.monotonic() < deadline:
            if result['status'] == 'completed':
                return result['result']
            if result['status'] == 'failed':
                raise EngineError(result.get('error') or 'External provisioning failed.')
            if result['status'] == 'uncertain':
                raise UncertainError('The node restarted during this operation. Inspect node resources before recovery.')
            time.sleep(2)
            result = self.operation_status(ident)
        raise UncertainError('External operation has not finished within 25 minutes. It remains reserved; reconcile it rather than creating a duplicate.')

    def create(self, spec, credentials, operation_id=None):
        return self._operate('create', spec, operation_id, credentials=credentials)

    def start(self, spec, **kwargs):
        return self._operate('start', spec, **kwargs)

    def stop(self, spec, **kwargs):
        return self._operate('stop', spec, **kwargs)

    def force_stop(self, spec, **kwargs):
        return self._operate('force_stop', spec, **kwargs)

    def restart(self, spec, **kwargs):
        return self._operate('restart', spec, **kwargs)

    def delete(self, spec, **kwargs):
        return self._operate('delete', spec, **kwargs)

    def resize(self, spec, disk_gb, **kwargs):
        return self._operate('resize', spec, disk_gb=disk_gb, **kwargs)

    def reinstall(self, spec, credentials, **kwargs):
        return self._operate('reinstall', spec, credentials=credentials, **kwargs)

    def metrics(self, spec):
        return node_protocol.metric(self._request('GET', f'/v1/instances/{spec["id"]}'), spec)

    def console(self, spec):
        return self._request('GET', f'/v1/instances/{spec["id"]}/console')['output']

    def console_input(self, spec, text):
        return self._request('POST', f'/v1/instances/{spec["id"]}/console', {'input': text})

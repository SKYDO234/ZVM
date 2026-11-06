"""Private WSS node relay: verified TLS, fixed origin, no proxy or redirects."""
import json
import logging
import re
import ssl
import time
from urllib.parse import urlsplit

from flask import current_app
from websockets.exceptions import WebSocketException
from websockets.sync.client import connect

from services.security import decrypt, validate_url
from services.webssh import MAX_INPUT, MAX_MESSAGE, SSHError, dimensions, message, send

# Upstream DEBUG frame/header logging must never record bearer tokens or SSH
# credentials, even when an operator enables verbose logging for other modules.
WIRE_LOGGER = logging.getLogger('skvm.private-webssh-wire')
WIRE_LOGGER.disabled = True
WIRE_LOGGER.propagate = False


def target(spec):
    return {key: spec[key] for key in ('id', 'owner_id', 'engine', 'username', 'ssh_port', 'ram_mb', 'vcpus', 'disk_gb')}


def capability(engine):
    cap = engine.capabilities().get('webssh')
    if not isinstance(cap, dict) or (type(cap.get('protocol_version')) is not int or cap['protocol_version'] != 1) or cap.get('available') is not True:
        raise SSHError('node_unsupported', 'This external node cannot provide WebSSH. Update/restart its agent and enable WebSocket upgrades in its HTTPS proxy.')


def open_stream(node, ident):
    if not node.enabled:
        raise SSHError('node_disabled', 'This external node is disabled.')
    validate_url(node.url, current_app.config['NODE_HOSTS'], public=False)
    origin = urlsplit(node.url)
    if origin.path not in ('', '/') or origin.query or origin.fragment:
        raise SSHError('invalid_node', 'External nodes must use exact allowlisted HTTPS origins.')
    token = decrypt(node.token_encrypted)
    try:
        context = ssl.create_default_context(cafile=current_app.config.get('NODE_CA_BUNDLE') or None)
        # websockets.sync.connect performs one handshake, never follows redirects.
        # No browser cookie, CSRF token or credential is placed in a URL/header.
        return connect('wss://' + origin.netloc + f'/v1/instances/{ident}/webssh',
                       ssl=context, additional_headers={'Authorization': f'Bearer {token}'},
                       proxy=None, compression=None, open_timeout=8, close_timeout=2,
                       ping_interval=20, ping_timeout=20, max_size=MAX_MESSAGE,
                       max_queue=8, logger=WIRE_LOGGER)
    except (OSError, TimeoutError, WebSocketException, ValueError):
        raise SSHError('node_unavailable', 'The authenticated node WebSocket could not be opened. Check its TLS certificate, agent version, token and proxy Upgrade settings. No local-host SSH fallback was attempted.') from None


def remote_message(data, spec):
    """Do not forward arbitrary node JSON or node-supplied credentials/identity."""
    kind = data['type']
    if kind == 'output' and isinstance(data.get('data'), str) and len(data['data'].encode('utf-8')) <= 65536:
        return {'type': kind, 'data': data['data']}
    if kind == 'pong' and type(data.get('nonce')) in (str, int) and len(str(data['nonce'])) <= 40:
        return {'type': kind, 'nonce': data['nonce']}
    if kind in ('host_key', 'connected'):
        digest = data.get('fingerprint')
        if not isinstance(digest, str) or not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', digest):
            raise SSHError('invalid_node_response', 'The node returned an invalid SSH host fingerprint.')
        if kind == 'connected':
            if data.get('username') != spec['username']:
                raise SSHError('target_changed', 'The external guest username differs from the panel record. Reconcile its configuration before reconnecting.')
            return {'type': kind, 'username': spec['username'], 'fingerprint': digest}
        previous, algorithm, changed = data.get('previous'), data.get('algorithm'), data.get('changed')
        if ((previous is not None and (not isinstance(previous, str) or not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', previous)))
                or not isinstance(algorithm, str) or not re.fullmatch(r'[A-Za-z0-9@._+-]{1,40}', algorithm)
                or type(changed) is not bool or changed != (previous is not None)):
            raise SSHError('invalid_node_response', 'The node returned invalid SSH trust metadata.')
        return {'type': kind, 'fingerprint': digest, 'algorithm': algorithm, 'previous': previous, 'changed': changed}
    if kind == 'error':
        # Never echo an arbitrary agent error (which could include its token).
        safe = {
            'authentication_failed': 'Guest SSH authentication failed. Use the guest password or authorized private key, not your panel password.',
            'host_key_rejected': 'The guest host fingerprint was not accepted. No guest credentials were sent.',
            'host_key_changed': 'The guest host key changed. Verify it independently in the serial console before replacing the saved key.',
            'host_key_timeout': 'Host-key confirmation timed out. Reconnect to try again.',
            'key_passphrase_required': 'This private key is encrypted. Enter its passphrase and reconnect.',
            'invalid_private_key': 'The private key or its passphrase could not be read. Use an OpenSSH Ed25519, ECDSA or RSA key.',
            'key_cost_limit': 'This private key exceeds the WebSSH decryption/validation work limit. Use a native SSH client or a dedicated bounded-cost key.',
            'session_limit': 'The node has reached its WebSSH session limit. Disconnect another session and retry.',
            'target_changed': 'The node guest configuration differs from the panel record. Reconcile it before connecting.',
            'timeout': 'The guest SSH connection timed out on the node. Check boot progress in Console.',
            'connection_refused': 'The guest SSH service is not accepting connections on the node. Check cloud-init and the guest SSH service.',
            'session_expired': 'The node WebSSH session expired. Reconnect to continue.',
        }
        code = data.get('code') if isinstance(data.get('code'), str) else ''
        raise SSHError(code if code in safe else 'node_ssh_failed', safe.get(code, 'The node could not complete this guest SSH session. Check its VM state, SSH service, host key and credentials in the node/serial console.'))
    if kind == 'disconnected':
        return {'type': kind, 'message': 'The external guest SSH session ended.'}
    raise SSHError('invalid_node_response', 'The node returned an invalid WebSSH message.')


def relay(ws, node, spec, first, check, audit=lambda action: None):
    peer = None
    try:
        check()
        peer = open_stream(node, spec['id'])
        # Bound TLS relay sends/close without imposing an idle read timeout.
        peer.socket = ws.watch_transport(peer.socket)
        check()
        peer.send(json.dumps({**first, 'target': target(spec)}))
        first['credentials'].clear()
        first.pop('credentials', None)
        started = last_input = window = time.monotonic()
        input_bytes = input_messages = 0
        while True:
            check()
            now = time.monotonic()
            if now - started >= current_app.config['WEBSSH_MAX_SECONDS'] or now - last_input >= current_app.config['WEBSSH_IDLE_SECONDS']:
                raise SSHError('session_expired', 'WebSSH reached its idle or maximum duration. Reconnect to continue.')
            for _ in range(4):
                try:
                    raw = peer.recv(timeout=0)
                except TimeoutError:
                    break
                data = remote_message(message(raw), spec)
                send(ws, data.pop('type'), **data)
                if data.get('username'):
                    audit('connected')
                if 'previous' in data:
                    audit('host_key_prompt')
                if data.get('message'):
                    return
            raw = ws.receive(timeout=0.025)
            if raw is None:
                continue
            data = message(raw)
            input_bytes += len(raw.encode('utf-8'))
            input_messages += 1
            if now - window >= 1:
                window, input_bytes, input_messages = now, len(raw.encode('utf-8')), 1
            if input_bytes > 512 * 1024 or input_messages > 200:
                raise SSHError('rate_limit', 'Terminal input rate exceeded the safe limit.')
            kind = data['type']
            if kind == 'input':
                if not isinstance(data.get('data'), str) or not 1 <= len(data['data'].encode('utf-8')) <= MAX_INPUT:
                    raise SSHError('invalid_message', 'Terminal input must be 1–16384 UTF-8 bytes.')
                last_input = now
            elif kind == 'resize':
                dimensions(data)
            elif kind not in ('trust', 'ping', 'disconnect'):
                raise SSHError('invalid_message', 'Unexpected WebSSH relay message.')
            check()
            peer.send(raw)
            if kind == 'disconnect':
                send(ws, 'disconnected', message='Disconnected. The remote guest continues running.')
                return
    except (WebSocketException, OSError, TimeoutError):
        raise SSHError('node_disconnected', 'The authenticated node stream closed. Check node reachability and its WebSocket proxy. The guest was not stopped.') from None
    finally:
        first.get('credentials', {}).clear()
        first.pop('credentials', None)
        if peer is not None:
            peer.close()

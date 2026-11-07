"""Real OS socket backpressure, without a host shell, VM or fake OS claims."""
import socket
import ssl
import threading
import time

import pytest
from simple_websocket import ConnectionClosed

from services.webssh_socket import BoundedSocket


class SocketWebSocket:
    """Only isolates protocol framing; blocking I/O is a real socketpair."""
    def __init__(self, raw, close_data=b'close'):
        self.sock = raw
        self.close_data = close_data
        self.stopped = threading.Event()

    def receive(self, timeout):
        if self.stopped.wait(timeout):
            raise ConnectionClosed(1000)
        return None

    def send(self, data):
        return self.sock.send(data)

    def close(self, **_kwargs):
        try:
            self.sock.send(self.close_data)
        finally:
            self.stopped.set()


@pytest.fixture(params=['tcp', 'tls'])
def backpressured_pair(request, tmp_path):
    raw, peer = socket.socketpair()
    if request.param == 'tls':
        from tests.test_node_tls import certificates
        ca, cert, key = certificates(tmp_path)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(str(cert), str(key))
        client_context = ssl.create_default_context(cafile=str(ca))
        raw = server_context.wrap_socket(raw, server_side=True, do_handshake_on_connect=False)
        peer = client_context.wrap_socket(peer, server_hostname='node.test', do_handshake_on_connect=False)
        raw.settimeout(3)
        peer.settimeout(3)
        handshake = threading.Thread(target=raw.do_handshake, daemon=True)
        handshake.start()
        peer.do_handshake()
        handshake.join(timeout=3)
        assert not handshake.is_alive()
        raw.settimeout(None)
        peer.settimeout(None)
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024)
    try:
        yield raw, peer
    finally:
        raw.close()
        peer.close()


@pytest.mark.parametrize('operation', ['send', 'close', 'node'])
def test_nonreading_socket_cannot_block_write_close_or_node_relay(operation, backpressured_pair):
    raw, peer = backpressured_pair
    browser, browser_peer = (raw, peer) if operation != 'node' else socket.socketpair()
    ws = BoundedSocket(SocketWebSocket(browser, b'x' * 1024 * 1024), write_timeout=0.1)
    remote = ws.watch_transport(raw) if operation == 'node' else None
    errors = []
    payload = b'x' * 1024 * 1024
    def write():
        try:
            if operation == 'send':
                ws.send(payload)
            elif operation == 'close':
                ws.close()
            else:
                remote.sendall(payload)
        except (ConnectionClosed, OSError) as exc:
            errors.append(type(exc).__name__)
    thread = threading.Thread(target=write, daemon=True)
    started = time.monotonic()
    try:
        thread.start()
        thread.join(timeout=2)
        assert not thread.is_alive(), 'Non-reading peer retained a terminal worker'
        assert time.monotonic() - started < 2
        assert ws.closed.is_set() and ws.reason == 1013
        assert all(t.aborted.is_set() for t in ws.transports)
        if operation != 'close':
            assert errors
    finally:
        ws.finish()
        peer.close()
        browser_peer.close()
        thread.join(timeout=1)
    assert not ws.reader.is_alive() and not ws.watchdog.is_alive()
    assert not ws.transports


def test_complete_concurrent_frames_are_not_truncated_or_interleaved():
    raw, peer = socket.socketpair()
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024)
    ws = BoundedSocket(SocketWebSocket(raw))
    chunks = []
    a, b = b'a' * 100_000, b'b' * 100_000
    def read():
        while sum(map(len, chunks)) < len(a) + len(b):
            chunk = peer.recv(1024)
            if not chunk:
                return
            chunks.append(chunk)
    reader = threading.Thread(target=read, daemon=True)
    writers = [threading.Thread(target=ws.send, args=(data,), daemon=True) for data in (a, b)]
    try:
        reader.start()
        for thread in writers:
            thread.start()
        for thread in writers:
            thread.join(timeout=3)
            assert not thread.is_alive()
        reader.join(timeout=3)
        assert not reader.is_alive()
        assert b''.join(chunks) in (a + b, b + a)
    finally:
        ws.finish()
        peer.close()
    assert not ws.reader.is_alive() and not ws.watchdog.is_alive()


def test_write_deadline_does_not_turn_idle_reads_into_timeouts():
    raw, peer = socket.socketpair()
    ws = BoundedSocket(SocketWebSocket(raw), write_timeout=0.05)
    try:
        assert ws.receive(timeout=0.2) is None
        assert not ws.closed.is_set()
        ws.send(b'active')
        assert peer.recv(100) == b'active'
    finally:
        ws.finish()
        peer.close()
    assert not ws.reader.is_alive() and not ws.watchdog.is_alive()

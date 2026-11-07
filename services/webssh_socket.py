"""Bound WebSSH input and writes, including during guest authentication.

Flask-Sock bounds messages but not its incoming queue or blocking socket writes.
The reader bounds pending messages; an independent watchdog interrupts stalled
writes with shutdown (not another potentially blocked WebSocket close frame).
Socket timeouts aren't changed: TLS reads must still remain idle between pings.
"""
import queue
import socket
import threading
import time

from simple_websocket import ConnectionClosed


STOP = object()
WRITE_TIMEOUT = 5


class DeadlineSocket:
    """Serialize complete frames and let a watchdog abort a blocked OS write.

    simple-websocket calls socket.send without handling short writes. sendall
    here prevents truncation/interleaving, including its internal ping replies.
    Forward all other socket operations unchanged, for raw and TLS sockets.
    """
    def __init__(self, raw, timeout):
        self.raw = raw
        self.timeout = timeout
        self.deadline = None
        self.lock = threading.Lock()
        self.aborted = threading.Event()

    def __getattr__(self, name):
        return getattr(self.raw, name)

    def sendall(self, data, *args, **kwargs):
        with self.lock:
            if self.aborted.is_set():
                raise OSError('WebSSH transport closed')
            self.deadline = time.monotonic() + self.timeout
            try:
                self.raw.sendall(data, *args, **kwargs)
            finally:
                self.deadline = None

    def send(self, data, *args, **kwargs):
        self.sendall(data, *args, **kwargs)
        return len(data)

    def abort(self):
        self.aborted.set()
        try:
            self.raw.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.raw.close()


class BoundedSocket:
    def __init__(self, ws, max_queue=16, write_timeout=WRITE_TIMEOUT):
        self.ws = ws
        self.queue = queue.Queue(maxsize=max_queue)
        self.closed = threading.Event()
        self.finished = threading.Event()
        self.reason = 1000
        self.write_timeout = write_timeout
        self.transports = []
        self.close_lock = threading.Lock()
        self.close_started = False
        # Both upstream libraries expose their OS socket. Wrap after the bounded
        # HTTP upgrade; their receiving threads continue to use the same fd.
        ws.sock = self.watch_transport(ws.sock)
        self.watchdog = threading.Thread(target=self._watch_writes, name='webssh-output', daemon=True)
        self.reader = threading.Thread(target=self._read, name='webssh-input', daemon=True)
        self.watchdog.start()
        self.reader.start()

    def watch_transport(self, raw):
        transport = DeadlineSocket(raw, self.write_timeout)
        self.transports.append(transport)
        if self.closed.is_set():
            transport.abort()
        return transport

    def _watch_writes(self):
        while not self.finished.wait(0.05):
            now = time.monotonic()
            if any((deadline := t.deadline) is not None and now >= deadline for t in tuple(self.transports)):
                self.reason = 1013
                self._wake_closed()
                self._abort_transports()

    def _abort_transports(self):
        for transport in tuple(self.transports):
            try:
                transport.abort()
            except OSError:
                pass

    def _read(self):
        try:
            while not self.closed.is_set():
                raw = self.ws.receive(timeout=0.25)
                if raw is None:
                    continue
                try:
                    self.queue.put_nowait(raw)
                except queue.Full:
                    self.close(reason=1009, message='WebSSH pending input limit exceeded')
                    return
        except (ConnectionClosed, OSError) as exc:
            if not self.closed.is_set():
                self.reason = getattr(exc, 'reason', 1000)
            self._wake_closed()

    def _wake_closed(self):
        self.closed.set()
        try:
            self.queue.put_nowait(STOP)
        except queue.Full:
            pass  # A blocked consumer already has data; ensure_open rejects it.

    def ensure_open(self):
        if self.closed.is_set():
            raise ConnectionClosed(self.reason)

    def receive(self, timeout=None):
        self.ensure_open()
        try:
            data = self.queue.get(timeout=timeout)
            self.ensure_open()
            if data is STOP:
                raise ConnectionClosed(self.reason)
            return data
        except queue.Empty:
            self.ensure_open()
            return None

    def send(self, data):
        self.ensure_open()
        try:
            return self.ws.send(data)
        except OSError:
            self._wake_closed()
            raise ConnectionClosed(self.reason) from None

    def close(self, reason=1000, message=None):
        self.reason = reason
        self._wake_closed()
        with self.close_lock:
            if self.close_started:
                return
            self.close_started = True
            try:
                self.ws.close(reason=reason, message=message)
            except (ConnectionClosed, OSError):
                pass

    def finish(self):
        try:
            self.close(reason=self.reason)
        finally:
            # Closing a WebSocket only sends its control frame. Interrupt any
            # stalled reader/writer before ending watchdog/request ownership.
            self._abort_transports()
            self.finished.set()
            self.reader.join(timeout=0.5)
            self.watchdog.join(timeout=0.5)
            while True:
                try:
                    self.queue.get_nowait()
                except queue.Empty:
                    break
            self.transports.clear()

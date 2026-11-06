"""Bound pending input even while SSH key exchange/authentication is blocking.

Flask-Sock limits each message but its underlying receive buffer has no queue
limit. A dedicated reader immediately drains it into a bounded queue; flooding
cannot pile up credentials/input while a guest stalls an SSH handshake.
"""
import queue
import threading

from simple_websocket import ConnectionClosed


STOP = object()


class BoundedSocket:
    def __init__(self, ws, max_queue=16):
        self.ws = ws
        self.queue = queue.Queue(maxsize=max_queue)
        self.closed = threading.Event()
        self.reason = 1000
        self.reader = threading.Thread(target=self._read, name='webssh-input', daemon=True)
        self.reader.start()

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
        return self.ws.send(data)

    def close(self, reason=1000, message=None):
        self.reason = reason
        self._wake_closed()
        try:
            self.ws.close(reason=reason, message=message)
        except (ConnectionClosed, OSError):
            pass

    def finish(self):
        self.close(reason=self.reason)
        self.reader.join(timeout=0.5)
        # Release queued JSON strings, which may include initial credentials.
        while True:
            try:
                self.queue.get_nowait()
            except queue.Empty:
                break

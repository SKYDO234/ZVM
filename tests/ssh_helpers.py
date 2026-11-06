"""Disposable real SSH protocol/PTY fixture, NOT a VM, host shell or OS boot.

Tests explicitly replace QEMU endpoint discovery with this loopback endpoint.
The server performs real key exchange, host keys, password/public-key auth and
PTY/window requests. Its shell callback only echoes bytes; it runs no commands.
"""
import io
import secrets
import socket
import threading
import time

import paramiko


class SSHProtocolServer:
    def __init__(self):
        self.key = paramiko.RSAKey.generate(2048)
        self.client_key = paramiko.RSAKey.generate(2048)
        self.password = secrets.token_urlsafe(24)
        self.auth_calls = []
        self.auth_delay = 0
        self.sizes = []
        self.inputs = []
        self.transports = []
        self.stop_event = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(8)
        self.listener.settimeout(0.2)
        self.endpoint = self.listener.getsockname()
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.thread.start()

    def private_key(self, passphrase=None):
        output = io.StringIO()
        self.client_key.write_private_key(output, password=passphrase)
        return output.getvalue()

    def _accept(self):
        while not self.stop_event.is_set():
            try:
                peer, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve, args=(peer,), daemon=True).start()

    def _serve(self, peer):
        transport = paramiko.Transport(peer)
        self.transports.append(transport)
        transport.add_server_key(self.key)
        state = self
        shell = threading.Event()

        class Interface(paramiko.ServerInterface):
            def get_allowed_auths(self, username):
                return 'password,publickey'

            def check_auth_password(self, username, password):
                state.auth_calls.append(('password', username))
                if state.auth_delay:
                    time.sleep(state.auth_delay)
                return paramiko.AUTH_SUCCESSFUL if username == 'guest' and secrets.compare_digest(password, state.password) else paramiko.AUTH_FAILED

            def check_auth_publickey(self, username, key):
                state.auth_calls.append(('key', username))
                return paramiko.AUTH_SUCCESSFUL if username == 'guest' and key.asbytes() == state.client_key.asbytes() else paramiko.AUTH_FAILED

            def check_channel_request(self, kind, chanid):
                return paramiko.OPEN_SUCCEEDED if kind == 'session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

            def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
                state.sizes.append((width, height))
                return term == b'xterm-256color'

            def check_channel_window_change_request(self, channel, width, height, pixelwidth, pixelheight):
                state.sizes.append((width, height))
                return True

            def check_channel_shell_request(self, channel):
                shell.set()
                return True

        try:
            transport.start_server(server=Interface())
            channel = transport.accept(12)
            if channel is None or not shell.wait(5):
                return
            channel.settimeout(0.2)
            channel.sendall(b'SSH protocol fixture ready (not an OS guest)\r\n')
            # Exercise stateful UTF-8 decoding across actual SSH packets.
            channel.sendall(b'\xe2')
            time.sleep(0.08)
            channel.sendall(b'\x82\xac UTF-8 stream\r\n')
            pending = bytearray()
            while transport.is_active() and not self.stop_event.is_set():
                try:
                    data = channel.recv(16384)
                except socket.timeout:
                    continue
                if not data:
                    break
                state.inputs.append(data)
                if data == b'\x03':
                    pending.clear()
                    channel.sendall(b'\r\nCONTROL-C received\r\n')
                elif data == b'\x04':
                    channel.send_exit_status(0)
                    channel.close()
                    break
                else:
                    channel.sendall(data.replace(b'\r', b'\r\n'))
                    pending.extend(data)
                    if b'\r' in pending or b'\n' in pending:
                        if b'__fixture_size__' in pending:
                            cols, rows = state.sizes[-1]
                            channel.sendall(f'PTY dimensions: {cols}x{rows}\r\n'.encode())
                        pending.clear()
        except (EOFError, OSError, paramiko.SSHException):
            pass  # Expected during rejected keys/auth and forced revocation tests.
        finally:
            transport.close()
            peer.close()

    def close(self):
        self.stop_event.set()
        self.listener.close()
        for transport in self.transports:
            transport.close()
        self.thread.join(timeout=2)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

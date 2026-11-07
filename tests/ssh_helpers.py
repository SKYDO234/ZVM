"""Real SSH protocol fixture, NOT a VM or an SSHX installation.

QEMU endpoint discovery is explicitly replaced in protocol tests. No shell,
PTY or OS command is executed. Fixed-script stdin is recorded and a test callback
returns clearly synthetic output. Native guest acceptance is a separate suite.
"""
import io
import secrets
import socket
import threading
import time

import paramiko


class SSHProtocolServer:
    def __init__(self, program=None):
        self.key = paramiko.RSAKey.generate(2048)
        self.client_key = paramiko.RSAKey.generate(2048)
        self.extra_keys = set()
        self.password = secrets.token_urlsafe(24)
        self.auth_calls, self.commands, self.scripts = [], [], []
        self.auth_delay = 0
        self.program = program or (lambda script: (0, 'fixture script received\n'))
        self.transports = []
        self.stop_event = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(8)
        self.listener.settimeout(.2)
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
        state, execute = self, threading.Event()

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
                accepted = key.asbytes() == state.client_key.asbytes() or key.asbytes() in state.extra_keys
                return paramiko.AUTH_SUCCESSFUL if username == 'guest' and accepted else paramiko.AUTH_FAILED

            def check_channel_request(self, kind, chanid):
                return paramiko.OPEN_SUCCEEDED if kind == 'session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

            def check_channel_exec_request(self, channel, command):
                state.commands.append(command)
                if command != b'sh -s':
                    return False
                execute.set()
                return True

        try:
            transport.start_server(server=Interface())
            channel = transport.accept(12)
            if channel is None or not execute.wait(5):
                return
            channel.settimeout(.2)
            script = bytearray()
            while transport.is_active() and not self.stop_event.is_set():
                try:
                    chunk = channel.recv(8192)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                script.extend(chunk)
                if len(script) > 65536:
                    return
            decoded = script.decode()
            state.scripts.append(decoded)
            code, output = state.program(decoded)
            channel.sendall(output.encode())
            channel.send_exit_status(code)
            channel.shutdown_write()
            while not channel.closed and not state.stop_event.wait(.05):
                pass
        except (EOFError, OSError, paramiko.SSHException):
            pass
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

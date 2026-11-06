#!/usr/bin/env python3
"""Start the real WSGI panel, foreground by default, without systemd or shell eval."""
import argparse
import fcntl
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import build_opener, ProxyHandler
import psutil

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from config import configuration


def owned_master(pidfile):
    if pidfile.is_symlink():
        raise RuntimeError('Unsafe panel PID-file symlink; inspect it before starting.')
    if not pidfile.exists():
        return None
    try:
        pid = int(pidfile.read_text().strip())
        if pid <= 1:
            raise ValueError
        process = psutil.Process(pid)
        if not process.is_running() or process.status() == psutil.STATUS_ZOMBIE:
            return None
        command = process.cmdline()
        matching_pid = any(arg == '--pid' and index + 1 < len(command) and command[index + 1] == str(pidfile)
                           for index, arg in enumerate(command))
        if Path(process.cwd()).resolve() != ROOT or not matching_pid or not any('gunicorn' in arg for arg in command) or 'skvm:create_app()' not in command:
            raise RuntimeError('The panel PID file refers to another process. Nothing was stopped or overwritten.')
        return process
    except psutil.NoSuchProcess:
        return None
    except (OSError, ValueError, psutil.AccessDenied) as exc:
        raise RuntimeError('Cannot prove panel process identity; inspect its PID file manually.') from exc


def wait_for_panel(pidfile, port, seconds=20):
    opener = build_opener(ProxyHandler({}))
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if owned_master(pidfile):
            try:
                with opener.open(f'http://127.0.0.1:{port}/login', timeout=2) as response:
                    if response.status == 200:
                        return True
            except (URLError, OSError):
                pass
        time.sleep(.2)
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--background', action='store_true', help='Use Gunicorn daemon mode and verify HTTP readiness.')
    parser.add_argument('--stop', action='store_true', help='Gracefully stop only this checkout’s proven Gunicorn master.')
    args = parser.parse_args()
    config = configuration()
    host = os.getenv('SKVM_HOST', '0.0.0.0')
    port = int(os.getenv('SKVM_PORT', '31120'))
    if not 1 <= port <= 65535:
        parser.error('Port must be between 1 and 65535.')
    data = Path(config['DATA_DIR'])
    if any(char in str(data) for char in ('\n', '\r', '\x00', ',')):
        parser.error('Data path contains unsupported control characters or separators.')
    data.mkdir(parents=True, exist_ok=True, mode=0o700)
    logs = data / 'logs'
    logs.mkdir(exist_ok=True, mode=0o700)
    pidfile = data / 'panel.pid'
    fd = os.open(data / 'panel-launch.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        existing = owned_master(pidfile)
        if args.stop:
            if not existing:
                print('No managed panel master is running. No guest process was stopped.')
                return 0
            existing.terminate()
            try:
                existing.wait(timeout=30)
            except psutil.TimeoutExpired:
                print('Panel shutdown is still draining; no force-kill was attempted.', file=sys.stderr)
                return 1
            print('Managed panel stopped. Guest resources and database were not deleted.')
            return 0
        if existing:
            if wait_for_panel(pidfile, port, seconds=5):
                print(f'SKVM is already running on port {port}; accounts/data were not reset.')
                return 0
            raise RuntimeError('A managed master is running but this port is not ready. Inspect data/logs/panel.error.log; no duplicate was launched.')
        # Do not mistake another service on the requested port for this panel.
        with socket.socket() as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind((host, port))
            except OSError as exc:
                raise RuntimeError(f'Port {port} is occupied. No unrelated process was stopped.') from exc
        gunicorn = ROOT / '.venv/bin/gunicorn'
        if not gunicorn.is_file():
            raise RuntimeError('Gunicorn is not installed. Run bash install.sh first.')
        command = [str(gunicorn), '--config', str(ROOT / 'gunicorn.conf.py'), '--chdir', str(ROOT),
                   '--bind', f'{host}:{port}', '--pid', str(pidfile),
                   '--access-logfile', str(logs / 'panel.access.log'), '--error-logfile', str(logs / 'panel.error.log'),
                   'skvm:create_app()']
        print(f'Starting SKVM on {host}:{port}. Keep Codespaces port visibility Private.', flush=True)
        os.chdir(ROOT)
        if args.background:
            subprocess.run(command + ['--daemon'], check=True, timeout=20)
            if not wait_for_panel(pidfile, port):
                raise RuntimeError('Panel did not become HTTP-ready. Inspect data/logs/panel.error.log; no success or force-kill was fabricated.')
            print(f'SKVM is ready on port {port}. PID: {pidfile}. Logs: {logs}.')
            return 0
        # Default is a real foreground service, suitable for a Codespaces terminal.
        os.execv(str(gunicorn), command)
    return 0


if __name__ == '__main__':
    os.umask(0o077)
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f'SKVM: {exc}', file=sys.stderr)
        raise SystemExit(1)

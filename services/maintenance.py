"""Bound emulator logs independently of long-running provisioning downloads."""
import logging
import os
import re
import stat
from pathlib import Path
from extensions import db
from models import ProvisionTicket
from models.user import utcnow
from services.security import locked


def trim_log(path, maximum=5 * 2**20, keep=2**20):
    try:
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
    except (OSError, FileNotFoundError):
        return
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size <= maximum:
            return
        os.lseek(fd, max(0, info.st_size - keep), os.SEEK_SET)
        tail = os.read(fd, keep)
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, tail)
        os.ftruncate(fd, len(tail))
        # QEMU serial logappend and Popen's 'ab' descriptor use O_APPEND,
        # so truncating this inode does not strand a live process on an unlinked file.
    finally:
        os.close(fd)


def maintain_once(app):
    root = Path(app.config['DATA_DIR']) / 'vms'
    for directory in root.iterdir():
        if directory.is_symlink() or not re.fullmatch(r'[0-9a-f-]{36}', directory.name):
            continue
        for name in ('serial.log', 'qemu.log'):
            trim_log(directory / name)
    db.session.execute(db.delete(ProvisionTicket).where(ProvisionTicket.expires_at < utcnow()))
    db.session.commit()


def _loop(app, stop_event):
    with app.app_context():
        try:
            with locked('maintenance-leader', blocking=False):
                while not stop_event.is_set():
                    try:
                        maintain_once(app)
                    except Exception:
                        logging.exception('Workspace maintenance failed')
                        db.session.rollback()
                    finally:
                        db.session.remove()
                    stop_event.wait(20)
        except BlockingIOError:
            pass


def start_maintenance(app):
    if not app.config['TEST_MODE']:
        from services.background import start_background
        return start_background(app, 'skvm-maintenance', _loop)

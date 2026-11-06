"""Vendor allowlisted HTTPS cloud images; no unverified URL is treated as working."""
from contextlib import contextmanager
import hashlib
import json
import os
import time
from pathlib import Path
from urllib.parse import urljoin
import requests
from flask import current_app
from engines import EngineError
from extensions import db
from models import OSImage
from models.user import utcnow
from services.security import atomic_json, locked, run, settings, validate_url

# The nine OS families come from docs/reference/n.txt. Original URLs are documented in the audit.
CATALOG = [
    ('ubuntu-22.04', 'Ubuntu 22.04', 'ubuntu', 'https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img', 'ubuntu:22.04', 8, None),
    ('ubuntu-24.04', 'Ubuntu 24.04', 'ubuntu', 'https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img', 'ubuntu:24.04', 8, None),
    ('debian-11', 'Debian 11', 'debian', 'https://cloud.debian.org/images/cloud/bullseye/latest/debian-11-generic-amd64.qcow2', 'debian:bullseye-slim', 8, 'Debian 11 is outside regular LTS. Review archive availability and extended support.'),
    ('debian-12', 'Debian 12', 'debian', 'https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2', 'debian:bookworm-slim', 8, None),
    ('debian-13', 'Debian 13', 'debian', 'https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.qcow2', 'debian:trixie-slim', 8, None),
    ('fedora-40', 'Fedora 40', 'fedora', 'https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/40/Cloud/x86_64/images/Fedora-Cloud-Base-40-1.14.x86_64.qcow2', 'fedora:40', 10, 'Fedora 40 is end-of-life. Archive only; not recommended for internet-facing workloads.'),
    ('centos-9', 'CentOS Stream 9', 'centos', 'https://cloud.centos.org/centos/9-stream/x86_64/images/CentOS-Stream-GenericCloud-9-latest.x86_64.qcow2', 'quay.io/centos/centos:stream9', 10, None),
    ('alma-9', 'AlmaLinux 9', 'alma', 'https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/AlmaLinux-9-GenericCloud-latest.x86_64.qcow2', 'almalinux:9', 10, None),
    ('rocky-9', 'Rocky Linux 9', 'rocky', 'https://download.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud.latest.x86_64.qcow2', 'rockylinux:9', 10, None),
]


def seed_images():
    for ident, name, user, url, docker_image, disk, eol in CATALOG:
        if not db.session.get(OSImage, ident):
            db.session.add(OSImage(id=ident, name=name, username=user, qemu_url=url,
                                   docker_image=docker_image, min_disk_gb=disk, eol_warning=eol))
    db.session.commit()


class ImageManager:
    @contextmanager
    def _request(self, url, method='GET', **kwargs):
        session = requests.Session()
        session.trust_env = False
        try:
            for _ in range(5):
                validate_url(url, settings()['image_hosts'])
                response = session.request(method, url, allow_redirects=False, timeout=(8, 30), **kwargs)
                if response.is_redirect:
                    next_url = urljoin(url, response.headers.get('Location', ''))
                    response.close()
                    url = next_url
                    continue
                if response.status_code not in (200, 206):
                    response.close()
                    raise EngineError(f'Image server returned HTTP {response.status_code}; update or verify this OS URL in Administration.')
                try:
                    yield response
                finally:
                    response.close()
                return
            raise EngineError('Too many image redirects.')
        except requests.RequestException as exc:
            raise EngineError(f'Image server unreachable: {type(exc).__name__}. Check outbound network access and the OS URL.') from exc
        finally:
            session.close()

    def verify(self, image):
        try:
            # Range GET also works on vendor hosts that reject HEAD.
            with self._request(image.qemu_url, stream=True, headers={'Range': 'bytes=0-3'}) as response:
                head = next(response.iter_content(4), b'')
                if head != b'QFI\xfb':
                    raise EngineError('URL did not return a QCOW2 image (it may be an HTML error page).')
            image.verification = 'verified'
            image.verification_message = 'HTTPS endpoint returned QCOW2 magic. Full image checks run before provisioning.'
            image.verified_at = utcnow()
            db.session.commit()
            return True
        except EngineError as exc:
            image.verification = 'unavailable'
            image.verification_message = str(exc)
            image.verified_at = utcnow()
            db.session.commit()
            raise

    def obtain(self, image):
        cache = Path(current_app.config['DATA_DIR']) / 'images'
        cache.mkdir(parents=True, exist_ok=True, mode=0o700)
        key = hashlib.sha256((image.qemu_url + (image.sha256 or '')).encode()).hexdigest()
        target = cache / f'{key}.qcow2'
        with locked(f'image-{key}'):
            if target.is_symlink():
                raise EngineError('Unsafe cloud-image cache symlink. Inspect the cache before retrying.')
            if target.exists():
                self.inspect(target)
                if image.sha256:
                    digest = hashlib.sha256()
                    with target.open('rb') as cached:
                        for block in iter(lambda: cached.read(1024 * 1024), b''):
                            digest.update(block)
                    if digest.hexdigest() != image.sha256.lower():
                        raise EngineError('Cached image SHA256 mismatch. No guest was created; inspect/remove the damaged cache entry.')
                run(['qemu-img', 'check', '-f', 'qcow2', target], timeout=180)
                return target
            self.verify(image)
            temp = target.with_suffix('.part')
            max_bytes = settings()['image_max_download_gb'] * 2**30
            digest = hashlib.sha256()
            written = 0
            started = time.monotonic()
            try:
                fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as out, self._request(image.qemu_url, stream=True) as response:
                    while block := response.raw.read1(1024 * 1024, decode_content=True):
                        written += len(block)
                        if written > max_bytes or time.monotonic() - started > 1200:
                            raise EngineError('Image download exceeded the configured size or time limit.')
                        digest.update(block)
                        out.write(block)
                    out.flush()
                    os.fsync(out.fileno())
                actual = digest.hexdigest()
                if image.sha256 and actual != image.sha256.lower():
                    raise EngineError('Image SHA256 mismatch. Image was not used.')
                self.inspect(temp)
                run(['qemu-img', 'check', '-f', 'qcow2', temp], timeout=180)
                os.replace(temp, target)
                atomic_json(target.with_suffix('.json'), {'url': image.qemu_url, 'sha256': actual, 'downloaded_at': utcnow().isoformat()})
            except requests.RequestException as exc:
                raise EngineError('Image download interrupted; no VM was created.') from exc
            finally:
                temp.unlink(missing_ok=True)
        return target

    @staticmethod
    def inspect(path):
        info = json.loads(run(['qemu-img', 'info', '--output=json', '-f', 'qcow2', path], timeout=30))
        if info.get('format') != 'qcow2' or info.get('backing-filename') or info.get('full-backing-filename'):
            raise EngineError('Only standalone QCOW2 cloud images without backing files are accepted.')
        specific = info.get('format-specific', {}).get('data', {})
        if specific.get('data-file') or specific.get('encrypt') or info.get('encrypted'):
            raise EngineError('External-data or encrypted cloud images are not supported.')
        return info

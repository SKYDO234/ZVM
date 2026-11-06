"""Unprivileged guest containers, not full VMs; Docker API is never exposed to browsers."""
import docker
import os
import threading
import time
from docker.errors import APIError, DockerException, NotFound
from flask import current_app
from engines import EngineError, UncertainError
from extensions import db
from models import OSImage
from services.security import locked, settings

COMMANDS = {
    'identity': ['id'], 'system': ['uname', '-a'], 'storage': ['df', '-h'],
    'processes': ['ps', 'aux'], 'os': ['cat', '/etc/os-release'],
}
KEEPALIVE = ['/bin/sh', '-c', "trap 'exit 0' TERM INT; while :; do sleep 60 & wait $!; done"]


_cpu_samples = {}
_cpu_lock = threading.Lock()


def _cpu_percent(ident, current, previous):
    """one_shot stats often omit precpu_stats; retain real counters across polls."""
    total = current.get('cpu_usage', {}).get('total_usage')
    system = current.get('system_cpu_usage')
    if type(total) is not int or type(system) is not int:
        return None
    with _cpu_lock:
        cached = _cpu_samples.get(ident)
        _cpu_samples[ident] = (total, system)
        if len(_cpu_samples) > 500:
            _cpu_samples.pop(next(iter(_cpu_samples)))
    old_total = previous.get('cpu_usage', {}).get('total_usage') if previous else None
    old_system = previous.get('system_cpu_usage') if previous else None
    if old_total is None or old_system is None:
        if cached is None:
            return None
        old_total, old_system = cached
    delta, system_delta = total - old_total, system - old_system
    if delta < 0 or system_delta <= 0:
        return None
    online = current.get('online_cpus') or len(current.get('cpu_usage', {}).get('percpu_usage') or []) or 1
    return round(delta / system_delta * online * 100, 2)


class DockerEngine:
    def _client(self, timeout=15):
        host = os.getenv('DOCKER_HOST', '')
        if host and not host.startswith('unix://'):
            raise EngineError('Direct remote Docker transports cannot safely use panel-host capacity. Deploy the authenticated SKVM agent beside the daemon and connect it as an external node instead.')
        try:
            client = docker.from_env(timeout=timeout)
            client.ping()
            return client
        except DockerException as exc:
            raise EngineError(f'Local Unix Docker daemon unavailable: {str(exc)[:700]}. Check the socket path/permissions and daemon availability, or deploy an external SKVM node.') from exc

    def capabilities(self):
        base = {'available': False, 'name': 'Docker containers', 'storage_limits': False,
                'warning': 'Containers share the host kernel. They are not full virtual machines. No SSH server is installed automatically.'}
        if not current_app.config['ENABLE_DOCKER'] or not settings()['docker_enabled']:
            return base | {'reason': 'Docker is disabled by the operator.'}
        if current_app.config['TEST_MODE']:
            return base | {'reason': 'Test mode: real provisioning is deliberately disabled.'}
        try:
            with self._client(timeout=3) as client:
                info = client.info()
            if not info.get('MemoryLimit', True) or not info.get('CpuCfsQuota', True):
                return base | {'reason': 'Docker cannot enforce memory or CPU quotas on this daemon. Configure cgroup delegation or use an external node.'}
            driver = info.get('Driver', 'unknown')
            supported = current_app.config['DOCKER_STORAGE_LIMITS'] and driver in ('overlay2', 'btrfs', 'zfs')
            return base | {'available': True, 'reason': 'Docker daemon responded to ping.', 'driver': driver,
                           'storage_limits': supported, 'rootless': any('rootless' in s for s in info.get('SecurityOptions', []))}
        except (EngineError, DockerException) as exc:
            return base | {'reason': 'Docker capability check failed: ' + str(exc)[:1000]}

    def _container(self, client, spec):
        ident = spec.get('runtime', {}).get('container_id')
        try:
            container = client.containers.get(ident or f'skvm-{spec["id"]}')
        except NotFound:
            return None
        labels = container.labels
        if labels.get('skvm.instance') != spec['id'] or labels.get('skvm.owner') != str(spec['owner_id']):
            raise EngineError('Container ownership labels do not match. Refusing to operate on it.')
        return container

    def create(self, spec, credentials=None, operation_id=None):
        capability = self.capabilities()
        if not capability['available']:
            raise EngineError(capability['reason'])
        enforced = capability['storage_limits']
        if not enforced and not spec.get('allow_unenforced_storage'):
            raise EngineError('This Docker storage driver has no verified size quotas. Explicitly acknowledge an unenforced storage budget or choose QEMU.')
        image = db.session.get(OSImage, spec['os_id'])
        if not image or not image.enabled:
            raise EngineError('Selected container image is not enabled.')
        attempting_create = False
        try:
            with locked(f'vm-{spec["id"]}'), self._client(timeout=600) as client:
                if self._container(client, spec):
                    raise EngineError('A container with this ID already exists. Refusing to duplicate it.')
                # Only catalog image references, never arbitrary Dockerfiles, mounts, commands or capabilities.
                image_obj = client.images.pull(image.docker_image)
                network_name = f'skvm-net-{spec["id"]}'
                try:
                    network = client.networks.get(network_name)
                    if (network.attrs.get('Labels') or {}).get('skvm.managed') != 'true' or (network.attrs.get('Labels') or {}).get('skvm.instance') != spec['id'] or not network.attrs.get('Internal'):
                        raise EngineError('This guest network is not an SKVM-managed internal bridge.')
                except NotFound:
                    attempting_create = True  # A network-create disconnect is also an uncertain mutation.
                    network = client.networks.create(network_name, driver='bridge', internal=True, labels={'skvm.managed': 'true', 'skvm.instance': spec['id']})
                attempting_create = True
                try:
                    container = client.containers.create(
                        image=image_obj.id, name=f'skvm-{spec["id"]}', hostname=spec['name'].lower(),
                        command=KEEPALIVE, user='1000:1000', working_dir='/tmp',
                        mem_limit=f'{spec["ram_mb"]}m', memswap_limit=f'{spec["ram_mb"]}m',
                        nano_cpus=spec['vcpus'] * 1_000_000_000, pids_limit=128,
                        cap_drop=['ALL'], security_opt=['no-new-privileges:true'], privileged=False,
                        network=network.name, init=True, stdin_open=False, tty=False,
                        storage_opt={'size': f'{spec["disk_gb"]}G'} if enforced else None,
                        restart_policy={'Name': 'no'},
                        log_config=docker.types.LogConfig(type='json-file', config={'max-size': '5m', 'max-file': '2'}),
                        labels={'skvm.instance': spec['id'], 'skvm.owner': str(spec['owner_id']), 'skvm.managed': 'true', 'skvm.os_id': spec['os_id']},
                    )
                except DockerException as exc:
                    if isinstance(exc, APIError) and exc.status_code and exc.status_code < 500:
                        try:
                            self._remove_network(client, spec)
                        except (EngineError, DockerException) as cleanup:
                            raise UncertainError('Container creation was rejected, but its network could not be cleaned up. Inspect the labeled network before releasing this job.') from cleanup
                    raise
                return {'status': 'stopped', 'runtime': {'container_id': container.id, 'image_id': image_obj.id,
                        'image_digest': (image_obj.attrs.get('RepoDigests') or [None])[0],
                        'storage_enforced': enforced, 'uid': 1000, 'network': network.name}, 'ssh_port': None}
        except DockerException as exc:
            if attempting_create and not (isinstance(exc, APIError) and exc.status_code and exc.status_code < 500):
                raise UncertainError('Docker disconnected during creation. A labeled container may exist; reconcile before retrying.') from exc
            raise EngineError(f'Docker creation failed: {str(exc)[:1200]}') from exc

    def _remove_network(self, client, spec):
        name = spec.get('runtime', {}).get('network') or f'skvm-net-{spec["id"]}'
        try:
            network = client.networks.get(name)
        except NotFound:
            return
        labels = network.attrs.get('Labels') or {}
        if labels.get('skvm.instance') != spec['id'] or labels.get('skvm.managed') != 'true':
            raise EngineError('Network ownership labels do not match; no unrelated network was deleted.')
        if network.attrs.get('Containers'):
            raise EngineError('The managed network still has attached containers. Inspect it before retrying deletion.')
        network.remove()

    def _action(self, spec, action):
        try:
            with locked(f'vm-{spec["id"]}'), self._client() as client:
                container = self._container(client, spec)
                if not container:
                    if action == 'delete':
                        self._remove_network(client, spec)
                        return {'status': 'deleted'}
                    raise EngineError('Managed container no longer exists in Docker.')
                if action == 'start':
                    container.start()
                elif action == 'stop':
                    container.stop(timeout=20)
                elif action == 'force_stop':
                    if container.status == 'paused':
                        container.unpause()
                    if container.status in ('running', 'paused', 'restarting'):
                        container.kill()
                elif action == 'restart':
                    container.restart(timeout=20)
                elif action == 'delete':
                    if container.status in ('running', 'restarting', 'paused'):
                        raise EngineError('Stop the container before deleting it.')
                    container.remove(v=True)
                    self._remove_network(client, spec)
                    return {'status': 'deleted'}
                wanted = 'running' if action in ('start', 'restart') else 'stopped'
                for attempt in range(20):
                    container.reload()
                    status = 'stopped' if container.status in ('created', 'exited') else container.status
                    if status == wanted:
                        return {'status': status}
                    if status in ('dead', 'removing'):
                        break
                    # Daemon acknowledgement may precede the task's actual exit/start.
                    if attempt < 19:
                        time.sleep(0.1)
                raise UncertainError(f'Docker accepted {action}, but its observed state is {status}, not {wanted}. Inspect/reconcile before retrying.')
        except DockerException as exc:
            if not (isinstance(exc, APIError) and exc.status_code and exc.status_code < 500):
                raise UncertainError(f'Docker disconnected during {action}. Actual state must be inspected before retrying.') from exc
            raise EngineError(f'Docker {action} failed: {str(exc)[:1000]}') from exc

    def start(self, spec, **_):
        return self._action(spec, 'start')

    def stop(self, spec, **_):
        return self._action(spec, 'stop')

    def force_stop(self, spec, **_):
        return self._action(spec, 'force_stop')

    def restart(self, spec, **_):
        return self._action(spec, 'restart')

    def delete(self, spec, **_):
        return self._action(spec, 'delete')

    def resize(self, spec, disk_gb=None, **_):
        raise EngineError('Docker root filesystem resizing is not supported by this engine. Recreate from a verified storage plan instead.')

    def metrics(self, spec):
        try:
            with self._client(timeout=4) as client:
                container = self._container(client, spec)
                if not container:
                    return {'status': 'missing', 'usage': {}}
                inspected = client.api.inspect_container(container.id, size=True)
                usage = {'disk_actual_bytes': inspected.get('SizeRw'), 'process_rss_mb': 0, 'process_cpu_percent': 0}
                if container.status == 'running':
                    stats = container.stats(stream=False, one_shot=True)
                    mem = stats.get('memory_stats', {})
                    inactive = mem.get('stats', {}).get('inactive_file', 0)
                    usage['process_rss_mb'] = round(max(0, mem.get('usage', 0) - inactive) / 2**20, 2)
                    cpu, prev = stats.get('cpu_stats', {}), stats.get('precpu_stats', {})
                    usage['process_cpu_percent'] = _cpu_percent(container.id, cpu, prev)
                state = 'running' if container.status == 'running' else ('stopped' if container.status in ('created', 'exited') else container.status)
                return {'status': state, 'usage': usage, 'storage_enforced': spec.get('runtime', {}).get('storage_enforced', False)}
        except DockerException as exc:
            raise EngineError('Docker metrics unavailable; container state is unknown, not stopped.') from exc

    def console(self, spec):
        try:
            with self._client() as client:
                container = self._container(client, spec)
                if not container:
                    raise EngineError('Container is missing.')
                text = container.logs(tail=200).decode(errors='replace')
                return text or 'No container log output. Use a diagnostic command below to inspect this OS container.'
        except DockerException as exc:
            raise EngineError('Docker logs are currently unavailable.') from exc

    def console_input(self, spec, command):
        if not isinstance(command, str) or command not in COMMANDS:
            raise EngineError('Choose one of the allowed container diagnostics. Arbitrary host commands are never executed.')
        try:
            with self._client() as client:
                container = self._container(client, spec)
                if not container or container.status != 'running':
                    raise EngineError('Start the container before running diagnostics.')
                result = container.exec_run(COMMANDS[command], user='1000:1000', privileged=False, demux=False)
                return {'output': result.output[:32768].decode(errors='replace'), 'exit_code': result.exit_code}
        except DockerException as exc:
            raise EngineError(f'Container diagnostic failed: {str(exc)[:500]}') from exc

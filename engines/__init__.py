class EngineError(RuntimeError):
    """A controlled provisioning failure, safe to show to the authenticated owner."""


class UncertainError(EngineError):
    """Remote operation may still be running. Never automatically retry destructively."""


def engine_for(kind, node=None):
    if node:
        from .node_engine import NodeEngine
        return NodeEngine(node)
    if kind == 'qemu':
        from .qemu_engine import QemuEngine
        return QemuEngine()
    if kind == 'docker':
        from .docker_engine import DockerEngine
        return DockerEngine()
    raise EngineError('Unsupported provisioning engine.')

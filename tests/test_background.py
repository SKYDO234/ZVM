"""Real worker-thread startup/leader lock/drain checks, never fake resources."""
import time
from services.background import stop_background
from services.provisioning import start_worker
from services.node_worker import start_agent_worker


def test_panel_background_workers_are_idempotent_and_drain_without_leaks(app):
    worker=start_worker(app)
    assert worker is start_worker(app) and worker.is_alive()
    assert stop_background(app,5)
    assert not worker.is_alive()
    restarted=start_worker(app)
    assert restarted is not worker and restarted.is_alive()
    assert stop_background(app,5)
    assert all(not row['thread'].is_alive() for row in app.extensions['skvm_background'].values())


def test_agent_workers_stop_the_real_polling_and_maintenance_threads(app):
    worker=start_agent_worker(app)
    assert worker is start_agent_worker(app)
    deadline=time.monotonic()+2
    while 'skvm-maintenance' not in app.extensions['skvm_background'] and time.monotonic()<deadline:time.sleep(.01)
    assert stop_background(app,5)
    assert not worker.is_alive()


def test_test_mode_does_not_start_any_background_consumer(app):
    app.config['TEST_MODE']=True
    assert start_worker(app) is None and start_agent_worker(app) is None
    assert not app.extensions.get('skvm_background')

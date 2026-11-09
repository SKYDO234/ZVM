"""Process-local worker lifecycle; guest mutations still use persistent file locks.

Stopping drains the current job; it never kills guests or retries operations.
The same application can be started/stopped safely by WSGI hooks and test hosts.
"""
import logging
import threading
import time

_registry_lock=threading.Lock()


def start_background(app,name,target):
    with _registry_lock:
        if app.extensions.get('skvm_background_stopping'):return None
        registry=app.extensions.setdefault('skvm_background',{})
        previous=registry.get(name)
        if previous and previous['thread'].is_alive():return previous['thread']
        stop=threading.Event()
        thread=threading.Thread(target=target,args=(app,stop),daemon=True,name=name)
        registry[name]={'thread':thread,'stop':stop}
        thread.start()
        return thread


def stop_background(app,timeout=10):
    """Request a drain, then wait boundedly. False means an active job is not done."""
    with _registry_lock:
        app.extensions['skvm_background_stopping']=True
        entries=list(app.extensions.get('skvm_background',{}).values())
    for entry in entries:entry['stop'].set()
    deadline=time.monotonic()+timeout
    for entry in entries:
        if entry['thread'] is not threading.current_thread():
            entry['thread'].join(max(0,deadline-time.monotonic()))
    stopped=all(not entry['thread'].is_alive() for entry in entries)
    if stopped:
        with _registry_lock:app.extensions['skvm_background_stopping']=False
    return stopped


def run_elected(app, name, stop_event, consume):
    """Remain a standby, and recover after a leader/startup failure.

    A file lock, not a heartbeat/age heuristic, grants exclusive consumption.
    Losing the election never resets work or disables the standby permanently.
    """
    from extensions import db
    from services.security import locked
    with app.app_context():
        while not stop_event.is_set():
            try:
                with locked(name, blocking=False):
                    consume(stop_event)
            except BlockingIOError:
                pass
            except Exception:
                logging.exception('Queue consumer %s stopped unexpectedly; retrying election', name)
            finally:
                db.session.remove()
            stop_event.wait(.25)

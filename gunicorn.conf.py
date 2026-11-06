bind = '0.0.0.0:5555'
workers = 2
threads = 4
timeout = 60
accesslog = '-'


def post_worker_init(worker):
    import os
    if os.getenv('SKVM_START_WORKER', '1') == '1':
        from services.provisioning import start_worker
        start_worker(worker.wsgi)

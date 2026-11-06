import os
from config import ROOT  # Loads .env without executing it as shell code.

chdir = str(ROOT)
bind = f"{os.getenv('SKVM_HOST', '0.0.0.0')}:{int(os.getenv('SKVM_PORT', '31120'))}"
workers = 2
threads = 4
timeout = 60
accesslog = '-'


def post_worker_init(worker):
    import os
    if os.getenv('SKVM_START_WORKER', '1') == '1':
        from services.provisioning import start_worker
        start_worker(worker.wsgi)

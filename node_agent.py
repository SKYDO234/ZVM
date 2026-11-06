#!/usr/bin/env python3
"""Run on an external Linux node, behind a validating HTTPS reverse proxy."""
import os
import sys
from pathlib import Path
if __name__ == '__main__' and sys.prefix == sys.base_prefix and (Path(__file__).parent / '.venv/bin/python').exists():
    interpreter = str(Path(__file__).parent / '.venv/bin/python')
    os.execv(interpreter, [interpreter, *sys.argv])
from skvm import create_app


def create_agent(start_worker=True):
    return create_app({'NODE_AGENT': True, 'START_WORKER': start_worker})


if __name__ == '__main__':
    app = create_agent()
    # Private loopback only; use an HTTPS reverse proxy on port 443. Never forward this raw port publicly.
    app.run(host='127.0.0.1', port=int(os.getenv('SKVM_AGENT_PORT', '5556')), debug=False, use_reloader=False, threaded=True)

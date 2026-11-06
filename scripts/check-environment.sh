#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
PYTHON=python3
if [[ -x .venv/bin/python ]]; then PYTHON=.venv/bin/python; fi
"$PYTHON" skvm.py check-environment
printf '\nNo VM was created by this check. Missing engines remain unavailable in the dashboard.\n'

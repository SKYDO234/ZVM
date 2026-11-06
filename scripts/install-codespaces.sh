#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
echo 'SKVM: installing Python dependencies and QEMU userspace tools (no systemd/KVM required).'
if command -v apt-get >/dev/null; then
  if [[ $(id -u) -eq 0 ]]; then SUDO=(); elif command -v sudo >/dev/null && sudo -n true 2>/dev/null; then SUDO=(sudo -n); else SUDO=(false); fi
  if ! "${SUDO[@]}" apt-get update || ! "${SUDO[@]}" apt-get install -y --no-install-recommends python3-venv qemu-system-x86 qemu-utils cloud-image-utils genisoimage openssl; then
    echo 'WARNING: apt dependency installation failed or sudo is unavailable. The panel still works; local QEMU will show the exact missing capabilities. Use an external node if necessary.' >&2
  fi
else
  echo 'WARNING: install QEMU, qemu-img, cloud-localds and a Python venv using your distro package manager.' >&2
fi
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python skvm.py init-db
bash scripts/check-environment.sh
echo 'Start: python skvm.py  |  Forward private port 5555 in Codespaces.'

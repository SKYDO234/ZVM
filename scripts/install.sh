#!/usr/bin/env bash
# Compatibility alias: root install.sh installs AND hosts the panel by default.
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
exec bash "$ROOT/install.sh" "$@"

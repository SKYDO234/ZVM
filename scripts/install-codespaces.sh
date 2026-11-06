#!/usr/bin/env bash
# Legacy setup-only entry point; the root installer owns all installation logic.
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
exec bash "$ROOT/install.sh" --no-start "$@"

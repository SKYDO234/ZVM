#!/usr/bin/env bash
# Codespaces / Debian / Ubuntu. Installs real runtimes; never simulates an engine.
set -Eeuo pipefail
umask 077
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
MODE=foreground
SKIP_SYSTEM=0
PORT_OVERRIDE=''
usage() {
  cat <<'EOF'
Usage: bash install.sh [--no-start | --background] [--skip-system] [--port PORT]
  (default)       Install prerequisites/assets and serve on 0.0.0.0:31120 in foreground.
  --background    Install and start managed Gunicorn in the background (no systemd).
  --no-start      Install/build/initialize only (for CI and devcontainer setup).
  --skip-system   Skip apt/Node installation; require Python 3.11+, Node 22+ and npm.
  --port PORT     Override SKVM_PORT/.env for this launch (default port is 31120).

First NEW empty panel only: admin / admin123. Login opens Overview; change the initial password in Profile.
Existing accounts/data are never reset. Keep Codespaces port visibility Private.
Set SKVM_BOOTSTRAP_ADMIN=0 before installation to disable default-account creation.
Stop background panel: .venv/bin/python scripts/serve-panel.py --stop
EOF
}
while (($#)); do
  case "$1" in
    --no-start) MODE=none; shift ;;
    --background) MODE=background; shift ;;
    --skip-system) SKIP_SYSTEM=1; shift ;;
    --port)
      if (($# < 2)) || [[ ! "$2" =~ ^[0-9]+$ ]] || ((${#2} > 5)) || ((10#$2 < 1 || 10#$2 > 65535)); then
        echo 'ERROR: --port requires an integer from 1 to 65535.' >&2; exit 2
      fi
      PORT_OVERRIDE="$((10#$2))"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done
trap 'printf "\nInstallation failed at line %s. Existing accounts, instances and secrets were not reset.\n" "$LINENO" >&2' ERR

node_ready() {
  command -v node >/dev/null && command -v npm >/dev/null &&
    node -e 'if (Number(process.versions.node.split(".")[0]) < 22) process.exit(1)' >/dev/null 2>&1
}
install_node() {
  # Existing supported LTS is reused. CI may explicitly exercise the fresh install.
  if [[ "${SKVM_INSTALL_NODE:-0}" != 1 ]] && node_ready; then return; fi
  local arch sums archive digest work target
  case "$(uname -m)" in x86_64) arch=x64 ;; aarch64|arm64) arch=arm64 ;;
    *) echo 'ERROR: Automatic Node installation supports Linux x64/arm64 only.' >&2; exit 1 ;;
  esac
  target="$ROOT/.local/node"
  if [[ "${SKVM_INSTALL_NODE:-0}" != 1 && -x "$target/bin/node" && -x "$target/bin/npm" ]]; then
    export PATH="$target/bin:$PATH"
    if node_ready; then return; fi
  fi
  [[ ! -L "$ROOT/.local" ]] || { echo 'ERROR: Refusing a symlink at .local.' >&2; exit 1; }
  mkdir -p "$ROOT/.local"
  work="$(mktemp -d "$ROOT/.local/.node-install.XXXXXX")"
  # Intentionally no curl|bash, shell-sourced .env, TLS bypass or unverified archive.
  echo 'Installing Node.js 24 LTS from the official HTTPS distribution with SHA-256 verification...'
  curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 --max-time 120 \
    https://nodejs.org/dist/latest-v24.x/SHASUMS256.txt --output "$work/SHASUMS256.txt"
  read -r digest archive < <(python3 - "$work/SHASUMS256.txt" "$arch" <<'PY'
import pathlib, re, sys
pattern = re.compile(r'node-v24\.[0-9]+\.[0-9]+-linux-' + re.escape(sys.argv[2]) + r'\.tar\.xz')
items = [line.split() for line in pathlib.Path(sys.argv[1]).read_text().splitlines()]
items = [item for item in items if len(item) == 2 and re.fullmatch('[a-f0-9]{64}', item[0]) and pattern.fullmatch(item[1])]
if len(items) != 1:
    raise SystemExit('The official Node manifest did not contain exactly one supported release.')
print(*items[0])
PY
  )
  curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 --max-time 600 \
    "https://nodejs.org/dist/latest-v24.x/$archive" --output "$work/$archive"
  (cd "$work" && printf '%s  %s\n' "$digest" "$archive" | sha256sum --check --strict)
  mkdir "$work/runtime"
  tar --extract --xz --file "$work/$archive" --directory "$work/runtime" --strip-components=1 --no-same-owner --no-same-permissions
  "$work/runtime/bin/node" --version
  # Never recursively remove an arbitrary existing installation or follow a symlink.
  if [[ -L "$target" ]]; then echo 'ERROR: Refusing a symlink at .local/node.' >&2; exit 1; fi
  if [[ -e "$target" ]]; then
    [[ -f "$target/.skvm-managed-runtime" ]] || { echo 'ERROR: Existing .local/node is not installer-owned; it was not replaced.' >&2; exit 1; }
    mv -- "$target" "$work/previous-runtime"
  fi
  touch "$work/runtime/.skvm-managed-runtime"
  mv -- "$work/runtime" "$target"
  rm -rf -- "$work"
  export PATH="$target/bin:$PATH"
  node_ready || { echo 'ERROR: Node/npm installation did not pass the runtime check.' >&2; exit 1; }
  echo "Local Node installed in $target (reused by subsequent installs)."
}

if (( ! SKIP_SYSTEM )); then
  [[ "$(uname -s)" == Linux ]] || { echo 'ERROR: This installer targets Linux Codespaces/Debian/Ubuntu.' >&2; exit 1; }
  command -v apt-get >/dev/null || { echo 'ERROR: apt-get is required, or preinstall prerequisites and use --skip-system.' >&2; exit 1; }
  SUDO=()
  if (( EUID != 0 )); then
    command -v sudo >/dev/null || { echo 'ERROR: sudo is required for apt; or preinstall packages and use --skip-system.' >&2; exit 1; }
    sudo -n true || { echo 'ERROR: Passwordless sudo is required in Codespaces; no password is collected.' >&2; exit 1; }
    SUDO=(sudo -n)
  fi
  # No explicit service/systemd commands; an existing Docker socket/daemon is preserved.
  APT_OPTS=(-o Acquire::Retries=2 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o Dpkg::Use-Pty=0)
  "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive apt-get "${APT_OPTS[@]}" update
  "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive apt-get "${APT_OPTS[@]}" install -y --no-install-recommends \
    ca-certificates curl xz-utils python3 python3-venv python3-pip build-essential libffi-dev libssl-dev \
    qemu-system-x86 qemu-utils cloud-image-utils openssh-client ubuntu-cloudimage-keyring gpgv \
    util-linux iproute2
  # Avoid conflicting with a preinstalled Docker CE CLI/daemon in Codespaces.
  # No privileged DinD, user/group/socket chmod, or daemon startup is attempted.
  if ! command -v docker >/dev/null 2>&1; then
    "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive apt-get "${APT_OPTS[@]}" install -y --no-install-recommends docker.io
  fi
  install_node
fi
command -v python3 >/dev/null || { echo 'ERROR: Python 3 is required.' >&2; exit 1; }
python3 -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11 or newer is required"'
node_ready || { echo 'ERROR: Node 22+ and npm are required. Omit --skip-system to install Node automatically.' >&2; exit 1; }
printf 'Using Node %s, npm %s and %s\n' "$(node --version)" "$(npm --version)" "$(python3 --version)"
python3 -m venv "$ROOT/.venv"
"$ROOT/.venv/bin/python" -m pip install --upgrade pip
"$ROOT/.venv/bin/python" -m pip install -r "$ROOT/requirements.txt"
npm ci --include=dev --no-audit --no-fund
npm run build:assets
[[ -s static/css/tailwind.css && -s static/css/app.css && -s static/vendor/lucide.min.js && -s static/vendor/chart.umd.js && -s static/fonts/inter-latin-variable.woff2 && -s static/vendor/xterm.js && -s static/vendor/xterm.css && -s static/vendor/xterm-addon-fit.js && -s static/vendor/xterm-addon-web-links.js && -s static/fonts/jetbrains-mono-latin-variable.woff2 ]] || { echo 'ERROR: Frontend assets were not built.' >&2; exit 1; }

# Never source .env as shell. Python's dotenv loader reads it as data and preserves it.
if [[ ! -e .env ]]; then
  python3 - <<'PY'
import os
from pathlib import Path
content = Path('.env.example').read_text()
if os.getenv('CODESPACES') == 'true':
    content = content.replace('SKVM_COOKIE_SECURE=0', 'SKVM_COOKIE_SECURE=1')
try:
    with open('.env', 'x') as handle:
        handle.write(content)
except FileExistsError:
    pass  # Another installer won; preserve its configuration.
PY
fi
[[ ! -L .env ]] || { echo 'ERROR: Refusing an .env symlink; inspect the configuration.' >&2; exit 1; }
chmod 600 .env
if [[ -n "$PORT_OVERRIDE" ]]; then export SKVM_PORT="$PORT_OVERRIDE"; fi
# Resolve .env settings through exactly the same configuration as the real app.
resolved_port="$(.venv/bin/python - <<'PY'
import os
from config import configuration
configuration()
port = os.getenv('SKVM_PORT', '31120')
if not port.isascii() or not port.isdecimal() or not 1 <= int(port) <= 65535:
    raise SystemExit('SKVM_PORT must be an integer between 1 and 65535.')
print(int(port))
PY
)"
export SKVM_PORT="$resolved_port"
export SKVM_HOST=0.0.0.0
if [[ "${CODESPACES:-false}" == true ]]; then
  export SKVM_COOKIE_SECURE=1
  # A preexisting public forwarded port must not publish a known initial password.
  if command -v gh >/dev/null 2>&1 && [[ -n "${CODESPACE_NAME:-}" ]]; then
    if ! gh codespace ports visibility "$SKVM_PORT:private" --codespace "$CODESPACE_NAME"; then
      echo "WARNING: Could not update port visibility automatically. Set port $SKVM_PORT to Private in the Ports tab before using default credentials." >&2
    fi
  else
    echo "WARNING: Verify port $SKVM_PORT is Private in the Codespaces Ports tab before signing in." >&2
  fi
fi
.venv/bin/python skvm.py init-db
.venv/bin/python skvm.py bootstrap-admin
.venv/bin/python skvm.py check-environment
cat <<EOF

SKVM installed. Panel port: $SKVM_PORT (bind: 0.0.0.0).
NEW empty panel login only: admin / admin123; replace it in Profile (12+ characters). Navigation is not locked.
Existing accounts are NOT reset or replaced. Keep forwarded port visibility Private.
Data and secrets remain in this workspace. No test users, mock engines or fake guests were created.
Docker daemon / network / virtualization permissions depend on the host; see the checks above.
No privileged container, KVM, systemd, Docker socket chmod or manual daemon startup is required by this installer.
EOF
case "$MODE" in
  none) echo 'Installation complete; --no-start requested. Start later with: .venv/bin/python scripts/serve-panel.py' ;;
  background) exec .venv/bin/python scripts/serve-panel.py --background ;;
  foreground) exec .venv/bin/python scripts/serve-panel.py ;;
esac

"""Constant cloud-init dependency setup, executed INSIDE explicit internet guests.

No user input, host execution, SSHX installation or network-policy changes. Avoid
cloud-init's unconditional package-index refresh when the image is already ready.
"""
SSHX_DEPENDENCIES = r'''set -eu
ready() {
    for tool in bash curl tar timeout setsid nohup readlink tr grep head awk sed python3; do
        command -v "$tool" >/dev/null 2>&1 || return 1
    done
    timeout --version >/dev/null 2>&1 || return 1
    [ -s /etc/ssl/certs/ca-certificates.crt ] || [ -s /etc/pki/tls/certs/ca-bundle.crt ] || return 1
    python3 -c 'import os, signal; assert hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"); fd = os.pidfd_open(os.getpid()); os.close(fd)' 2>/dev/null || return 1
}
if ready; then
    printf '%s\n' 'SKVM: SSHX prerequisites already installed; no package update needed.'
    exit 0
fi
if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get -o Acquire::Retries=1 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 update
    apt-get -o Acquire::Retries=1 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 -o DPkg::Lock::Timeout=60 install -y --no-install-recommends curl ca-certificates bash tar coreutils util-linux python3
elif command -v dnf >/dev/null 2>&1; then
    dnf --setopt=timeout=20 --setopt=retries=1 install -y curl ca-certificates bash tar coreutils util-linux python3
else
    printf '%s\n' 'SKVM: install SSHX prerequisites through the native guest package manager.' >&2
    exit 1
fi
ready || { printf '%s\n' 'SKVM: SSHX prerequisites or kernel pidfds remain unavailable.' >&2; exit 1; }
printf '%s\n' 'SKVM: SSHX prerequisites installed.'
'''

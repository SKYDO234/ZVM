"""Fixed guest-only SSHX operations and strict validation of the real CLI output.

The management key never enters a VM manifest or the guest. Links are returned
only to the controller, which encrypts them; neither keys nor output are logged.
"""
import base64
from datetime import datetime, timedelta
import re
from urllib.parse import urlsplit

from flask import current_app

from engines import EngineError, UncertainError
from engines.node_engine import NodeEngine
from extensions import db
from models import GuestAccess, SSHXSession
from models.user import utcnow
from services.guest_ssh import FINGERPRINT, GuestSSH, credentials, validate_spec
from services.guest_process_control import SSHX_PROCESS_CONTROL
from services.security import decrypt, encrypt, valid_uuid

MODES = {'probe', 'verify', 'enroll', 'generate', 'stop', 'inspect', 'inspect_stop'}
ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')


def valid_link(value):
    if not isinstance(value, str) or not 20 <= len(value) <= 400 or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise EngineError('SSHX returned an invalid access link; it was not displayed.')
    try:
        url = urlsplit(value)
        if (url.scheme != 'https' or url.netloc != 'sshx.io' or url.query
                or not re.fullmatch(r'/s/[A-Za-z0-9_-]{4,128}', url.path)
                or not re.fullmatch(r'[A-Za-z0-9]{10,128}', url.fragment)):
            raise ValueError
    except ValueError:
        raise EngineError('SSHX returned an unexpected access-link origin or format; it was not displayed.') from None
    return value


def result(data, mode):
    """Validate local AND remote results, never trust arbitrary agent JSON."""
    if not isinstance(data, dict) or set(data) - {'fingerprint', 'state', 'link', 'seconds'}:
        raise UncertainError('Invalid SSHX operation response. Its guest outcome must be inspected.')
    fp = data.get('fingerprint')
    if not isinstance(fp, str) or not FINGERPRINT.fullmatch(fp):
        raise UncertainError('The SSHX operation returned no valid guest fingerprint.')
    if mode in ('generate', 'inspect'):
        if data.get('state') != 'generated' or type(data.get('seconds')) is not int or not 60 <= data['seconds'] <= 3600:
            raise UncertainError('The SSHX operation did not prove a live bounded client.')
        valid_link(data.get('link'))
    elif data.get('state') != {'probe': 'probed', 'verify': 'verified', 'enroll': 'enrolled', 'stop': 'stopped', 'inspect_stop': 'stopped'}[mode] or 'link' in data:
        raise UncertainError('Unexpected guest SSH operation state.')
    return data


def enrollment_script(public_key):
    # Only a generated/validated public key is encoded into this fixed script.
    if not isinstance(public_key, str) or not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/]{68} skvm-managed', public_key):
        raise EngineError('Invalid management public key.')
    encoded = base64.b64encode((public_key + '\n').encode()).decode()
    return r'''# SKVM_FIXED_ENROLLMENT
set -eu
umask 077
fail() { printf 'SKVM_ERROR:ENROLL\n'; exit 1; }
[ -n "$HOME" ] && [ ! -L "$HOME/.ssh" ] || fail
mkdir -p "$HOME/.ssh" || fail
chmod 700 "$HOME/.ssh" || fail
file="$HOME/.ssh/authorized_keys"
[ ! -L "$file" ] || fail
[ ! -e "$file" ] || [ -f "$file" ] || fail
touch "$file" || fail
chmod 600 "$file" || fail
key=$(printf '%s' 'ENCODED_KEY' | base64 -d) || fail
# Append only: preserve every owner key and password. A newline prevents joining
# a pre-existing final line. The public key is not a password/private credential.
grep -qxF "$key" "$file" || printf '\n%s\n' "$key" >> "$file"
printf 'SKVM_ENROLLED\n'
'''.replace('ENCODED_KEY', encoded)


def guest_script(spec, mode, operation_id, seconds):
    valid_uuid(spec['id'])
    valid_uuid(operation_id)
    if mode not in ('generate', 'stop', 'inspect', 'inspect_stop') or type(seconds) is not int or not 60 <= seconds <= 3600:
        raise EngineError('Invalid fixed SSHX operation.')
    # UUIDs, an enum and a bounded integer are the ONLY interpolated values.
    script = r'''# SKVM_FIXED_SSHX
set -eu
umask 077
mode='MODE_VALUE'
vm='VM_VALUE'
op='OP_VALUE'
seconds='SECONDS_VALUE'
fail() { printf 'SKVM_ERROR:%s\n' "$1"; exit 1; }
for tool in timeout readlink tr grep head awk sed; do
    command -v "$tool" >/dev/null 2>&1 || fail TOOLS
done
if [ "$mode" = generate ]; then
    for tool in bash curl tar setsid nohup; do command -v "$tool" >/dev/null 2>&1 || fail TOOLS; done
fi
state="$HOME/.local/state/skvm-sshx-$vm"
[ ! -L "$state" ] || fail PROCESS
if [ "$mode" = inspect ] || [ "$mode" = inspect_stop ]; then
    [ -d "$state" ] || fail NOT_FOUND
else
    mkdir -p "$state"
    chmod 700 "$state"
fi
for file in pid operation seconds output stopped; do [ ! -L "$state/$file" ] || fail PROCESS; done
pid=$(cat "$state/pid" 2>/dev/null || true)
oldop=$(cat "$state/operation" 2>/dev/null || true)
verified() {
    case "$pid" in ''|*[!0-9]*) return 1;; esac
    [ "${#pid}" -le 10 ] && [ "$pid" -gt 1 ] && kill -0 "$pid" 2>/dev/null || return 1
    [ "$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null || true)" != Z ] || return 1
    [ "$(readlink "/proc/$pid/exe" 2>/dev/null)" = "$(readlink -f "$(command -v timeout)")" ] || return 2
    tr '\000' '\n' < "/proc/$pid/environ" | grep -qxF "SKVM_SSHX_INSTANCE=$vm" || return 2
    tr '\000' '\n' < "/proc/$pid/environ" | grep -qxF "SKVM_SSHX_OPERATION=$oldop" || return 2
    return 0
}
# Recover the exact tagged timeout if the SSH request/guest shell died between
# launch and writing its PID. Never signal an unrelated or ambiguous process.
if ! verified; then
    found=''
    for entry in /proc/[0-9]*/environ; do
        [ -r "$entry" ] || continue
        candidate=${entry%/environ}; candidate=${candidate##*/}
        [ "$(readlink "/proc/$candidate/exe" 2>/dev/null)" = "$(readlink -f "$(command -v timeout)")" ] || continue
        tr '\000' '\n' 2>/dev/null < "$entry" | grep -qxF "SKVM_SSHX_INSTANCE=$vm" || continue
        [ -z "$found" ] || fail PROCESS
        found=$candidate
    done
    if [ -n "$found" ]; then
        pid=$found
        oldop=$(tr '\000' '\n' < "/proc/$pid/environ" | sed -n 's/^SKVM_SSHX_OPERATION=//p')
    else
        pid=''
    fi
fi
alive=0
verified && alive=1 || { code=$?; [ "$code" -eq 1 ] || fail PROCESS; }
control_clients() {
    command -v python3 >/dev/null 2>&1 || fail PIDFD
    if python3 - "$1" "$vm" "$(readlink -f "$(command -v timeout)")" "$(command -v sshx 2>/dev/null || true)" <<'SKVM_PROCESS_CONTROL'
SSHX_CONTROL_VALUE
SKVM_PROCESS_CONTROL
    then return 0
    else
        code=$?
        [ "$code" -ne 2 ] || fail PIDFD
        fail PROCESS
    fi
}
stop_client() {
    # Kernel pidfds bind identity BEFORE proof and signaling. This also finds
    # tagged orphan sshx clients if timeout or its saved PID disappeared.
    control_clients stop
    rm -f "$state/pid" "$state/output" "$state/operation" "$state/seconds"
}
if [ "$mode" = stop ]; then
    stop_client
    printf '%s\n' "$op" > "$state/stopped"
    printf 'SKVM_STOPPED\n'
    exit 0
fi
if [ "$mode" = inspect_stop ]; then
    control_clients check
    [ "$alive" -eq 0 ] && [ "$(cat "$state/stopped" 2>/dev/null || true)" = "$op" ] || fail NOT_FOUND
    printf 'SKVM_STOPPED\n'
    exit 0
fi
if [ "$mode" = inspect ]; then
    [ "$alive" -eq 1 ] && [ "$oldop" = "$op" ] || fail NOT_FOUND
elif [ "$alive" -eq 0 ] || [ "$oldop" != "$op" ]; then
    stop_client
    # This is executed INSIDE the authenticated, verified VM, never on the host.
    timeout --signal=TERM --kill-after=5 90 bash -o pipefail -c 'curl -sSf https://sshx.io/get | sh' >/dev/null 2>&1 || fail INSTALL
    command -v sshx >/dev/null 2>&1 || fail INSTALL
    printf '%s\n' "$op" > "$state/operation"
    printf '%s\n' "$seconds" > "$state/seconds"
    # A detached, bounded guest process survives the panel request. timeout
    # forwards SIGINT to sshx, invoking its graceful server-session close path.
    nohup setsid env SKVM_SSHX_INSTANCE="$vm" SKVM_SSHX_OPERATION="$op" SSHX_SERVER=https://sshx.io NO_COLOR=1 RUST_LOG=error timeout --signal=INT --kill-after=5 "$seconds" sshx > "$state/output" 2>&1 < /dev/null &
    pid=$!
    printf '%s\n' "$pid" > "$state/pid"
    oldop=$op
fi
tries=0
while :; do
    if verified && grep -q 'https://sshx.io/s/' "$state/output" 2>/dev/null; then
        printf 'SKVM_RUNNING\nSKVM_SECONDS:'
        head -c 5 "$state/seconds"
        printf '\n'
        head -c 32000 "$state/output"
        exit 0
    fi
    tries=$((tries + 1)); [ "$tries" -lt 100 ] || break
    sleep 0.2
done
# Failed generation must not leave an unreported usable link running.
if verified; then alive=1; stop_client; fi
fail NO_LINK
'''
    return (script.replace('SSHX_CONTROL_VALUE', SSHX_PROCESS_CONTROL).replace('MODE_VALUE', mode).replace('VM_VALUE', spec['id'])
            .replace('OP_VALUE', operation_id).replace('SECONDS_VALUE', str(seconds)))


def local(spec, mode, *, private=None, host_fingerprint=None, operation_id=None,
          auth=None, public_key=None, seconds=None, check=lambda: None):
    validate_spec(spec)
    if mode not in MODES:
        raise EngineError('Unsupported guest SSH operation.')
    seconds = current_app.config['SSHX_MAX_SECONDS'] if seconds is None else seconds
    if mode == 'generate' and spec.get('runtime', {}).get('network_restricted', True):
        raise EngineError('Guest internet is restricted. An administrator must explicitly enable outbound internet while this VM is stopped.')
    if mode != 'probe' and host_fingerprint is None and mode == 'enroll':
        raise EngineError('Verify the guest fingerprint before sending enrollment credentials.')
    with GuestSSH(spec, host_fingerprint, check) as ssh:
        if mode == 'probe':
            return {'fingerprint': ssh.fingerprint, 'state': 'probed'}
        if mode == 'enroll':
            ssh.authenticate(credentials(auth))
            output = ssh.execute(enrollment_script(public_key), seconds=15)
            if 'SKVM_ENROLLED' not in output:
                raise EngineError('The guest did not confirm management-key enrollment.')
        else:
            if not isinstance(private, str):
                raise EngineError('This VM needs one-time management-key enrollment first.')
            ssh.authenticate({'method': 'key', 'private_key': private})
            if mode == 'verify':
                return {'fingerprint': ssh.fingerprint, 'state': 'verified'}
            output = ssh.execute(guest_script(spec, mode, operation_id, seconds), seconds=130 if mode == 'generate' else 25)
        data = {'fingerprint': ssh.fingerprint,
                'state': {'enroll': 'enrolled', 'stop': 'stopped', 'inspect_stop': 'stopped', 'generate': 'generated', 'inspect': 'generated'}[mode]}
        if mode in ('stop', 'inspect_stop') and 'SKVM_STOPPED' not in output:
            raise UncertainError('The guest did not prove the SSHX client stopped. The link was not declared revoked.')
        if mode in ('generate', 'inspect'):
            urls = re.findall(r'https://[^\s\x1b<>"\']{1,480}', ANSI.sub('', output))
            links = []
            for value in urls:
                try:
                    links.append(valid_link(value))
                except EngineError:
                    continue
            ttl = re.search(r'^SKVM_SECONDS:(\d+)\s*$', output, re.M)
            if 'SKVM_RUNNING' not in output or len(set(links)) != 1 or ttl is None:
                raise UncertainError('SSHX output did not contain one verified-origin access link and live-process proof. Inspect before retrying.')
            data.update(link=links[0], seconds=int(ttl[1]))
        return result(data, mode)


def dispatch(spec, mode, node=None, check=lambda: None, **kwargs):
    validate_spec(spec)
    check()
    if node:
        data = NodeEngine(node).guest_ssh(spec, mode, **kwargs)
        try:
            check()
        except EngineError:
            if mode in ('generate', 'stop', 'enroll'):
                raise UncertainError('Panel authority changed after a remote guest mutation. Inspect its outcome before retrying.') from None
            raise
        result(data, mode)
        expected = kwargs.get('host_fingerprint')
        if expected is not None and data['fingerprint'] != expected:
            raise UncertainError('The external node returned a different guest fingerprint. No new pin or link was accepted.')
        return data
    return result(local(spec, mode, check=check, **kwargs), mode)


def stored_access(ident):
    row = db.session.get(GuestAccess, ident)
    if not row:
        raise EngineError('This existing VM needs one-time SSHX enrollment. Its guest credentials will not be reset.')
    data = decrypt(row.private_key_encrypted)
    return data['private_key'], row.host_fingerprint


def retire(ident):
    """Only call after a proven guest stop/delete/reinstall, never as tunnel revocation."""
    row = db.session.get(SSHXSession, ident)
    if row:
        row.state, row.link_encrypted = 'stopped', None


def save_session(vps, operation_id, data, started_at=None):
    result(data, 'generate')
    row = db.session.get(SSHXSession, vps.id)
    if row is None:
        row = SSHXSession(instance_id=vps.id)
        db.session.add(row)
    row.owner_id, row.operation_id = vps.owner_id, operation_id
    row.link_encrypted, row.state = encrypt(data['link']), 'generated'
    issued = datetime.fromisoformat(started_at) if started_at else utcnow()
    row.verified_at, row.expires_at = utcnow(), issued + timedelta(seconds=data['seconds'])
    access = db.session.get(GuestAccess, vps.id)
    if access:
        access.host_fingerprint = data['fingerprint']


def visible_session(vps):
    row = db.session.get(SSHXSession, vps.id)
    if not row or row.owner_id != vps.owner_id or row.state != 'generated' or row.expires_at <= utcnow():
        return None
    return {'link': valid_link(decrypt(row.link_encrypted)), 'verified_at': row.verified_at, 'expires_at': row.expires_at}

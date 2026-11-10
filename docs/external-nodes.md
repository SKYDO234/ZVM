# External Linux nodes: deployment and API

The management panel and guests can run on different machines. The Codespace is the **control-plane host**; the node's **host capacity** and each **instance's configured allocations/actual usage** remain distinct.

## 1. Prepare the node

Use a trusted x86-64 Linux host with sufficient RAM and disk. Install this source and:

```bash
bash install.sh --no-start
cp .env.example .env
chmod 600 .env
```

In the node's `.env`, set persistent **absolute** `SKVM_DATA_DIR` and `SKVM_DATABASE_URL` paths. The default workspace-local paths are fine if the checkout persists. Do not share a node database/data directory with the Codespace panel. Package installation may require an operator; runtime does not require root, systemd, KVM or a privileged guest container.

Generate a token with `python -c 'import secrets; print(secrets.token_urlsafe(48))'`. Put it in the node's `.env` as `SKVM_NODE_TOKEN`. Use at least 32 URL-safe random characters; there is no default. Transfer it privately to the panel administrator, not to a Git-tracked config or URL query string.

Verify engines and image candidates **on the node**:

```bash
python skvm.py check-environment
python skvm.py verify-images
python scripts/qemu-smoke-test.py
# Optional update/pin, using a genuinely trusted vendor SHA256:
python skvm.py configure-image --id ubuntu-24.04 --url 'https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img' --sha256 '<vendor-checksum>'
```

QEMU uses TCG by default. Docker must already be configured (rootless/delegated cgroups preferred). The same node-local `config.json` plus SQLite policy applies. Agent requests cannot supply arbitrary image URLs, commands, mounts, or QEMU flags.

## 2. Start the private agent

```bash
python node_agent.py
```

The standalone agent exposes **only** `/v1/` machine endpoints; panel registration/login/admin routes are not registered. It binds **127.0.0.1:5556**, because a raw bearer-token HTTP port must not be forwarded publicly. The persistent operation worker starts with it. For a WSGI process on the node:

```bash
.venv/bin/gunicorn --bind 127.0.0.1:5556 --workers 1 --threads 16 --timeout 180 'node_agent:create_agent()'
```

This starts the agent worker via its factory, with a workspace leader lock. A supervisor can be a container's normal process manager, tmux, or an operator-managed init system; SKVM has no dependency on systemd.

## 3. Add authenticated HTTPS

Use your existing valid TLS certificate, domain and reverse proxy. Example nginx server **after** obtaining a certificate normally (do not paste private keys into the panel):

```nginx
server {
    listen 443 ssl;
    server_name compute.example.org;
    ssl_certificate /etc/letsencrypt/live/compute.example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/compute.example.org/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 256k;
    location /v1/ {
        proxy_pass http://127.0.0.1:5556;
        proxy_set_header Host $host;
        proxy_set_header Authorization $http_authorization;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_read_timeout 180s;
        proxy_send_timeout 180s;
    }
    location / { return 404; }
}
```

For **SSHX**, update/restart both panel and agent. Updated agents advertise `sshx.protocol_version: 1`; old agents explicitly refuse managed-key provisioning/guest control rather than falling back to the panel's localhost. The controller makes verified HTTPS **POST** requests for fixed guest actions; the agent proves its own selected QEMU guest and executes inside it. **No WebSocket Upgrade configuration is used.** Secret credentials/results stay in memory over TLS, not in agent operation records or logs. Use the 180-second proxy read/send timeout above. Updated guest control caps the complete request at 170 seconds and uses a 175-second node read budget; its shared 40-second setup budget accommodates slow TCG greeting/key exchange/authentication/channel responses. Update both ends for the fixed pre-command authentication-timeout code and whitelisted stage diagnostics. [SSHX usage/security](sshx.md).

Keep 5556 firewalled/loopback-only. Restrict 443 access to the control plane/VPN where practical. For a private CA, set `SKVM_NODE_CA_BUNDLE=/secure/path/to/node-ca.pem` on the panel and restart, or install the root into its trusted Python certificate chain; **do not disable certificate verification**. The panel only allows exact HTTPS origins on port 443, rejects redirects with tokens, and checks its environment-configured allowlist. It deliberately permits allowlisted private node hostnames; OS-image downloads separately reject private network addresses.

## 4. Connect from the panel

In the Codespace `.env`:

```dotenv
SKVM_NODE_HOSTS=compute.example.org
```

Restart the panel. Admin control → External nodes → name, `https://compute.example.org`, matching token → Connect & verify. A live authenticated capabilities request must succeed before a node is registered. The token is Fernet-encrypted in panel SQLite; keep `data/.encryption-key` private. Never publish a Docker socket, a node token, port 5556, or private key material.

Create VPS now offers that node. Node **Check capacity** reports its own measured RAM/CPU/storage/inventory. Disabling a node prevents new remote operations; it does not pretend to stop its guests. Re-enable it for lifecycle recovery. To rotate a token, coordinate a maintenance window: update the node’s private `.env`, restart the agent, then use **Rotate token** beside that node in Admin control. The replacement is saved only after an authenticated capabilities check passes. Existing guests and node associations stay intact. A stale token produces authorization errors, never fallback anonymous access.

## Protocol

The capability response includes **`protocol_version: 1`**. Upgrade panel and agents together; legacy/unversioned or incompatible agents are rejected rather than treated as valid capacity or provisioning results.

All endpoints require `Authorization: Bearer <node-token>` and JSON. They never accept browser-cookie authentication; this machine-only blueprint is CSRF-exempt for that reason. All other panel mutation routes require CSRF.

| Method / path | Result |
|---|---|
| `GET /v1/capabilities` | `protocol_version: 1`, `host` known-capacity flag/reason, effective cgroup/ancestor RAM/CPU/free storage, independent `qemu`/`docker` capabilities, `sshx` protocol/availability, actual `instances` engine/state inventory, reserved SSH ports, pending provisioning count, image configuration IDs/status |
| `POST /v1/operations` | Queue validated operation; returns persistent `id`, `status` and HTTP 202 |
| `GET /v1/operations/<uuid>` | `queued/running/completed/failed/uncertain`; completed `result` or controlled `error` |
| `POST /v1/operations/<uuid>/reconcile` | Inspect an **uncertain** operation under nonblocking capacity/control locks; apply a proven result without replaying the mutation. Returns 409 for busy/incomplete/ambiguous evidence |
| `POST /v1/operations/<uuid>/close-power` | Inspect only an uncertain basic power request under nonblocking operation/capacity/control locks; prove stable owned running/stopped state, retain instance/allocation and record failed/unconfirmed—not success. Rejects storage/provisioning/SSHX, live work and ambiguous evidence. Upgrade/restart both ends. |
| `GET /v1/instances/<uuid>` | Instance `id`, exact configured `allocation`, actual engine state, process/cgroup usage and storage enforcement |
| `POST /v1/instances/<uuid>/sshx` | Stateless fixed guest actions: `probe`, `verify`, `enroll`, `generate`, `stop`, `inspect`, `inspect_stop`. Exact managed target must match. Bearer only, browser Origin rejected, sensitive response capped at 64 KiB. No arbitrary host/port/user/command fields. |

Creation schema (example describes a request, **not an actual provisioned VM**):

```json
{
  "id": "a unique UUID generated by the panel for this operation",
  "kind": "create",
  "spec": {
    "id": "a different unique UUID for the instance",
    "owner_id": 1,
    "name": "development-01",
    "engine": "qemu",
    "os_id": "ubuntu-24.04",
    "ram_mb": 1024,
    "vcpus": 1,
    "disk_gb": 10,
    "username": "ubuntu",
    "ssh_port": 22000,
    "forwards": []
  },
  "credentials": {
    "public_key": "the owner’s valid OpenSSH public key",
    "control_public_key": "the generated per-VM Ed25519 management public key"
  }
}
```

Both UUID strings above must be real canonical UUIDs; the agent rejects placeholders/non-UUIDs. The built-in client generates these IDs. Do not copy an example owner ID to target another panel's node resources; the node token identifies a trusted control plane, not an end user. User RBAC/ownership is enforced by the panel before transmission, exact runtime identity is checked again on the node, and the agent serializes capacity checks independently.

Other operation kinds: `start`, `stop`, `force_stop`, `restart`, `delete`, `resize` (additional `disk_gb`), `reinstall` (new allowed OS/credentials, QEMU only), `network` (stopped QEMU; explicit `network_restricted` boolean) and `assign` (stopped QEMU; target `owner_id`). The panel requires administrator authorization for creation/assignment/network changes and applies the enabled assignee’s plan/quotas; the node token represents the trusted control plane, not a user account. Agent-side `runtime` is always loaded from trusted local state for actions; user-provided runtime metadata is not used to select a host process/container.

The panel validates instance/operation IDs, integer allocations, finite capacity values, inventory/port shapes and allowed operation states. It strips panel-owned identity/owner/name/node fields from node metric data rather than trusting remote overrides. Authenticated responses are capped at 1 MiB; transfer/read deadlines and redirect rejection apply. Invalid JSON, mismatched completed results, transport failures and HTTP 5xx leave an operation **uncertain**, not falsely failed/successful. Stored bearer tokens are redacted from returned node errors.

Update/restart **both panel and agent** for owner lifecycle fixes. A Delete request remains **one operation ID**: the agent worker proves graceful shutdown before removing the guest/network and its metadata; it never silently Force stops. A failed/unproven stop blocks both restart and deletion, and an unproven deletion retains the agent record for reconciliation. A Start on a freshly verified running guest completes as a no-op without another RAM allocation. Missing/unreachable resources are not conflated: only an actual owned-container NotFound permits orphan-network cleanup.

Operation IDs are idempotent and bound to a digest of the validated request. The same ID with different input returns 409. The transport first checks an existing operation before submitting; polling never reissues a destructive action. Completed/failed payloads are cleared; uncertain payloads remain encrypted for investigation. Node restarts do **not** auto-replay interrupted provisioning.

## Failure, backup, and recovery boundaries

- A dropped network response after mutation may mean the operation continues on the node. The panel retains the reservation and reports **uncertain**.
- Admin job reconciliation reads a completed/failed node operation result. If it is uncertain, the panel calls the authenticated agent reconciliation endpoint, which **inspects** actual resources without repeating create/start/stop/delete/resize. A genuinely queued/running operation must be allowed to finish; busy control locks return a controlled 409.
- If the **agent itself** crashes mid-operation, it marks the operation uncertain on restart. Inspect its real labeled containers, QEMU manifests/PIDs, and any `.reinstall-backup` directory locally. Creation recovery checks real QCOW2 integrity/capacity/CIDATA seed or actual Docker isolation/limits, not a manifest/label alone. Lifecycle/delete recovery proves observed state/absence; growth recovery only synchronizes metadata after proving the target disk size. Reinstall recovery additionally requires the pending unique control-public-key seed generation, exact stopped resources and no incomplete backup. Ambiguous policy changes or partial/mismatched evidence remain uncertain and require operator inspection; there is intentionally no automatic destructive guess.
- Do not use the panel's `resolve-job --confirm-no-resource` until the node's resource really is absent and its operation is no longer running. This is a maintenance assertion, not a cleanup tool.
- Back up node SQLite, protected key files, stopped guest disks and Docker's managed persistence through appropriate daemon tooling. A full OS boot and a real external TLS deployment must be smoke-tested on your actual node. The repository includes genuine loopback HTTPS client/agent and fixed guest-SSH protocol tests (real CA/hostname verification, bearer rejection, KEX and authentication), but routes TCP to explicit test fixtures rather than a real external guest. That is not proof of your DNS, reverse proxy, network reachability or real external-node guest execution.

The former `/console` and `/webssh` machine endpoints have been removed. No browser terminal/PTY transport, token/PIN bypass or plaintext enrollment/key/link storage is retained. Stop old workers during upgrade; do not reset the database or guest storage.

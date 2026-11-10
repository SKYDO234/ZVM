# SKVM · QEMU + Docker VPS control panel

<p align="center">
  <img src="docs/assets/zk-studios-logo.png" alt="ZK STUDIOS logo" width="280">
</p>

**This panel is made by ZK STUDIOS.**

A workspace-first Flask management panel for **real QEMU virtual machines** and **separate Docker OS containers**. Dark responsive interface, live measured charts, user accounts, quotas, audit trails, background provisioning, and an authenticated external-node agent.

**No LXC. No systemd requirement. No privileged guest containers. No required KVM. No simulated VPS records.**

**Current revision:** Admin controls have dedicated pages for Users, Instances, Plans, External nodes, OS images, Configuration, Jobs, Recovery and Audit, plus separate per-VM Network, Ownership and Suspension pages. Details/My VPS identify blocking operations instead of only displaying a generic active-job error. Conflicting retries open the authorized existing job without queueing duplicate work. Recovery inspects real outcomes, can cancel non-executing queued requests, and can close an interrupted basic power request as failed/unconfirmed only after proving current state—never by clearing live locks or storage reservations. Owner power/delete, admin-only creation/assignment and guest-only **Generate SSHX** remain intact. See [blocked-operation recovery](docs/operations.md), [SSHX security](docs/sshx.md) and [exact validation scopes/revisions](docs/testing.md).

**SSHX guest-boot fix:** QEMU **Running** is not proof that Linux/cloud-init/sshd is ready. Generate now safely retries proven pre-command connection failures for up to ten minutes by default, releasing the worker between attempts. Slow guest setup now waits for real SSH completion events within a shared 40-second budget rather than repeatedly discarding valid 10/5-second handshake/channel responses. Details shows **Waiting for guest SSH**, the actual stalled stage and attempt number. Explicit host-key/credential rejection and any potentially submitted command are not automatically replayed. No VPS reset is required. [Guest SSH readiness troubleshooting](docs/sshx.md#when-generate-fails-with-cannot-establish-verified-guest-ssh).

**SSHX waiting fix:** Generate/Stop use a separate elected queue lane; standby workers keep retrying, busy guest locks do not block the consumer, and SSH command acknowledgement is bounded. Details refreshes real task progress and recovers after transient polling errors. Existing uncertain requests still require proof, not a blind reset. [Troubleshooting and upgrade steps](docs/sshx.md#when-generate-sshx-stays-queued-or-running).

## The uploaded `n.txt` is the reference

The entire 1,104-line uploaded Bash manager was read and audited before implementation. Its exact bytes are retained in [`docs/reference/n.txt`](docs/reference/n.txt). The Python engine is a conversion of its useful provisioning/lifecycle behavior—not a website that displays or executes the Bash script.

Read the [reference audit and feature mapping](docs/reference-audit.md), including the destructive resize fallback, default passwords, `source` injection, process-matching bugs, and broken extra-forward handling that were replaced.

## Quick start in GitHub Codespaces

```bash
bash install.sh
```

The **root installer** installs Python/venv/build prerequisites, QEMU/cloud-init/SSH tools and Docker packages when no Docker CLI is present; reuses Node 22+ or installs **Node 24 LTS with HTTPS + SHA-256 verification**; installs Python/npm dependencies; builds the frontend; safely initializes SQLite; and starts the real **Gunicorn panel on `0.0.0.0:31120`**. It requires Debian/Ubuntu Linux and passwordless sudo for system packages. Installation failures are reported, not silently ignored.

1. Open forwarded port **31120** from the Codespaces **Ports** tab. **Keep visibility Private.** The installer attempts to mark it Private using the existing Codespaces CLI; if that fails, check the Ports tab yourself. The devcontainer forwards 31120 and starts the installed panel on container startup.
2. On a **new, empty panel**, sign in with **username `admin` / password `admin123`**. Login opens **Admin overview** immediately and all pages/buttons remain available under normal authorization. A persistent, non-blocking reminder asks you to replace the initial password in **Profile** with a private password of **12–128 characters**. Passwords are stored as salted hashes. Reinstallation/restart **never resets the password or adds this account to an existing installation**.
3. Open **Settings** for the *actual* local engine capabilities. Missing host permissions, a Docker daemon or QEMU are not hidden. Installing binaries does not grant a Codespace Docker/cgroup/KVM privileges.
4. As an administrator, configure an available engine, select **Create VPS**, choose an **enabled owner account**, review that account’s plan/quotas and the configuration, and confirm. Watch its background job. A successful create leaves a **real stopped instance**; use **Start** to boot/run it.
5. For SSHX, explicitly allow guest outbound internet at creation (or ask an administrator to change it while stopped). On the running VM’s Details page, select **Generate SSHX**. The installer and client execute **inside that selected VM**, and the actual output URL appears there. Existing guests use one-time credential enrollment without resetting passwords or keys. Normal users sign in to **My workspace** and manage only their assigned VPS; they cannot create or assign guests.

The default install stays in the foreground; leave the terminal open. Alternatively:

```bash
bash install.sh --background        # Install, then start without systemd
bash install.sh --no-start          # Setup only (CI/devcontainer preparation)
bash install.sh --skip-system      # Already have Python 3.11+, Node 22+ and npm
bash install.sh --port 31120        # Explicit port override for this launch
# After setup, start/stop just the managed panel:
.venv/bin/python scripts/serve-panel.py --background
.venv/bin/python scripts/serve-panel.py --stop
```

Background logs are `data/logs/panel.error.log` / `panel.access.log`; the master PID is `data/panel.pid` (or your configured data directory). Repeated starts do not duplicate the server; occupied ports or unproven PIDs are refused without killing unrelated processes. Background hosting lasts only while the Codespace runs. No systemd, privileged DinD, Docker-socket chmod or automatic daemon start is used. Existing accessible Docker daemons are reused.

`python skvm.py` **still works** and automatically uses `.venv/bin/python`. Node/npm are build-time only; browser dependencies are bundled locally, without CDN requirements. A newly downloaded Node runtime lives in ignored `.local/node`; the installer reuses it (for manual npm work, add `.local/node/bin` to `PATH`). Legacy `scripts/install.sh` delegates to the root installer; `scripts/install-codespaces.sh` remains a setup-only compatibility wrapper.

### Owner power controls and deletion

Open **My VPS → Manage** or use the buttons directly on your instance card. Start is enabled for verified stopped guests; Stop and Restart reflect the observed state. Details refreshes availability from the metrics API, including changes made in another tab. Pending work disables conflicting actions, and suspended guests cannot be started/restarted. These are UI hints in addition to backend ownership, session, CSRF and worker checks—not replacements for them.

**Delete** is available to the assigned owner and administrators, including for a running or suspended VPS. Confirming it queues one operation that requests graceful shutdown, verifies the guest is stopped, then removes only that instance’s storage/resources and metadata. If shutdown fails or its outcome is unknown, deletion is aborted: **no automatic Force stop**, fake success or quota release. You may explicitly Force stop with its separate data-loss warning, then retry deletion. An unreachable node or an uncertain storage/provisioning operation still requires inspection/reconciliation; it is never bypassed by deleting a database row.

Administrator-requested power jobs are visible to the assigned owner, while audit entries retain the actual requesting administrator. Update/restart both panel and external agents for the new stop-before-delete flow. Existing accounts, guests and saved credentials are not reset.

### SSHX guest access

The panel runs the requested `curl -sSf https://sshx.io/get | sh`, then `sshx`, **inside the selected managed QEMU VM**, never on the host. New VMs receive unique encrypted management keys alongside the owner’s native authentication. Existing VMs enroll once using their current guest credential and an independently confirmed SSH host fingerprint; no reinstall/reset is required.

Only the VM owner or an administrator can generate, view, copy or stop its real output link on **VPS Details**. **The URL is a shell/sudo capability outside panel login.** Keep it private. Logout, password changes and account disablement do not revoke a copied URL: stop its verified client or the VM. Managed clients have a maximum one-hour lifetime. Docker has no injected SSH daemon and does not offer SSHX.

**Restricted outbound networking remains the default** and prevents SSHX. An administrator must explicitly acknowledge internet access per VM; QEMU user networking with restrictions disabled can also reach host/private services, so use trusted guests or an isolated node. Nothing silently relaxes global or existing policy. [Full setup, guest prerequisites, enrollment, encryption and recovery](docs/sshx.md).

**Use HTTPS** outside local development. External guests use verified-TLS, bearer-authenticated **HTTPS RPC**, not a WebSocket relay or panel-localhost fallback. Update/restart both ends; node proxies need 180-second read/send timeouts. The active Console/WebSSH pages, APIs, PTYs, transports and xterm dependencies were removed. Original uploaded references are retained unchanged only as references.

Existing installations need updated dependencies and **all old workers restarted**, not a database reset:

```bash
.venv/bin/python scripts/serve-panel.py --stop
bash install.sh --no-start
.venv/bin/python scripts/serve-panel.py --background
```

`npm ci && npm run build:assets` rebuilds the committed local frontend assets. `SKVM_SSHX_ENABLED=0` disables new guest-control operations but does **not** stop existing clients; stop clients/guests first. Preserve SQLite and the original encryption/session key files together.

### Existing installation stuck on one page

The old first-login guard redirected every link back to Profile and returned `403 password_change_required` from APIs. That guard has been removed: the initial administrator can navigate normally, use activity/metrics and submit authorized forms without a forced password-change loop. The initial-password reminder stays visible until a new password is saved. Authentication, CSRF, role/ownership checks and session invalidation remain enforced.

After updating to this revision, restart the managed panel (no reinstall, database deletion or password reset is needed):

```bash
.venv/bin/python scripts/serve-panel.py --stop
.venv/bin/python scripts/serve-panel.py --background
```

If you launched `python skvm.py` directly, stop that terminal process with Ctrl+C and run `python skvm.py` again. Keep port **31120 Private** and replace the known initial password as soon as possible.

### Installation without apt/sudo

If Python 3.11+, Node 22+ and npm already exist, use `bash install.sh --skip-system`. To run the bundled frontend with Python only:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
python skvm.py
```

Install distro QEMU tools separately or select an external Linux node if the host cannot provide them. The panel reports the actual missing capability; it never substitutes a fake VM or Docker daemon.

### Configuration and database

The installer creates `.env` only when absent and preserves existing configuration. For manual setup, copy `.env.example` to `.env` and edit it. Do not put credentials in Git.

- Default database: **`database/skvm.db`**, automatically initialized on startup. Explicit initialization: `python skvm.py init-db`.
- Guest disks, image cache, locks and private key files: **`data/`**, inside the checkout by default.
- Static initial policy: `config.json`. Admin changes are stored in SQLite `Setting` rows and override those defaults.
- Default port: **31120**, bound to **0.0.0.0**; no host/origin restriction blocks a forwarded preview.
- Set `SKVM_COOKIE_SECURE=1` for HTTPS/Codespaces. Leave it `0` only for local HTTP development. The devcontainer sets `1`.
- `SKVM_DATA_DIR` and `SKVM_DATABASE_URL` support operator-chosen persistent paths. Use a short path without commas/control characters: QEMU Unix socket paths have a length limit.
- A session signing key is generated at startup; a separate Fernet encryption key is generated when encrypted review/job/node data is first needed, both with mode **0600**. `umask 077` protects newly created data. Back these keys up along with the database.
- Only the requested **first-run** admin account is initialized; no debug mode, reloader, fake users or example VPS records. A persistent bootstrap marker prevents re-creation even after that account is deleted.

### Optional: create your own administrator instead

To disable the default account **before the first startup**, set `SKVM_BOOTSTRAP_ADMIN=0` in `.env` or the environment, then use:

```bash
SKVM_BOOTSTRAP_ADMIN=0 bash install.sh --no-start
python skvm.py create-admin --email you@example.com --name 'Your Name'
python skvm.py
```

Persist `SKVM_BOOTSTRAP_ADMIN=0` in `.env` for this opt-out. This flag prevents creation; it does not remove an account that already exists. `init-db` initializes schema/catalog only; `bootstrap-admin` explicitly performs the same one-time empty-database bootstrap used by the installer. External agents and ordinary isolated tests do not receive default accounts.

The terminal prompts for a password twice without echoing it. Minimum length: 12 characters. Existing accounts are **not** silently promoted. New registrations always have the user role. Admin control can subsequently assign roles and plans, disable accounts, suspend guests, configure limits/images, and connect nodes. You cannot disable, demote or delete your current administrator through the UI. Account deletion requires its instances and active/uncertain jobs to be gone; old sessions are invalidated and audit history is retained. Session identities also bind to a randomly salted password hash so a reused SQLite numeric ID cannot inherit an old login.

## Engine A: QEMU

The backend builds controlled argument lists for `qemu-system-x86_64`, `qemu-img`, and `cloud-localds`. It never invokes a web-supplied shell script or accepts arbitrary QEMU flags.

- **TCG by default**, `-machine type=pc,accel=tcg`, modern `-cpu max`, configurable `-m` and `-smp`.
- KVM requires **all three**: explicit `SKVM_USE_KVM=1`, usable `/dev/kvm`, and a real paused-machine accelerator probe. It is never required.
- Allowlisted vendor HTTPS cloud images, QCOW2 magic verification, bounded downloads, optional pinned SHA256, standalone-image validation, and `qemu-img check` before use.
- Each guest gets a **full independent QCOW2 copy**, resized only after validating its base virtual size, plus its own cloud-init seed and UUID. No shared writable disk or backing-file dependency.
- Root SSH disabled. Choose a valid public key or a SHA512-crypt guest password hash. Plaintext guest passwords are not saved to disk, sessions, job payloads, or logs. Temporary user/meta-data files are removed after seed creation; the protected seed contains the required password **hash**, if chosen.
- Loopback-only SSH and extra TCP forwards on one validated user-mode network backend. No TAP/bridge privilege required. QEMU binds `127.0.0.1`, not a public interface. Outbound guest networking is restricted by default; operator network policy applies to new instances.
- Independent `Popen` processes, per-VM `flock` locks, private Unix QMP control sockets, persisted PID **and creation time**, exact UUID/disk matching, and recovery of a matching process if its metadata was lost.
- **Start** initially pauses the virtual CPUs until the QMP monitor is ready, then explicitly resumes and verifies the machine. It requires a responsive QMP monitor and a running QMP machine state. That proves a QEMU process is running, **not** that cloud-init or SSH is ready. If a resume reply is lost, the process is kept and the job becomes uncertain; no potentially live guest is silently killed.
- **Stop** sends QMP `system_powerdown` (ACPI). It waits up to 180 seconds to accommodate slow TCG shutdown/services; a still-running guest is then reported honestly; it is **not** silently killed. **Force stop** is separate, explicit and warns about data loss.
- Restart and panel deletion both require a proven graceful stop before proceeding. Owners can delete their running VPS in one confirmed job; a failed shutdown never falls back to Force stop. Low-level disk deletion still refuses a running/open disk. **Grow-only** disk resizing and OS reinstall remain stopped-only. Reinstall retains the old disk until the new image/seed is prepared. Growing the virtual disk may still require `growpart`/`resize2fs`/`xfs_growfs` inside the guest.
- Emulator/serial boot logs remain internal for bounded operator troubleshooting; the maintenance loop trims logs above 5 MiB to the latest 1 MiB. There is no public serial-input/Console endpoint. Interactive access is the guest’s native SSH or its explicitly generated SSHX capability.

### OS catalog derived from `n.txt`

| OS | Catalog ID | Notes |
|---|---|---|
| Ubuntu 22.04 | `ubuntu-22.04` | Jammy cloud image |
| Ubuntu 24.04 | `ubuntu-24.04` | Noble cloud image |
| Debian 11 | `debian-11` | Lifecycle/archive warning |
| Debian 12 | `debian-12` | Bookworm |
| Debian 13 | `debian-13` | Stable Trixie path instead of the script's daily URL |
| Fedora 40 | `fedora-40` | EOL; corrected archive filename, explicit warning acknowledgement |
| CentOS Stream 9 | `centos-9` | GenericCloud |
| AlmaLinux 9 | `alma-9` | GenericCloud |
| Rocky Linux 9 | `rocky-9` | GenericCloud |

**A catalog entry is not a promise that an old URL works.** Verify from the actual provisioning host:

```bash
python skvm.py verify-images
# Or Admin control → OS image catalog → Verify saved URL now.
# On an external node, update its own image configuration with:
python skvm.py configure-image --id debian-13 --url 'https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.qcow2' --sha256 '<trusted-vendor-sha256>'
```

Use a checksum from the vendor's authenticated/signed manifest, not an arbitrary third party. Without a pin, TLS plus format validation is used; that is **not** a cryptographic publisher-signature verification service. Redirects are revalidated against the vendor allowlist. Private/link-local/loopback image endpoints are rejected.

### SSH from your computer

The details page shows the real configured port and user. In the provisioning host's terminal, use that exact command. From a laptop, tunnel to the Codespace first:

```bash
# Replace YOUR_CODESPACE and 22000 with the actual name/guest forwarding port.
gh codespace ssh -c YOUR_CODESPACE -- -L 2222:127.0.0.1:22000
# Another local terminal:
ssh -p 2222 ubuntu@127.0.0.1
```

For external QEMU nodes, tunnel through **that node**, not the Codespace. Browser HTTP port forwarding is not raw SSH. No public guest IP, SSH private key, or default guest password is fabricated.

## Engine B: Docker (containers, not full VMs)

Docker uses the **Python Docker SDK** and only built-in OS image references. Docker must already be available to the panel user, preferably rootless with delegated cgroups. A Docker socket effectively grants extensive control over its host; use a dedicated trusted node, not a shared public daemon.

Local Unix socket configuration works with `docker.from_env()` (`DOCKER_HOST=unix:///run/user/1000/docker.sock` for an appropriate rootless daemon). Direct TCP/SSH remote Docker transports are refused, including TLS-enabled TCP: the panel cannot safely substitute its own free RAM/disk/CPU for a different daemon host. Deploy the authenticated SKVM node agent **on the Docker host** and connect it as an external node instead. Never forward or expose a Docker socket in the browser.

Containers have:

- Configured memory/memory+swap ceilings and NanoCPUs, PID limit 128.
- UID/GID **1000:1000**, all capabilities dropped, `no-new-privileges`, no privileged flag, no host mounts/socket, and no host namespaces.
- Their own SKVM-labeled **internal bridge network**, separate from QEMU and other guest networks. No automatic public port or SSH server. Use trusted operator daemon tooling or an operator-approved deployment architecture for application networking.
- Exact instance/owner labels checked before every lifecycle operation.
- Owner start, stop, restart, explicit force-stop and confirmed stop-then-delete, with actual cgroup metrics and writable-layer usage. A verified missing container can still have its owned orphan network/panel metadata cleaned up; an unreachable daemon is not treated as absence.
- Fixed allowlisted diagnostics (`id`, `uname -a`, `df -h`, `ps aux`, `/etc/os-release`), never a web-accessible host shell. Some minimal images omit utilities; actual nonzero exit codes are displayed.

**Storage enforcement:** Docker's writable-rootfs quota is storage-driver dependent. SKVM does not assume overlay2 supports it. Only after the operator verifies driver prerequisites (e.g. XFS project quotas), set `SKVM_DOCKER_STORAGE_LIMITS=1`. The real daemon must accept the storage option. Otherwise the user must explicitly accept a **budget-only** disk allocation, clearly marked “not enforced”. Layer usage is not the host's total disk or a fabricated guest capacity. In-place reinstall and rootfs resizing are deliberately unsupported for Docker; create a replacement.

## Honest resource reporting and quotas

A VM configured with 2048 MiB RAM, 2 vCPU and a 20 GiB disk displays those exact values from its provisioning record/manifest. They **never** come from `psutil.virtual_memory()` or the Codespace CPU count.

| VPS allocation | VPS actual usage | Host environment |
|---|---|---|
| Configured RAM | QEMU process RSS / Docker cgroup RAM | Host/cgroup memory ceiling and available memory |
| Configured vCPU | Process/cgroup CPU percentage | Host CPU utilization and affinity/cgroup CPU capacity |
| Virtual disk capacity / container budget | Allocated QCOW2 blocks / writable-layer bytes | Available host storage and panel RSS/CPU/process count |

CPU usage may exceed 100% across cores. Process RSS is not guest `free` memory. A first CPU sample can be unavailable; it is not replaced by an invented reading. Docker one-shot CPU telemetry uses real successive counters if the daemon omits a previous sample; unavailable writable-layer measurements remain unavailable, not an invented zero. Charts accumulate real 5-second samples while open, without made-up history or clipping multi-core CPU values at 100%.

On Linux, capacity follows the process's actual cgroup v1/v2 membership and mount roots, including ancestor RAM/CPU/cpuset limits and shared-parent RAM headroom—not just the mount root or the physical machine totals. Usage scope is labeled separately from effective allocation capacity. Malformed, missing or unreadable cgroup capacity data blocks new allocations with a visible reason rather than guessing that the physical host is available.

Defaults: 3 VPS/user, 4096 MiB/user, 4 vCPU/user, 60 GiB/user; per-instance ceilings 2048 MiB/2 vCPU/40 GiB; 8 guests/node; 75% of effective host RAM available for allocations; 2 GiB free-storage reserve; **no CPU overcommit**. Real node capacity may be **much less** than the plan. Queued/running/uncertain create jobs, incoming assignments and disk-growth deltas reserve the assigned owner’s quota (growth is charged to the guest owner, even when an administrator requested it). Stopped instances retain allocations. Full virtual disk reservation deliberately overestimates materialized storage to avoid thin-provisioning surprises. RAM available-now checks add 256 MiB headroom. Restart rechecks that headroom **after** graceful shutdown releases the guest's memory; if the check fails, the guest stays stopped and the job fails rather than claiming a restart. Stopped disk growth does not reserve the guest's RAM a second time.

Virtual RAM and vCPU are guest configuration—not new physical hardware or a Codespaces promise of dedicated cores. QEMU also has emulator/I/O overhead; vCPU count is not a hard host cgroup CPU ceiling. **TCG can be very slow.** Do not expose this personal/team control plane as a commercial hostile multi-tenant hosting service.

## External nodes

See [the complete external-node setup and API contract](docs/external-nodes.md). This is an implemented agent/transport, not a placeholder dropdown.

- Panel stays in Codespaces; node agent runs on a Linux host with QEMU/Docker capabilities.
- Bearer-authenticated HTTPS with certificate validation and operator allowlisted origins. Node tokens are encrypted in panel SQLite. Panel and agent use **protocol version 1**; upgrade them together. Invalid versions, identities, allocations or oversized responses are rejected, never displayed as trusted success.
- Node-local persistent operation IDs and a single locked worker avoid replaying destructive actions on retries.
- Capacity, actual inventory, image availability and operation state are reported independently from the Codespace host and guest allocations.
- Unreachable nodes show **unknown**, not stopped. A lost mutation response becomes **uncertain** with reservations retained.

## Jobs, persistence and crash recovery

`python skvm.py` starts a persistent SQLite-backed queue and one background worker. Multiple web processes cannot own the worker lock at once. Downloads do not occupy web request threads. Confirmation tickets are bound to the requesting administrator and assignee, encrypted, expire in 10 minutes, and are consumed once. Records are saved **after** an engine creates actual resources.

For a WSGI deployment:

```bash
.venv/bin/gunicorn -c gunicorn.conf.py 'skvm:create_app()'
# The supplied worker-init hook starts one workspace-locked queue consumer.
# Alternatively run a separate consumer with:
python skvm.py worker
```

Use a TLS reverse proxy or private Codespaces proxy. Run as an unprivileged service user, not root. systemd is optional and not used by the application. Do not run arbitrary ad-hoc WSGI commands without starting a queue consumer.

An interrupted in-flight operation becomes **uncertain** on worker restart. The app does not blindly repeat create/start/stop/delete/resize actions or erase a disk. Admin → job → **Reconcile** inspects actual resources under the same control/allocation locks:

- QEMU creation must prove matching identity/allocations, a complete non-symlink manifest/disk/cloud-init seed, a real ISO9660 CIDATA descriptor, and native standalone QCOW2 capacity/integrity. A matching JSON file alone is not success.
- Docker creation must prove matching labels, actual memory/CPU/security constraints and an owned internal network. Its storage enforcement/budget flag remains honest.
- Lifecycle recovery observes actual state and, for a running QEMU guest, matching vCPU/RAM/accelerator arguments. Deletion requires proven absence, including the owned Docker network.
- Disk-growth recovery validates the **already-grown** QCOW2 target and synchronizes metadata only; it never resizes again.
- External recovery reads the durable operation and, if the agent itself crashed, invokes its authenticated inspection endpoint. Busy/incomplete/ambiguous evidence keeps the reservation uncertain. Reinstall recovery requires the pending unique management-key generation, proven stopped resources and completed backup cleanup; ambiguous transitions remain uncertain and require manual inspection.

After verifying and removing **all** leftover resources for a failed job, an operator can release its reservation:

```bash
python skvm.py resolve-job JOB_UUID --confirm-no-resource
```

That command is a manual assertion, not proof that a resource is absent; never use it to bypass inspection. External-agent interrupted operations also retain their encrypted request and uncertain state; let inspection reconcile a proven result, or inspect/recover that node's storage and operation database before manually resolving the panel job. No destructive automatic rollback is attempted across a network partition.

Workspace suspension terminates running processes; disk files survive ordinary restart. Deleting a Codespace can delete its workspace. Back up stopped guests, SQLite (using SQLite's backup API or after stopping writers), `data/.session-key`, and `data/.encryption-key` together. Do not copy a live QCOW2 disk as a crash-consistent backup. Schema initialization/migration is additive; incompatible changes require an explicit migration, never database deletion.

## Tests and compatibility checks

```bash
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
bash scripts/check-environment.sh
.venv/bin/python scripts/qemu-smoke-test.py

# Safe UI/test mode: refuses creation and lifecycle mutations, no demo VPS records.
SKVM_TEST_MODE=1 python skvm.py

# Optional frontend rebuild + Chromium desktop/Android-emulation tests:
npm ci
npm run build:assets
npx playwright install chromium
npm run test:ui
```

Browser tests use **separate temporary databases** on ports 5558/5559, never the live panel database. Desktop and Android-emulation journeys cover user registration/isolation, denied user creation, admin assignee selection, account/plan/node/catalog/settings controls, the non-blocking password reminder and session revocation. SSHX browser journeys use a clearly synthetic SSH-protocol server to test actual backend key authentication, enrollment, polling, link display/copy/stop and foreign-owner denial. They never execute an OS shell or installer and are **not** native guest/SSHX evidence.

Unit tests isolate engine/transport boundaries explicitly. **Separate native acceptance** exercises the real Flask routes, one-use confirmation, durable jobs and actual background consumers:

- Actual standalone QCOW2/CIDATA, TCG process/QMP, duplicate-start protection, growth and deletion.
- Admin provisioning to a **regular assigned owner**, then a trusted-pin Ubuntu 24.04 **TCG** boot, real cloud-init/SSH, guest-visible 768 MiB/1 vCPU and disk growth to 11 GiB, suspension policy, owner restart/persistence/reinstall and running-guest stop-then-delete. Actual guest SSHX installation/link display/stop before and after reinstall includes stale PID/orphan-client recovery and a repeated Start that must preserve the live capability. Force-stop process identity is exercised separately by native blank-QEMU and Docker acceptance.
- Actual Docker memory/CPU/PID limits, isolation/internal network, writable-layer telemetry and lifecycle/persistence.
- Panel → real TLS/bearer agent → actual agent worker → real Docker guest, with separate databases and inventory/diagnostic/deletion checks. Only TCP dialing is routed to an ephemeral loopback port; TLS, HTTP, engines and resources are not mocked.

The push/PR **SKVM full checks** workflow runs Python 3.11/3.12, browser, the actual installer/blank-QEMU test, signed-manifest OS acceptance, all nine live image checks and Docker/TLS-agent acceptance on disposable Linux runners. Native tests do not run by default locally, install/start a Docker daemon, require KVM, prune unrelated resources or touch the live panel database. The manual **Equipped Linux acceptance** workflow remains available for selected checks.

See [the execution report, limitations and equipped-host commands](docs/testing.md) for exact results. The supplied sandbox has no local engines and cannot reach OS vendors, so its four native skips are **not** compatibility passes. Remote CI results are identified separately; endpoint checks do not certify booting all nine OS releases, and Android emulation is not physical-device certification.

## Source layout

```text
skvm.py / config.py / config.json / requirements.txt
engines/       qemu_engine.py, docker_engine.py, node_engine.py
services/      provisioning, guest_ssh/keys/access, sshx, guest process control, capacity/recovery, ...
models/        user, vps/jobs/audit/images/settings, plan, node/agent, encrypted guest access/SSHX
routes/        auth, admin/user dashboards, vps, sshx, admin, api, standalone node_api
templates/     all connected pages, confirmations, job views, setup guide
static/        compiled Tailwind + custom CSS, JS, local icons/chart/font dependencies
scripts/       installation, environment/TCG checks, asset build
tests/         backend/engine/security/agent tests + Playwright desktop/mobile tests
node_agent.py  external-node entry point (loopback only, HTTPS proxy required)
database/      runtime skvm.db (ignored)
data/          runtime vms, images, logs, locks and secrets (ignored)
docs/          original n.txt, audit, external-node instructions, test report
```

Vendored third-party frontend licenses are retained in `static/vendor/` and `static/fonts/`. No runtime image downloads, virtual disks, secrets, live databases, browser binaries or generated test artifacts are included in the source patch.

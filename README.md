# SKVM · QEMU + Docker VPS control plane

A workspace-first Flask management panel for **real QEMU virtual machines** and **separate Docker OS containers**. Dark responsive interface, live measured charts, user accounts, quotas, audit trails, background provisioning, and an authenticated external-node agent.

**No LXC. No systemd requirement. No privileged guest containers. No required KVM. No simulated VPS records.**

## The uploaded `n.txt` is the reference

The entire 1,104-line uploaded Bash manager was read and audited before implementation. Its exact bytes are retained in [`docs/reference/n.txt`](docs/reference/n.txt). The Python engine is a conversion of its useful provisioning/lifecycle behavior—not a website that displays or executes the Bash script.

Read the [reference audit and feature mapping](docs/reference-audit.md), including the destructive resize fallback, default passwords, `source` injection, process-matching bugs, and broken extra-forward handling that were replaced.

## Quick start in GitHub Codespaces

```bash
bash scripts/install-codespaces.sh
python skvm.py
```

1. Forward **5555** from the Codespaces **Ports** tab and open it in your browser. **Keep port visibility Private.** Both `devcontainer.json` and `.devcontainer/devcontainer.json` describe the environment and forwarding.
2. Register an ordinary user in the UI, or create your administrator using the operator CLI below.
3. Open **Settings** for the *actual* local engine capabilities. Missing QEMU tools or a Docker daemon are not hidden.
4. Configure an available engine, select **Create VPS**, review your configuration, and confirm. Watch its background job. A successful create leaves a **real stopped instance**; use **Start** to boot/run it.

`python skvm.py` automatically uses `.venv/bin/python` if the installer created it. Node/npm are **not required at runtime**; Tailwind CSS, Inter, Lucide, and Chart.js are built and committed locally, without CDN dependencies.

### Installation without apt/sudo

Python dependencies can be installed without root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
python skvm.py
```

Installing distro QEMU packages may require an operator or prebuilt devcontainer. The installer attempts `qemu-system-x86`, `qemu-utils`, `cloud-image-utils`, and `genisoimage` on Debian/Ubuntu, but does not silently pretend apt succeeded. The panel can run without these binaries; local QEMU remains unavailable and an external Linux node can be selected instead. It does not install or require a privileged Docker-in-Docker daemon.

### Configuration and database

Copy `.env.example` to `.env` and edit it. Do not put credentials in Git.

- Default database: **`database/skvm.db`**, automatically initialized on startup. Explicit initialization: `python skvm.py init-db`.
- Guest disks, image cache, locks and private key files: **`data/`**, inside the checkout by default.
- Static initial policy: `config.json`. Admin changes are stored in SQLite `Setting` rows and override those defaults.
- Default port: **5555**, bound to **0.0.0.0**; no host/origin restriction blocks a forwarded preview.
- Set `SKVM_COOKIE_SECURE=1` for HTTPS/Codespaces. Leave it `0` only for local HTTP development. The devcontainer sets `1`.
- `SKVM_DATA_DIR` and `SKVM_DATABASE_URL` support operator-chosen persistent paths. Use a short path without commas/control characters: QEMU Unix socket paths have a length limit.
- A session signing key is generated at startup; a separate Fernet encryption key is generated when encrypted review/job/node data is first needed, both with mode **0600**. `umask 077` protects newly created data. Back these keys up along with the database.
- No debug mode, reloader, public default credentials, seeded users, or example VPS records.

### Create an administrator

```bash
python skvm.py create-admin --email you@example.com --name 'Your Name'
```

The terminal prompts for a password twice without echoing it. Minimum length: 12 characters. Existing accounts are **not** silently promoted. New registrations always have the user role. Admin control can subsequently assign roles and plans, disable accounts, suspend guests, configure limits/images, and connect nodes. You cannot disable, demote or delete your current administrator through the UI. Account deletion requires its instances and active/uncertain jobs to be gone; old sessions are invalidated and audit history is retained. Session identities also bind to a randomly salted password hash so a reused SQLite numeric ID cannot inherit an old login.

## Engine A: QEMU

The backend builds controlled argument lists for `qemu-system-x86_64`, `qemu-img`, and `cloud-localds`. It never invokes a web-supplied shell script or accepts arbitrary QEMU flags.

- **TCG by default**, `-machine type=pc,accel=tcg`, modern `-cpu max`, configurable `-m` and `-smp`.
- KVM requires **all three**: explicit `SKVM_USE_KVM=1`, usable `/dev/kvm`, and a real paused-machine accelerator probe. It is never required.
- Allowlisted vendor HTTPS cloud images, QCOW2 magic verification, bounded downloads, optional pinned SHA256, standalone-image validation, and `qemu-img check` before use.
- Each guest gets a **full independent QCOW2 copy**, resized only after validating its base virtual size, plus its own cloud-init seed and UUID. No shared writable disk or backing-file dependency.
- Root SSH disabled. Choose a valid public key or a SHA512-crypt guest password hash. Plaintext guest passwords are not saved to disk, sessions, job payloads, or logs. Temporary user/meta-data files are removed after seed creation; the protected seed contains the required password **hash**, if chosen.
- Loopback-only SSH and extra TCP forwards on one validated user-mode network backend. No TAP/bridge privilege required. QEMU binds `127.0.0.1`, not a public interface. Outbound guest networking is restricted by default; operator network policy applies to new instances.
- Independent `Popen` processes, per-VM `flock` locks, private Unix QMP/serial sockets, persisted PID **and creation time**, exact UUID/disk matching, and recovery of a matching process if its metadata was lost.
- **Start** initially pauses the virtual CPUs until the QMP monitor is ready, then explicitly resumes and verifies the machine. It requires a responsive QMP monitor and a running QMP machine state. That proves a QEMU process is running, **not** that cloud-init or SSH is ready. If a resume reply is lost, the process is kept and the job becomes uncertain; no potentially live guest is silently killed.
- **Stop** sends QMP `system_powerdown` (ACPI). It waits up to 180 seconds to accommodate slow TCG shutdown/services; a still-running guest is then reported honestly; it is **not** silently killed. **Force stop** is separate, explicit and warns about data loss.
- Restart, stopped-only deletion, **grow-only** disk resizing, and stopped-only OS reinstall. Reinstall retains the old disk until the new image/seed is prepared. Growing the virtual disk may still require `growpart`/`resize2fs`/`xfs_growfs` inside the guest.
- Serial console output is real guest output. An independent maintenance loop trims emulator/serial logs above 5 MiB to the latest 1 MiB every 20 seconds. Input goes to a guest-only Unix chardev, never a host shell. Input is hidden in the UI and not included in audit logs.

### OS catalog derived from `n.txt`

| OS | Catalog ID | Notes |
|---|---|---|
| Ubuntu 22.04 | `ubuntu-22.04` | Jammy cloud image |
| Ubuntu 24.04 | `ubuntu-24.04` | Noble cloud image |
| Debian 11 | `debian-11` | Lifecycle/archive warning |
| Debian 12 | `debian-12` | Bookworm |
| Debian 13 | `debian-13` | Stable Trixie path instead of the script's daily URL |
| Fedora 40 | `fedora-40` | EOL; archive candidate, explicit warning acknowledgement |
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
- Their own SKVM-labeled **internal bridge network**, separate from QEMU and other guest networks. No automatic public port or SSH server. Use in-container Console diagnostics or an operator-approved deployment architecture for application networking.
- Exact instance/owner labels checked before every lifecycle operation.
- Start, stop, restart, explicit force-stop, stopped-only delete, actual cgroup metrics and writable-layer usage.
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

Defaults: 3 VPS/user, 4096 MiB/user, 4 vCPU/user, 60 GiB/user; per-instance ceilings 2048 MiB/2 vCPU/40 GiB; 8 guests/node; 75% of effective host RAM available for allocations; 2 GiB free-storage reserve; **no CPU overcommit**. Real node capacity may be **much less** than the plan. Queued/running/uncertain create jobs and disk-growth deltas reserve quota (growth is charged to the guest owner, even when an administrator requested it). Stopped instances retain allocations. Full virtual disk reservation deliberately overestimates materialized storage to avoid thin-provisioning surprises. RAM available-now checks add 256 MiB headroom. Restart rechecks that headroom **after** graceful shutdown releases the guest's memory; if the check fails, the guest stays stopped and the job fails rather than claiming a restart. Stopped disk growth does not reserve the guest's RAM a second time.

Virtual RAM and vCPU are guest configuration—not new physical hardware or a Codespaces promise of dedicated cores. QEMU also has emulator/I/O overhead; vCPU count is not a hard host cgroup CPU ceiling. **TCG can be very slow.** Do not expose this personal/team control plane as a commercial hostile multi-tenant hosting service.

## External nodes

See [the complete external-node setup and API contract](docs/external-nodes.md). This is an implemented agent/transport, not a placeholder dropdown.

- Panel stays in Codespaces; node agent runs on a Linux host with QEMU/Docker capabilities.
- Bearer-authenticated HTTPS with certificate validation and operator allowlisted origins. Node tokens are encrypted in panel SQLite. Panel and agent use **protocol version 1**; upgrade them together. Invalid versions, identities, allocations or oversized responses are rejected, never displayed as trusted success.
- Node-local persistent operation IDs and a single locked worker avoid replaying destructive actions on retries.
- Capacity, actual inventory, image availability and operation state are reported independently from the Codespace host and guest allocations.
- Unreachable nodes show **unknown**, not stopped. A lost mutation response becomes **uncertain** with reservations retained.

## Jobs, persistence and crash recovery

`python skvm.py` starts a persistent SQLite-backed queue and one background worker. Multiple web processes cannot own the worker lock at once. Downloads do not occupy web request threads. Confirmation tickets are owner-bound, encrypted, expire in 10 minutes, and are consumed once. Records are saved **after** an engine creates actual resources.

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
- External recovery reads the durable operation and, if the agent itself crashed, invokes its authenticated inspection endpoint. Busy/incomplete/ambiguous evidence keeps the reservation uncertain. Reinstall and ambiguous policy transitions still require manual inspection.

After verifying and removing **all** leftover resources for a failed job, an operator can release its reservation:

```bash
python skvm.py resolve-job JOB_UUID --confirm-no-resource
```

That command is a manual assertion, not proof that a resource is absent; never use it to bypass inspection. External-agent interrupted operations also retain their encrypted request and uncertain state; let inspection reconcile a proven result, or inspect/recover that node's storage and operation database before manually resolving the panel job. No destructive automatic rollback is attempted across a network partition.

Workspace suspension terminates running processes; disk files survive ordinary restart. Deleting a Codespace can delete its workspace. Back up stopped guests, SQLite (using SQLite's backup API or after stopping writers), `data/.session-key`, and `data/.encryption-key` together. Do not copy a live QCOW2 disk as a crash-consistent backup. Schema v1 uses `create_all`; future incompatible schema changes need an explicit migration, not deletion of the DB.

## Tests and compatibility checks

```bash
.venv/bin/python -m pytest -q
bash scripts/check-environment.sh
python scripts/qemu-smoke-test.py

# Safe UI/test mode: refuses creation and lifecycle mutations, no demo VPS records.
SKVM_TEST_MODE=1 python skvm.py

# Optional frontend rebuild + Chromium desktop/Android-emulation tests:
npm ci
npm run build:assets
npx playwright install chromium
npm run test:ui
```

Browser tests use their **own temporary DB and port 5558**, not `database/skvm.db`. Backend tests use temporary databases; provisioning boundaries are explicitly mocked. The local TLS integration uses a real HTTPS server, generated test-only certificates, the actual panel client and standalone agent; it validates CA/hostname rejection and bearer authentication without creating guests or claiming an external deployment.

An equipped-host QEMU integration test starts a blank-disk TCG machine and verifies real QMP/PID/disk operations; it skips when tools are absent and does not claim an OS boot. **Separate opt-in acceptance tests** now cover an actual pinned Ubuntu 24.04 cloud-init/SSH boot, independent guest RAM/vCPU, graceful shutdown/growth/restart/persistence, and a real Docker container's cgroup limits/internal network/lifecycle/persistence. They do not run by default, install a daemon, require KVM, or touch the panel database.

See [equipped-host commands and checksum requirements](docs/testing.md#opt-in-equipped-host-acceptance). The manual **Equipped Linux acceptance** workflow runs these tests on disposable Linux runners when explicitly requested. Adding that workflow is not evidence that it has run.

See [the execution report](docs/testing.md) for exactly what was run and what could not be tested in the supplied sandbox.

## Source layout

```text
skvm.py / config.py / config.json / requirements.txt
engines/       qemu_engine.py, docker_engine.py, node_engine.py
services/      provisioning, cgroups, resource_monitor, recovery, node_protocol, validation, ...
models/        user, vps/jobs/audit/images/settings, plan, node/agent records
routes/        auth, dashboard, vps, admin, api, standalone node_api
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

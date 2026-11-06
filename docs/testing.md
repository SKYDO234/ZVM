# Test execution and compatibility report

Date: **2026-11-06**. Validated application source: **`56bb0a2`** on `arena/364e5d5e-zvm`. Documentation-only follow-ups do not change that application source.

## Latest results

| Check | Result and scope |
|---|---|
| Local backend/security/regressions | **166 passed, 4 skipped, 1 warning in 45.55 s** |
| Local measured Python coverage | **71%** (3,009 statements); not a claim of exhaustive coverage |
| Local Chromium desktop + Pixel 7 emulation | **8 passed in 49.9 s** |
| Remote Python 3.11 and 3.12 | **166 passed, 4 skipped on each version**, source `56bb0a2` |
| Actual Ubuntu 24.04 / TCG / cloud-init / SSH | **1 passed, 0 skipped** on `56bb0a2`, including the corrected bounded graceful-shutdown wait |
| Actual Docker and panel → TLS agent → Docker | **2 passed, 0 skipped**, source `56bb0a2` |
| All nine live image endpoints | **9 verified HTTPS QCOW2 endpoints** on `56bb0a2`, including the Fedora archive and Debian mirror redirects |
| Actual documented installer + blank-disk QEMU | **Passed**, actual installer + native smoke/integration on `56bb0a2` |
| Interactive administrator bootstrap | Passed in a disposable DB using a genuine terminal; hidden password, stored hash, no silent promotion, no guests |

**Final-source CI: COMPLETED SUCCESSFULLY — all six jobs green.** [SKVM full checks, run 42203719685](https://github.com/SKYDO234/ZVM/actions/runs/42203719685), application commit `56bb0a256dc2b8789a6aa22359dc9fd419e4915c`. The real Ubuntu panel/SSH/lifecycle step ran from **10:35:58 to 10:49:17 UTC** and passed without skips. Earlier failures were fixed and rerun, not counted as successes. Documentation-only follow-ups use `[skip ci]` to avoid needlessly repeating the same long native execution; no application/test/workflow code changes after this validated revision are included in those follow-ups.

## What the automated checks exercise

### Backend, security and persistence

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q -rs
.venv/bin/python -m pytest --cov=engines --cov=services --cov=routes --cov=models --cov=skvm --cov-report=term-missing -q
```

Temporary databases/directories are used, never `database/skvm.db`. Unit tests explicitly mock engine/transport boundaries where real host resources are not intended. Native resource tests are separately identified below.

Coverage includes:

- Registration/login/logout, salted password hashing, safe redirects, CSRF and role/ownership checks on details, metrics, console and every action.
- Password/profile changes, session revocation, account disablement, numeric-user-ID reuse, guarded deletion, retained audits, and purpose-separated login/registration throttles.
- Admin users, roles, plans, quotas, persistent settings, image configuration and node registration/token handling.
- Strict HTML5 parsing of public/authenticated/admin/instance/job forms, including correct node-form actions and CSRF fields.
- Creation review, encrypted expiring confirmation, duplicate-confirmation rejection, no premature VPS row, conservative capacity/quotas and uncertain-operation reservations.
- Cgroup v1/v2 membership/mount/ancestor accounting, sibling pressure, CPU quotas/affinity, private-path/SSRF protection and fail-closed unknown capacity.
- Controlled QEMU arguments, full-copy disk provisioning, independent allocations/seeds, initial paused QMP launch/resume, exact process identity, duplicate start/PID reuse, no automatic graceful-to-force escalation, disk growth and recovery proof.
- Docker SDK signatures and explicit client closure using a genuine SDK client at a mocked network boundary; resource/security options, network cleanup, measured CPU history and exact-container writable-layer telemetry.
- Allowlisted HTTPS redirects, HTTP cleanup, raw stream timeout classification/deadlines, cached-image SHA256 revalidation, symlink rejection and partial-file cleanup.
- Real background-thread startup, idempotency, shutdown drain/restart, and refusal of mutations in test mode.
- Versioned node schemas, capacity/identity validation, token redaction, durable/idempotent operations and metadata-only reconciliation without replaying mutations.

The one local warning is Passlib's use of Python 3.11's deprecated `crypt` interface. It is not a failed test. Python versions actually checked remotely are 3.11 and 3.12.

### Browser checks

```bash
npm ci
npm run build:assets
npx playwright install --with-deps chromium
npm run test:ui
```

Four journeys execute on both **1440 × 960 desktop Chromium** and **Pixel 7 Chromium emulation**:

1. Responsive landing, registration, actual empty dashboard/activity/chart samples and mobile navigation.
2. Connected authenticated pages, live allocation form summary, Docker/QEMU field switching, honest test-mode provisioning refusal and ordinary-user admin denial.
3. Admin node-form submission/rejection, plan creation/assignment, user disablement/login denial/re-enable, image checksum configuration, resource policy persistence, guarded deletion cancel/confirm and metrics authorization.
4. Profile/password replacement, rejection of an old session, session revocation, confirmation dialog, mobile-menu logout and unauthenticated API rejection.

There are no seeded historical chart points or guests and no browser JavaScript exceptions. The test server uses **port 5558**, its own temporary database, private randomly generated fixture credentials and **real provisioning disabled**. These are browser/UI results, not native resource tests or physical-device certification.

The sandbox could not reach Playwright's normal browser-download host, so its local Chromium executable was extracted from an allowed npm package outside the repository. CI uses the ordinary Playwright installer. No browser binaries or credential artifacts are committed.

### Actual TLS/authentication

`tests/test_node_tls.py` uses generated temporary CA/server certificates, the actual `NodeEngine`, and a real HTTPS agent. It verifies untrusted CA, wrong hostname and wrong bearer rejection, and a valid authenticated capabilities response. Only the TCP destination is routed to an ephemeral loopback port; TLS, hostname checks, HTTP, token checking and JSON are genuine.

The native Docker suite additionally provisions a **real guest through this TLS agent**, using separate panel/agent databases and actual worker threads. This is an isolated loopback integration, **not** a claim that an internet-facing node/reverse proxy was deployed.

## Equipped-host resource acceptance

`.github/workflows/tests.yml` executes these checks on disposable Ubuntu Linux runners. Native tests use unique UUIDs, isolated databases and owned-resource cleanup. They do not seed success rows, prune unrelated resources, start a Docker daemon, require KVM or use privileged guest containers.

### Installer and blank-disk QEMU

The `qemu-userspace` CI job executes **the actual `scripts/install-codespaces.sh`**, then `scripts/qemu-smoke-test.py` and `tests/test_qemu_integration.py` with the installed virtual environment. Package network retries/timeouts are bounded. The smoke/integration steps fail if real tools are missing, even if the installer correctly fell back to panel-only mode.

The integration verifies actual standalone QCOW2 creation, CIDATA seed, TCG process/QMP state, duplicate start rejection, explicit force stop, stopped disk growth and owned deletion. A running blank disk is **not** called an OS boot.

### Ubuntu 24.04 cloud-init/SSH and lifecycle

Install QEMU, qemu-img, cloud-localds, OpenSSH and **a trusted distribution Ubuntu cloud-image keyring**, then:

```bash
.venv/bin/python scripts/qemu-smoke-test.py
export SKVM_BOOT_IMAGE_SHA256="$(.venv/bin/python scripts/verified-ubuntu-checksum.py)"
SKVM_RUN_OS_BOOT=1 .venv/bin/python -m pytest tests/test_qemu_os_boot.py -q -rs
```

`verified-ubuntu-checksum.py` verifies the HTTPS vendor manifest's GPG signature against the **distribution-provided keyring**, not a key fetched alongside that manifest. It accepts exactly one checksum for the selected image. A changed image/pin mismatch fails; TLS or signature checks are never bypassed.

`tests/test_qemu_os_boot.py` executes real Flask login/create/review/one-use confirmation routes, the durable queue and an **actual background consumer**, followed by:

- Real independent 10 GiB QCOW2 and CIDATA creation, native image integrity and recovery checks.
- **TCG explicitly**, 768 MiB RAM / 1 vCPU; real QMP running state followed separately by actual SSH readiness.
- Key-authenticated configured user, Ubuntu 24.04 identity, guest-visible RAM/vCPU, `cloud-init status --wait` completion with no errors.
- Guest data write, actual ACPI stop/admin suspension, start denial while suspended and unsuspension.
- Stopped growth to 11 GiB, guest-visible **11 × 2³⁰-byte block device** and persisted data after reboot.
- Graceful stop, same-guest reinstall, new first boot/key authentication, absence of the old data, explicit force stop, disk/row deletion.

A repeated run exposed Ubuntu's final shutdown service occasionally exceeding 25 seconds under TCG. The engine now waits **up to 180 seconds**, never automatically force-kills, and still reports failure if the process remains. This fix is not hidden by weakening the native test.

Optional `SKVM_BOOT_REPORT_DIR` records phase/allocation/checksum/result JSON and bounded failure log tails. Private keys and disks are never uploaded. Native tests can take many minutes under TCG.

### Docker and TLS-agent provisioning

Use an already-accessible **local Unix** daemon with actual memory/CPU controls:

```bash
# Set your actual Unix socket if needed; never a remote TCP/SSH daemon URL.
# export DOCKER_HOST=unix:///run/user/1000/docker.sock
SKVM_RUN_DOCKER_INTEGRATION=1 .venv/bin/python -m pytest tests/test_docker_integration.py -q -rs
```

The first case verifies real panel confirmation/queued creation, **128 MiB / 1 CPU**, in-container memory/CPU/**128-PID** enforcement, UID 1000, no privilege/host mounts/ports, internal network, actual process/writable-layer telemetry, data persistence through stop/start/restart, force stop and owned deletion.

The second registers the actual TLS/bearer-authenticated agent through the admin route, provisions through **both real queue consumers**, verifies panel/agent records and actual inventory/diagnostics, and stops/deletes the container through the authenticated protocol.

The requested **1 GiB disk is explicitly budget-only** unless a supported driver has separately been configured and verified for rootfs quota enforcement. These tests do not certify universal Docker storage quotas or container-to-VM equivalence.

### Image catalog verification

```bash
.venv/bin/python scripts/check-image-catalog.py --report test-results/image-catalog.json --strict
```

All nine URLs are range-read from a disposable database and checked for QCOW2 magic. Fedora 40 uses the corrected `Fedora-Cloud-Base-Generic.x86_64-40-1.14.qcow2` archive filename. Debian's official HTTPS redirects require explicit `cdimage.debian.org` and the observed `gemmei`, `laotzu`, and `chuangtzu.ftp.acc.umu.se` mirror allowlist entries. Each redirect still undergoes HTTPS/host/public-DNS validation. No wildcard or TLS fallback was added.

**Endpoint verification is not an OS boot, support-lifecycle guarantee or publisher-signature check.** Debian 11 and Fedora 40 keep their warnings. All nine were verified remotely; the supplied sandbox itself still cannot reach vendor hosts.

### CI evidence

The push/PR workflow covers Python 3.11/3.12, browser, actual installer/blank QEMU, signed-checksum full-OS panel acceptance, and Docker/TLS-agent panel acceptance. `scripts/report-ci.py` publishes bounded JUnit/catalog details through GitHub check annotations in addition to artifacts; failures retain root causes even when log-storage downloads are blocked. Artifacts expire after seven days and exclude keys/disks.

`.github/workflows/acceptance.yml` also provides manually dispatched `qemu`, `docker` or `both` targets. Publish the workflow on your default branch before using its manual Actions control. For manual QEMU runs, supply the trusted current image checksum; missing tools, pin or daemon are failures, not skipped acceptance successes.

## Boundaries and deployment acceptance

- The supplied sandbox still has **no local QEMU/qemu-img/cloud-localds, Docker daemon or KVM**. Its four local native skips are shown, not counted as passes. Native execution takes place on the identified equipped CI runners.
- Only **Ubuntu 24.04** received a full OS/SSH/lifecycle acceptance run; other catalog entries received endpoint checks, not complete boot certification.
- KVM, a physical Android device, ARM hosts, live WAN/reverse-proxy deployment, rootless Docker, all storage drivers/quotas and every partition/crash timing have **not** been certified.
- A fresh Codespaces devcontainer build and its actual long-running production deployment must still be checked in that Codespace. The Linux installer CI does not claim to be such a deployment.
- No tests prove dedicated hardware performance, VM-grade Docker isolation, universal disk quotas, unlimited capacity, uptime or production hardening for hostile public multi-tenancy.

Before real deployment: keep port 5555 Private; enable secure cookies for HTTPS; create your own administrator interactively; verify the selected engine and image from the provisioning host; check real serial/cloud-init/SSH readiness, not just QMP status; validate your node's TLS/proxy/socket/cgroup/storage arrangement; and back up SQLite, keys and stopped guest storage together.

The live preview uses the actual application and preserved empty production database. No default administrator, public password, fake IP, fake guest or success metrics are inserted for the preview.

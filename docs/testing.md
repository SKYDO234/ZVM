# Test execution and honest compatibility report

Date: **2026-11-06 (UTC)**. Development environment: Linux x86-64, Python 3.11, approximately 3.7 GiB effective RAM and 2 effective CPUs. Measurements vary with running processes; these host values were never used as guest allocations.

## Executed successfully

### Python backend: 127 passed, 3 skipped

Command: `.venv/bin/python -m pytest -q -rs`. Latest full run: **127 passed, 3 skipped, 1 warning in 26.44 seconds**.

The suite covers:

- Registration, login/logout, salted scrypt password hashing, safe post-login redirects.
- Session revocation on password change or account disablement; ordinary registrations never grant admin.
- Real CSRF tokens and rejection of missing tokens.
- Admin route authorization and connected-page template rendering, working plan assignment and persistent settings.
- Guarded account deletion, retained/anonymized audit history, rejection while resources/jobs remain, and old-session rejection even if a numeric SQLite user ID is reused.
- Every instance details/metrics/console/action ownership path.
- Strict guest/input/key validation; root login rejection; guest password hash rather than plaintext.
- QEMU/Docker absence detection, TCG default, explicit-and-probed KVM selection at a mocked OS boundary.
- QEMU command parameters, single-NIC extra forwarding, loopback binding and independent allocations.
- Per-VM cloud-init YAML and temporary-file cleanup.
- Independent disk-copy commands and stopped provisioning manifests.
- Duplicate-process rejection, reused-PID safety, initial-paused QMP readiness/retry/resume, no force-kill after a lost resume reply, non-escalating ACPI shutdown, grow-only/stopped resizing.
- Safe argument-list subprocess execution, URL/SSRF allowlists, path traversal rejection.
- Docker SDK CPU/memory limits, UID 1000, dropped capabilities, no privilege/host socket, storage-budget honesty, safe network cleanup/retry, and rejection of direct remote transports (use a co-located node agent for correct capacity).
- Cgroup v1/v2 leaf/ancestor memory, quota and cpuset discovery, namespace/mount roots/escaped paths, shared-parent headroom, scoped real usage and fail-closed unknown/missing capacity.
- Per-user RAM/CPU/disk/count quotas, pending/uncertain create and disk-growth reservations (including administrator-requested growth charged to its owner), actual host capacity denial.
- Independent 2048 MiB / 2 vCPU / 20 GiB allocation reporting rather than host totals.
- Provisioning failure without a VPS record; record insertion only after an explicitly mocked successful engine boundary.
- One-time encrypted review tickets, duplicate-confirmation prevention and deferred provisioning.
- SQLite persistence across app factory lifecycles.
- External-agent bearer authentication, no public panel routes, persistent idempotency IDs, transport allowlisting, verified token rotation, test-mode refusal, node disk-resize JSON persistence.
- Version-1 node schemas, bounded TLS transport, no redirects, identity/allocation checks, finite capacity numbers, invalid/5xx responses remaining uncertain and token error redaction (HTTP/engine boundaries mocked).
- Read-only outcome recovery with actual-file fixtures and mocked native QCOW2/Docker/process boundaries: complete CIDATA/manifest proof, target-only disk metadata synchronization, no lifecycle replay, isolation/PID/device/namespace drift rejection, orphan-network refusal, and preserved reservations.
- Durable completed SQLite transactions remain completed even when a simulated commit acknowledgement is lost.
- Restart checks available memory after graceful shutdown; failed headroom checks never start a process. Stopped disk growth does not require guest RAM a second time. Panel and agent paths are covered.
- Docker paused force-stop, bounded observation after daemon acknowledgement, refusal to report an unverified state as stopped, actual-counter CPU history and unavailable layer-size handling (SDK boundaries mocked).
- QCOW2 endpoint verification success/failure state at a mocked HTTP boundary.
- Request-independent worker audit insertion.
- Stable private secret files and bounded emulator logs without following symlinks.

**Tests that mock engines do not create real guests.** All three real-resource integration tests were skipped: blank-disk QEMU lacks binaries; full-OS QEMU and Docker are explicit opt-ins. The real HTTPS loopback test below is not a resource-provisioning test. Fixture records only exist in temporary databases. They are not inserted into `database/skvm.db`. There is no fake engine wired into the application.

One known non-failing warning: Passlib imports Python 3.11's deprecated `crypt` module for its SHA512-crypt backend. This is not plaintext storage. Passlib also provides a pure-Python fallback on versions without that module. Application login passwords use Werkzeug scrypt, separately.

### Chromium desktop + Android emulation: 4 passed

Command: `LD_LIBRARY_PATH=/tmp/al2023/lib SKVM_BROWSER_EXECUTABLE_PATH=/tmp/chromium npm run test:ui`. Latest run: **4 passed in 18.1 seconds** after the capacity/scope UI changes and asset rebuild.

The sandbox blocks Playwright's ordinary browser-download host. For this run only, a Chromium package was obtained from the allowed npm registry, extracted outside the repository, and used for browser execution. No browser binaries or test data are committed. Normal development can use `npx playwright install chromium`.

Executed on 1440-pixel desktop and Playwright Pixel 7 / Chromium emulation:

- Landing → registration → authenticated dashboard.
- Zero instances/allocations are actual empty-database values.
- Host chart collects two real measured samples; no historical points are seeded.
- Responsive layout has no horizontal overflow; Android sidebar opens and navigates.
- My VPS, create, console, profile, settings and docs routes work.
- Docker selection hides/disables QEMU credential inputs and shows storage acknowledgement.
- Form summary reflects entered configuration.
- Test-mode submission shows a real error and leaves total VPS at zero.
- Ordinary user cannot access admin.
- No browser JavaScript exceptions.

Browser test server: **5558**, automatically started/stopped, isolated temporary database, real provisioning disabled. This is **Android browser emulation, not a physical-device certification**. Desktop/mobile screenshots were inspected locally but are not part of the source patch.

### Real local HTTPS client/agent integration: passed

`tests/test_node_tls.py` runs the actual NodeEngine client against the standalone Flask agent over real loopback TLS, with generated temporary CA/server keys and certificates. It verifies:

- An untrusted CA fails before an authenticated HTTP request succeeds.
- Explicitly trusting that CA allows a real version-1 capabilities response with actual host measurements and an empty temporary inventory.
- A different allowlisted hostname still fails certificate hostname verification.
- A wrong bearer token receives an actual HTTP 401.
- No AgentInstance resources are created; the test agent really refuses provisioning in test mode.

Only the TCP dialing destination is routed to an ephemeral loopback port, avoiding privileged port 443. HTTP responses, TLS, hostname/CA verification, token checking and protocol decoding are **not mocked**. This does not validate external DNS, a deployed reverse proxy, network-partition behavior or real remote guest execution.

### Other checks

- `npm run build:assets`: local vendor files/licenses/font and compiled Tailwind rebuilt successfully.
- `node --check static/js/app.js`: passed.
- Python bytecode compilation: passed.
- Ruff name/import checks (`ruff check --select F .`): passed.
- Uploaded reference checksum verified against the exact preserved file.
- Both GitHub workflow files parse as valid YAML; no remote execution is implied.
- Shell syntax checks passed for every installer/environment script.
- `bash scripts/check-environment.sh`: correctly reports the missing capabilities below.
- Live Flask preview binds `0.0.0.0:5555` with no host/origin rejection.

## Unavailable or unverified, not reported as success

| Capability | Actual result |
|---|---|
| `qemu-system-x86_64` | Not installed |
| `qemu-img` | Not installed |
| `cloud-localds` | Not installed |
| `/dev/kvm` | Absent; KVM **not** claimed |
| Local Docker daemon/socket | No accessible daemon/socket |
| Real blank-disk QEMU integration | **Skipped**, due to missing binaries |
| Full-OS QEMU and real-Docker opt-ins | **Skipped**, not enabled; prerequisites are also unavailable here |
| `python scripts/qemu-smoke-test.py` | Exits nonzero with `UNAVAILABLE`; it does not fake a pass |
| All nine vendor cloud-image endpoints | Live range-GET attempted; blocked with SSL/TLS connection failures by sandbox outbound-host policy |
| Cloud image download / cloud-init / guest OS boot / SSH | **Not performed** here |
| Real Docker image pull/container lifecycle/cgroup enforcement | **Not performed** here |
| Live remote TLS node deployment | Protocol/auth/persistence unit-tested **and** real loopback HTTPS tested; **no external deployment** validated here |
| GitHub Actions workflows | Added for future runner execution; **not** claimed to have run remotely |

The QEMU integration test and CI userspace-QEMU job validate real disk/process/QMP operations only when actually executed on an equipped Linux host. The blank-disk test does **not** assert a successful cloud OS boot. The separate opt-ins below are written to test OS/SSH and Docker behavior; they have not been executed in this sandbox.

## Opt-in equipped-host acceptance

Use a dedicated/disposable **x86-64 Linux** host with conservative free capacity, trusted internet access, and userspace QEMU/cloud-localds/OpenSSH installed. These tests use temporary app databases/directories and unique resource IDs; they never use `database/skvm.db`, provision seeded success rows, prune other containers/images, start a daemon, require KVM, or launch privileged containers. Default pytest can run the **blank-disk** QEMU test if its binaries are installed; full-OS and Docker tests require the flags below.

### Real Ubuntu/cloud-init/SSH boot (not run here)

Obtain the current Ubuntu 24.04 **amd64** image SHA256 from the authenticated vendor checksum manifest (verify its signed manifest through your normal trusted vendor procedure). It must match the built-in Noble `current` image at download time. A vendor update/pin mismatch is a failure, never a reason to disable checksum/TLS verification. The test does not auto-trust a checksum downloaded alongside untrusted data.

```bash
# Prerequisites on Debian/Ubuntu; installation may require an operator:
# sudo apt-get install qemu-system-x86 qemu-utils cloud-image-utils genisoimage openssh-client
.venv/bin/python scripts/qemu-smoke-test.py
read -r -p 'Vendor-verified current Ubuntu amd64 SHA256: ' SKVM_BOOT_IMAGE_SHA256
export SKVM_BOOT_IMAGE_SHA256
SKVM_RUN_OS_BOOT=1 .venv/bin/python -m pytest tests/test_qemu_os_boot.py -q -rs
```

The checksum must be exactly 64 hex characters. The test creates a short-path temporary data directory (QEMU Unix-socket limits), a private disposable SSH key, an independent 10 GiB QCOW2 and real CIDATA seed. It explicitly uses **TCG**, boots 768 MiB/1 vCPU, waits for real key-authenticated SSH and `cloud-init status`, checks Ubuntu 24.04 and actual guest RAM/vCPU, persists a marker, gracefully stops, grows to 11 GiB, restarts, verifies the marker, then stops/deletes its own UUID. It does not need a plaintext password or an uploaded private key. Cleanup forcibly stops only its own proven process if needed.

Optional `SKVM_BOOT_REPORT_DIR=/operator/chosen/test-output` records phase/result metadata and bounded failure log tails, **not** private key contents. Keep output outside Git. Source-level/native recovery assertions are exercised against actual qemu-img/cloud-localds output only when this test runs.

### Real Docker lifecycle/enforcement (not run here)

Docker must already expose an accessible **local Unix** daemon with actual memory/CPU controls. Use a trusted dedicated daemon; the test does not install one or enable Docker-in-Docker/privilege/systemd. It pulls the catalog's Ubuntu container image; cached images are deliberately not pruned.

```bash
# Use your actual rootless Unix socket if applicable; never a TCP/SSH daemon URL.
# export DOCKER_HOST=unix:///run/user/1000/docker.sock
SKVM_RUN_DOCKER_INTEGRATION=1 .venv/bin/python -m pytest tests/test_docker_integration.py -q -rs
```

It creates a disposable 128 MiB/1 CPU/1 GiB **container budget**, verifies UID 1000 and actual in-container memory/CPU/PID cgroup limits, internal network and no host mounts/ports, polls real usage, verifies writable-layer persistence through stop/start/restart, then force-stops/deletes the container and owned network. Missing layer-size telemetry remains unavailable. Storage is explicitly **budget-only unless the operator has independently enabled/verified driver enforcement**; passing this test must not be described as proof of a universal Docker rootfs quota.

### Manual CI on disposable equipped runners

`.github/workflows/acceptance.yml` provides **Equipped Linux acceptance**, with `qemu`, `docker`, or `both` targets. It runs only by manual `workflow_dispatch`; it is not a hidden image download on every PR. Enable/publish the workflow on your default branch before using the Actions manual-run control. For QEMU, supply the trusted current image checksum. Preflight steps fail if tools/daemon/checksum are missing, rather than treating a skip as an acceptance pass. JUnit output and bounded QEMU phase/failure evidence are retained for seven days; no private keys/disks are uploaded.

**Neither acceptance job nor the existing push/PR checks have been executed remotely during this session.** A workflow definition is not a compatibility result.

## Deployment acceptance checklist

On the actual Codespace or Linux node:

1. Install userspace dependencies and rerun environment + real TCG probes.
2. Verify each selected image URL from that host and pin a trusted vendor checksum.
3. Create a small guest within real host capacity; confirm disk/seed, start it, inspect QMP state and actual serial boot output.
4. Verify cloud-init, the configured SSH user/key, and a real SSH tunnel. Do not confuse QMP “running” with guest readiness.
5. Exercise graceful stop, explicit force-stop, duplicate start prevention, restart, stopped disk growth and deletion on disposable data.
6. For Docker, verify actual cgroups, driver prerequisites, internal network isolation, writable-layer metrics, budget/enforcement labels and lifecycle behavior.
7. If using external nodes, validate certificate trust, bearer-token rejection, capacities/inventory, asynchronous operations and network-partition reconciliation.
8. Keep Codespaces forwarding Private, enable secure cookies for HTTPS, back up SQLite + keys + stopped guest storage, and review OS support lifecycles.

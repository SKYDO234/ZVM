# Validation and compatibility boundaries

## Current SSHX / role-separation revision

Console/WebSSH and the WebSocket/xterm implementation have been removed. Their unchanged uploaded design remains a reference, not deployed code. The current feature is **Generate SSHX inside the selected QEMU VM**, encrypted management keys and output links, admin-only creation/assignment, and the separate `/user` workspace. [Usage and trust boundaries](sshx.md).

### Executed locally

| Check | Result and actual scope |
|---|---|
| Full Python backend/security/regression suite | **317 passed, 4 skipped, 1 warning in 76.78 s**, Python 3.11; the passlib `crypt` deprecation is shown, not hidden |
| Chromium desktop + Pixel 7 emulation | **16 passed in 1.4 minutes**; both ordinary panel flows and SSHX protocol-fixture flows |
| Focused guest/SSH/node/process safety run | **90 passed in 27.86 s** before the additional enrollment/recovery cases incorporated in the full suite |
| Locked npm install / asset build | Passed; **0 npm vulnerabilities**; only the existing Browserslist age notice |
| Ruff undefined/unused-name checks | Passed; rerun with `ruff check --select F .` |
| Guest shell syntax | All four fixed-script modes parsed with `sh -n`, **without executing their contents on the host** |

The four native skips are two opt-in Docker cases, missing local QEMU tools, and the opt-in pinned full-OS boot. **These are not four compatibility passes.** This sandbox has no usable QEMU guest or Docker daemon, and its outbound network cannot reach the OS/SSHX distribution hosts. It never installs SSHX on the panel host or inserts a fake production guest/link.

### What these checks prove

- Hashed passwords, CSRF, session invalidation, role-aware landing pages and the non-blocking initial-password reminder remain connected.
- User creation/review/confirmation is denied on the backend, not merely hidden. Admin requests reserve and enforce the **enabled assignee's plan**, including pending incoming assignments; admin and quota owner are separate.
- Users see only their own assigned instances and guest allocations, not host-wide metrics. They retain owner power, grow-only disk resize, reinstall and deletion.
- Unique management keys are encrypted before queueing and applied only after the runtime proves their public-key generation. Existing-guest enrollment confirms a host key, appends a public key, verifies its actual authentication, and preserves the previous durable key on failed verification/storage transactions.
- Link parsing rejects untrusted origins, malformed fragments, control characters and ambiguous output. Capability URLs/private keys remain encrypted, owner/admin-only, excluded from audit messages, no-store and no-referrer.
- Fresh authority checks reject disablement, reassignment and stale sessions. Shared admission leases impose global/principal/rate bounds across workers.
- Endpoint proof requires the exact managed QEMU process/UUID/disk/network/listener/QMP state and loopback tuple. Negative runtime tests explicitly replace the process boundary and assert no dial.
- Real SSH protocol fixtures exercise key exchange, host pinning, password/encrypted-key parsing, authentication, fixed `sh -s` execution and deadlines. **No fixture executes a shell, OS command, installer or real SSHX client.** It records stdin and returns clearly synthetic output.
- A real local CA/hostname-verified HTTPS/bearer agent fixture forwards those fixed SSH operations. It rejects browser Origins, arbitrary targets/commands, identity mismatch, changed host pins and old node capabilities; private output is not put in agent operation/manifests.
- Process-control tests simulate `/proc`, pidfds and signals with wholly fake OS modules. They cover PID reuse before/after proof, an unrelated process, another VM's client, orphan SSHX, inspection-only behavior, unavailable/denied pidfds and stop timeout. They never signal a host process.
- Reconciliation uses observational evidence, not installer replay. Reinstall recovery requires the pending unique seed-key hash and no incomplete backup. A mismatched engine state cannot falsely retire an access link.

### Browser fixtures versus native acceptance

`tests/ui_server.py` uses its own temporary DB and test-mode provisioning refusal on port 5558. `tests/sshx_ui_server.py` uses another DB and real SSH fixture on 5559; only its QEMU discovery/metrics boundaries are explicitly replaced. Its marked synthetic links never represent a live relay. Browser coverage includes fingerprint/credential-field enrollment, actual new-key SSH authentication, Generate/poll/Details/copy/stop, safe external-link attributes and foreign-owner denial.

These test-only programs are not application demo/fallback modes and are never the production preview. Android is browser emulation, not physical-device certification.

## Reproducing routine checks

```bash
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m compileall -q engines models routes services skvm.py node_agent.py
.venv/bin/python -m ruff check --select F .
.venv/bin/python -m pytest -q -rs
npm ci
npm run build:assets
npx playwright install --with-deps chromium
npm run test:ui
```

CI uses its installed Playwright Chromium. Where an equipped local Chromium is already available, `SKVM_BROWSER_EXECUTABLE_PATH` is a test-only executable override; it does not change guest engine selection.

## Equipped-host acceptance

### Real Ubuntu / QEMU / SSHX

This revision's native SSHX run must pass on an equipped runner before claiming that real feature acceptance. Historical WebSSH CI is not evidence for the replacement. Install native QEMU/cloud-init/OpenSSH tools on a disposable Linux host; do not require KVM or a privileged guest container. Obtain the image checksum using the distribution-provided Ubuntu cloud-image GPG keyring:

```bash
.venv/bin/python scripts/qemu-smoke-test.py
export SKVM_BOOT_IMAGE_SHA256="$(.venv/bin/python scripts/verified-ubuntu-checksum.py)"
SKVM_RUN_OS_BOOT=1 SKVM_USE_KVM=0 .venv/bin/python -m pytest tests/test_qemu_os_boot.py -q -rs
```

The checksum script validates the vendor HTTPS manifest signature against the **distribution** keyring, not a key fetched beside that manifest. No TLS/signature bypass or unpinned image fallback is used.

`test_qemu_os_boot.py` exercises real Flask login/create/review/one-use confirmation, durable jobs and an **actual queue consumer**:

- Independent 10 GiB QCOW2/CIDATA, **TCG**, 768 MiB / 1 vCPU, real QMP then separately verified guest SSH/cloud-init readiness.
- Explicit per-VM outbound internet acknowledgment; actual `curl -sSf https://sshx.io/get | sh` and `sshx` execute **inside that VM only**.
- The actual CLI link is encrypted, shown on Details and never written into test logs/reports. Independently collected guest host fingerprints match the management connection.
- Stop SSHX must preserve an unrelated guest sleep even with a corrupted PID record. After reinstall it also tests an orphaned SSHX client after timeout/PID loss.
- Guest-visible OS/RAM/CPU/disk, data persistence through stop/start/growth to 11 GiB, admin suspension, same-guest reinstall, fresh management key, force stop and deletion.

ACPI shutdown can require up to 180 seconds under TCG; tests do not silently force-kill an unresponsive guest. Optional `SKVM_BOOT_REPORT_DIR` stores bounded phase/result JSON and boot-error tails, never disks/private keys/access links. Native acceptance can take many minutes.

### Docker and TLS-agent lifecycle

Use an already accessible **local Unix** daemon with working memory/CPU controls:

```bash
SKVM_RUN_DOCKER_INTEGRATION=1 .venv/bin/python -m pytest tests/test_docker_integration.py -q -rs
```

Tests check real queued panel creation, 128 MiB / 1 CPU / 128 PID limits, UID 1000, no privileges/host mounts/public ports, owned internal network, actual telemetry and persistent data through lifecycle/deletion. The second case goes through a real TLS/bearer agent and both queue consumers. Direct test-only SDK diagnostics are not a public Console API.

Container disk allocation remains **budget-only** unless a separately verified supported storage driver enforces it. Docker is not a full VM or an SSHX guest.

### Installer and image catalog

The equipped CI workflow runs the actual root installer, fresh verified Node 24 LTS, pip/npm/build/schema setup and real Gunicorn port-31120 default-login/navigation/password/session/restart checks using a disposable DB. The installer is **not** executed on the live development data. It also runs native blank-disk QEMU smoke/integration.

```bash
.venv/bin/python scripts/check-image-catalog.py --report test-results/image-catalog.json --strict
```

All nine retained catalog URLs are range-read and checked for QCOW2 magic. URL/redirect validation remains HTTPS/public-host allowlisted. Endpoint verification is **not** a full boot or support-lifecycle guarantee. Fedora 40 and Debian 11 retain their EOL warnings; only the named Ubuntu full-OS test establishes a boot result.

### CI evidence and history

The push/PR `tests.yml` workflow covers Python 3.11/3.12, browser, actual installer/blank QEMU, pinned full-OS SSHX and Docker/TLS-agent acceptance. `acceptance.yml` also supports manually selected equipped tests. Missing tools/checksum/daemon fail opted-in acceptance rather than producing a skipped success. Artifacts expire after seven days and exclude keys/disks/access links.

The merged **pre-SSHX** PR #3 source `4afd4ec35f6b731451232fadb6cf38c418dce8f3` passed all six jobs in [run 42352860733](https://github.com/SKYDO234/ZVM/actions/runs/42352860733). It validated that historical WebSSH/installer/lifecycle source, **not** this replacement. The first SSHX run [42387903374](https://github.com/SKYDO234/ZVM/actions/runs/42387903374), source `129c219`, passed both backend versions, browser, actual installer/blank QEMU, Docker/TLS-agent and all nine image endpoints, but **failed** the full-OS test before SSHX: unconditional cloud-init package updates exceeded 300 seconds under TCG despite the required tools already being installed. The bootstrap was corrected to check first and install only missing dependencies; a new equipped run is required. This failure is not described as SSHX success. Fresh run identity/results must be recorded separately.

## Deployment limits

- No KVM, physical Android, ARM host, live WAN/reverse-proxy node, every storage driver or all nine OS boots are certified by local protocol tests.
- The node TLS harness uses real certificates/HTTP/SSH but redirects TCP to a loopback fixture, not a deployed external VM. Run actual node/guest acceptance in your own TLS/network arrangement.
- A fresh real Codespaces deployment remains a separate check; Linux installer CI is not proof of that environment or uptime.
- This is a trusted personal/team control plane, not certified hostile public multi-tenant hosting. Guest root can alter its own software/processes or start unrelated tunnels; the managed timeout is not an egress firewall against a malicious guest owner.
- Keep port 31120 Private, use HTTPS/secure cookies, replace `admin/admin123`, isolate internet-enabled guests from host/private services, verify guest prerequisites and keep a separate native SSH recovery credential.
- Back up SQLite, the original encryption/session keys and stopped guest storage together. Do not reset accounts/data to upgrade. Hiding/disabling a panel link is not revocation: stop the actual client/VM.

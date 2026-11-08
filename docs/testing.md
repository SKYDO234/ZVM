# Validation and compatibility boundaries

## Owner lifecycle repair

The current repair keeps ordinary owners' backend permissions and makes their controls usable: observed-state Start/Stop/Restart, visible confirmed Delete on Details/My VPS, one verified graceful-stop-then-delete job, and owner-visible admin-requested power jobs with requester audit attribution. Already-running Start is an engine-verified no-op that does not demand a second allocation or retire a live SSHX link. Neither restart nor deletion proceeds after failed/unproven shutdown; unknown deletion keeps agent metadata and reservations intact.

- Final local Python suite: **366 passed, 4 skipped, 1 warning in 179.37 s**. The four documented native skips are not compatibility passes. Final focused owner/lifecycle suite: **49 passed in 39.00 s**, including failed/unproven shutdown, retained agent metadata, suspended-owner deletion, Docker NotFound cleanup and correct admin failure-audit attribution.
- Desktop/Android browser suite: **18 passed in 2.4 minutes**, including ordinary owner Start/Stop/Restart/Delete, confirmation cancellation, foreign-owner denial, live cross-tab button updates, deleted-resource 404 and no mobile overflow/JavaScript errors. The port-5559 engine/SSH fixtures are explicitly synthetic; they never execute a shell or installer.
- Native QEMU and Docker/TLS-agent tests now create through an admin, assign to a **separate `role=user` account**, then execute owner lifecycle actions and verify job-page/API access. The full-OS test adds owner restart/persistence and deletion of the running guest. **A fresh equipped run is required for these changes; older SSHX runs below do not prove this revised owner flow.**
- Compile, Ruff `F`, JavaScript syntax and diff checks passed. The locked npm asset build has no unrelated vendor/font changes. No production accounts/guests are inserted by the test harnesses.

## Earlier SSHX / role-separation revision

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
| Production preview after final-source restart | Actual Chromium login, eight authenticated pages, non-blocking reminder, removed terminal routes returning 404, desktop and 412 px mobile without overflow or JavaScript errors; existing accounts/data preserved |

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

`tests/ui_server.py` uses its own temporary DB and test-mode provisioning refusal on port 5558. `tests/sshx_ui_server.py` uses another DB and real SSH protocol fixture on 5559, with explicitly replaced QEMU discovery, lifecycle/metrics and capacity boundaries. Its in-memory engine state machine executes no OS commands, and its marked synthetic links never represent a live relay. Browser coverage includes fingerprint/credential-field enrollment, actual new-key SSH authentication, Generate/poll/Details/copy/stop, safe external-link attributes, owner lifecycle controls and foreign-owner denial.

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

**SSHX-base run, before the owner lifecycle repair:** [run 42390315688](https://github.com/SKYDO234/ZVM/actions/runs/42390315688), application/test source `2c874d858a561d0ab2a2ec15b32a90f55099b399`, completed all six jobs successfully. Its full-OS check reported **1 case, 0 failures/errors, 0 skipped**, including actual guest SSHX installation, captured-link display, stop proof and reinstall/orphan checks. This is SSHX rather than historical WebSSH evidence, but it does not establish the newly revised regular-owner lifecycle flow. That repair's final equipped result must be recorded separately above.

To reproduce, install native QEMU/cloud-init/OpenSSH tools on a disposable Linux host; do not require KVM or a privileged guest container. Obtain the image checksum using the distribution-provided Ubuntu cloud-image GPG keyring:

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
- Admin creation/assignment to a separate regular user; owner-visible job page/API, guest-visible OS/RAM/CPU/disk, persistence through owner stop/start/growth to 11 GiB and explicit restart, admin suspension, same-guest owner reinstall, fresh management key, and deletion of the running guest only after verified graceful shutdown. Force stop is separately exercised by native blank-QEMU/Docker tests.

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

**SSHX-base acceptance, before the owner lifecycle repair:** [run 42390315688](https://github.com/SKYDO234/ZVM/actions/runs/42390315688), application/test source **`2c874d858a561d0ab2a2ec15b32a90f55099b399`**, concluded **success** on all six jobs:

| Equipped CI job | Result |
|---|---|
| Backend Python 3.11 | 321 cases, 0 failures/errors, 4 native skips: **317 passed** |
| Backend Python 3.12 | 321 cases, 0 failures/errors, 4 native skips: **317 passed** |
| Browser | **16 passed**, desktop and Android emulation; SSHX sessions remain explicitly synthetic in this job |
| Actual installer / userspace QEMU | Passed complete installer, fresh verified Node, port-31120 production checks and native blank-disk QEMU tests |
| Cloud OS / SSHX | **1 real Ubuntu/TCG case passed, 0 failures/errors, 0 skips**; actual guest installer/client, encrypted/displayed output link, pinned management authentication, wrong-PID/unrelated-process/orphan stop checks, persistence/growth/reinstall/deletion |
| Docker / TLS-agent | **2 native cases passed, 0 failures/errors, 0 skips** |

All **nine catalog endpoints** also passed HTTPS/QCOW2 verification in that run. The full-OS success establishes the named Ubuntu path, not nine successful OS boots. Checks API annotations record `qemu-panel.xml` with one case/no skips, `docker-panel.xml` with two cases/no skips, and both `backend.xml` results; application/test source is identified explicitly so a later documentation-only commit is not mistaken for another native run. No live capability URL/private key is included in this evidence.

**Earlier results, not substituted for current acceptance:** the merged pre-SSHX PR #3 source `4afd4ec35f6b731451232fadb6cf38c418dce8f3` passed all six jobs in [run 42352860733](https://github.com/SKYDO234/ZVM/actions/runs/42352860733). It validated historical WebSSH/installer/lifecycle source, not this replacement. The first SSHX run [42387903374](https://github.com/SKYDO234/ZVM/actions/runs/42387903374), source `129c219`, passed the other five jobs and all nine image endpoints, but **failed** the full-OS test before SSHX: unconditional cloud-init package updates exceeded 300 seconds under TCG despite the required tools already being installed. Source `2c874d8` corrected bootstrap to check first and install only missing dependencies. The subsequent successful run above verifies that correction; the earlier failure remains recorded as a failure.

## Deployment limits

- No KVM, physical Android, ARM host, live WAN/reverse-proxy node, every storage driver or all nine OS boots are certified by local protocol tests.
- The node TLS harness uses real certificates/HTTP/SSH but redirects TCP to a loopback fixture, not a deployed external VM. Run actual node/guest acceptance in your own TLS/network arrangement.
- A fresh real Codespaces deployment remains a separate check; Linux installer CI is not proof of that environment or uptime.
- This is a trusted personal/team control plane, not certified hostile public multi-tenant hosting. Guest root can alter its own software/processes or start unrelated tunnels; the managed timeout is not an egress firewall against a malicious guest owner.
- Keep port 31120 Private, use HTTPS/secure cookies, replace `admin/admin123`, isolate internet-enabled guests from host/private services, verify guest prerequisites and keep a separate native SSH recovery credential.
- Back up SQLite, the original encryption/session keys and stopped guest storage together. Do not reset accounts/data to upgrade. Hiding/disabling a panel link is not revocation: stop the actual client/VM.

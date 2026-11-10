# Validation and compatibility boundaries

## Slow-guest SSH setup / repeated readiness queue repair

- Reproduced **three failures before the fix** using real delayed SSH responses: a valid **11-second greeting** was discarded/requeued, an **11-second authentication** response was incorrectly reported as bad credentials, and a **6-second channel open** was discarded/requeued. All three failed in **28.29 s** against the previous application and pass after repair. The endpoint identity boundary is explicitly replaced; these protocol fixtures never execute a shell/installer or contact a real SSHX relay.
- Setup now waits for actual handshake/authentication completion events within a **shared 40-second** budget, with fresh authority checks. Per-stage ceilings (25-second handshake, 20-second auth, 15-second channel) are clipped to that budget, not summed. A full guest request is capped at **170 seconds**, fitting the **175-second** sensitive-node read budget and existing **180-second** proxy limit. Admission leases use **240 seconds**, including the controller’s preceding capability lookup/TLS/response overhead; global/per-principal concurrency and rate limits are unchanged. The existing 600-second default boot window, 15-second released retry, 130-second command budget, quotas, credential/host-key rejection and no-replay handling after exec are unchanged.
- Details labels released readiness work **Waiting for guest SSH**, not merely Queued, and displays the exact whitelisted stalled stage/attempt. Deadline failure preserves its last stage. No raw banner, key, credential or guest output is placed in progress/error messages.
- **19 additional backend cases** cover delayed valid setup, unanswered key/password authentication, shared setup and total request deadlines, authority revocation during auth, expiry after channel-open but before exec, final-attempt stage retention, whitelisted remote stage handling and real TLS-agent authentication readiness. The existing explicit rejection, identity and uncertain-outcome regressions remain green.
- Final full local Python: **498 passed, 4 native skips, 1 warning in 249.39 s**. Local QEMU binaries/Docker are unavailable, so the native skips are not presented as compatibility passes. Ruff F/compile/JavaScript syntax/diff checks and locked asset build pass.
- Desktop/Pixel 7 browser: **20 passed in 2.9 minutes**, including the new readiness label and exact greeting-stage/attempt message, automatic retry/recovery, real protocol-backed link display/copy/stop and foreign-owner denial. Browser fixtures are explicitly synthetic, not real guests.
- Fresh equipped native acceptance will be recorded separately; the native case now uses the cloud image's existing default **ubuntu** account, matching the reported username, rather than only a freshly created username. It retains immediate Generate after QMP Start/reinstall with no external SSH pre-wait, observed readiness retry and all genuine guest SSHX/lifecycle/persistence checks. Previous equipped run `42603368894` below validates the earlier source, not this follow-up.
- The user's screenshot alone does not prove a permanent boot failure or identify their guest's underlying condition. No access to that deployed Codespace/VM, account reset, guest reinstallation or forced job unlock is claimed. After upgrading both panel/agents, cancel a released old queued request through Recovery or wait for it to finish, then submit a new Generate; uncertain work still requires inspection.

## Previous guest SSH cold-boot readiness repair

- Reproduced the reported early connection-failure path in **two pre-fix regressions**: a refused pre-boot TCP connection and an SSH banner reset. Both incorrectly ended Generate as **Failed**. Their fixtures replace only the QEMU identity boundary, use real SSH KEX/auth/exec on recovery, and never execute a shell/installer or contact a real relay.
- Added **30 readiness regressions** for safe retry, one guest-script submission, preserved keys, released leases/lane fairness, persistent expiry independent of queue age, client TTL independent of boot wait, administrator cancellation, current authority on every attempt, bounded configuration and refusal to retry identity/host-key/auth/installer/unknown outcomes. TLS-agent cases distinguish fixed pre-command handshake/channel readiness rejection from uncertain mutation failure.
- Final full local Python: **479 passed, 4 native skips, 1 warning in 191.42 s**. The corrected 82-case SSH/queue/readiness/TLS subset also passed. The earlier 475-case local suite preceded the channel-open additions. The four native skips remain missing/opt-in Docker and QEMU, not compatibility passes.
- The real Ubuntu/TCG acceptance test has been tightened: it now queues Generate **immediately after QMP Start**, before any external SSH readiness helper, requires an actual Queued boot-readiness observation, and independently verifies the guest host key and real encrypted/displayed client link after generation. Reinstall also generates without an SSH pre-wait. The first fresh run is recorded below; the historical run did pre-wait for guest SSH and is not evidence of this new cold-boot behavior.
- Final desktop/Pixel 7 browser: **20 passed in 2.9 minutes**, including a reset first SSH connection, visible Queued boot-readiness progress, live Running state, dropped status-fetch recovery, completed-link display/copy and Stop. Temporary local Chromium NSS/NSPR libraries were extracted before this successful run; no production dependency/lockfile or authentication-limit change was needed.
- Compile, Ruff `F`, JavaScript syntax, locked asset build and diff checks passed.
- Initial equipped [run 42602161109](https://github.com/SKYDO234/ZVM/actions/runs/42602161109), source `c0488161e2ccc448f6013a763c6b89477e96579d`: both backend versions, browser, actual installer/QEMU and Docker/TLS-agent passed, and all nine OS endpoints verified. **The cold-boot Ubuntu case failed** before sending an exec request: authentication succeeded while channel-open confirmation exceeded its setup timeout. That exposed an additional real boot race hidden by the old SSH pre-wait. A new real-protocol delayed-channel regression reproduced it; the fix only retries channel setup before any command submission. Corrected equipped [run 42603368894](https://github.com/SKYDO234/ZVM/actions/runs/42603368894), exact application/test source **`71f6d8e5f095aec08e8db15b819b2e6fba7670f2`**, completed **SUCCESS on all six jobs**. The tightened Ubuntu/TCG/guest-SSHX case reported **1 case, 0 failures/errors, 0 skipped**: an observed cold-boot readiness retry, real guest-only installation/link capture and encrypted Details display without an external SSH pre-wait, plus owner lifecycle, persistence, reinstall/new-key/orphan-stop verification and deletion. Python 3.11/3.12 each reported **483 cases, 0 failures/errors, 4 native skips = 479 passed**; browser and the actual installer/fresh verified Node/userspace-QEMU checks passed. Native Docker/TLS-agent reported **2 cases, 0 failures/errors, 0 skipped**. All nine retained OS endpoints were HTTPS/QCOW2-verified, not nine boot certifications. Documentation-only follow-ups do not alter this tested application source.
- The actual secure-cookie Gunicorn preview passed login, 17 authenticated routes, the nonblocking reminder, metrics via the browser, 412 px mobile and both elected queue leases. It has no fabricated VPS or native guest; this preview smoke is not a substitute for equipped boot acceptance.
- [Guest readiness troubleshooting and safe upgrade](sshx.md#when-generate-fails-with-cannot-establish-verified-guest-ssh). No database/guest reset, host SSHX installation, arbitrary unlock or automatic installer replay.

## Earlier SSHX queued/running stall repair

- Reproduced **five failing regressions** before the fix: blocking VM-lock claims, SSHX waiting behind unrelated provisioning, a standby abandoning its queue, a new leader incorrectly relabelling live SSHX work, and the unbounded SSH command-acknowledgement wait.
- Final local Python: **446 passed, 4 native skips, 1 warning in 174.39 s**. Additional coverage includes both queue-lane leadership takeovers and retry after a transient consumer-startup failure. Queue tests use real threads/file locks with explicitly mocked engine/guest boundaries; the SSH acknowledgement regression uses a real SSH protocol fixture without executing a shell or installer.
- Final desktop/Pixel 7 browser suite: **20 passed in 2.3 minutes**. The Generate/Stop flow now also injects a dropped status request, verifies live Running/message updates and automatic recovery to the completed link. It reuses the test's real authenticated session rather than weakening the production login rate limit. Browser SSHX links remain explicitly synthetic.
- Compile, Ruff `F`, JavaScript syntax, locked asset build and diff checks passed; no unrelated package-lock/vendor/font changes.
- **All six equipped jobs passed** in [run 42582152859](https://github.com/SKYDO234/ZVM/actions/runs/42582152859), exact application/test source **`30d5af4830986fe6ffa0f433743cf1417a6cd932`**. Python 3.11/3.12 each reported **450 cases, 0 failures/errors, 4 native skips = 446 passed**. Browser and the actual root installer/fresh verified Node/userspace-QEMU checks passed. The actual Ubuntu/TCG/guest-SSHX case reported **1 case, 0 failures/errors, 0 skipped**; it generated the real client link through the new SSHX queue, verified encrypted storage/Details display, stopped the client and continued owner lifecycle/persistence/reinstall/deletion. Native local/TLS-agent Docker reported **2 cases, 0 failures/errors, 0 skipped**. All nine retained OS endpoints were HTTPS/QCOW2-verified, not nine boot certifications. Documentation-only follow-ups do not change this tested source.
- The real Gunicorn preview passed login, 17 authenticated routes, the nonblocking reminder, metrics and 412 px mobile without JavaScript errors/overflow or fabricated VPS. Independent file-lock probes proved both general and SSHX consumers held their actual exclusive leases. This local preview has no native QEMU/Docker or guest-outbound SSHX access; real guest proof comes from the named equipped run, not a local simulation.
- See [queued/running troubleshooting and safe rollout](sshx.md#when-generate-sshx-stays-queued-or-running). No production guest/account reset or force-unlock is part of this fix.

## Earlier blocking-operation recovery and dedicated admin pages

- Final local Python: **439 passed, 4 native skips, 1 warning in 142.47 s**, including default-password access to all nine dedicated admin pages. Compile, Ruff `F`, JavaScript syntax, diff checks and the locked asset build passed. No unrelated vendor/font/manifest changes.
- Browser: **20 passed in 1.9 minutes**. Desktop/Pixel 7 navigation exercises all dedicated admin pages, the default-password reminder, connected account/plan/image/settings forms, owner blocker visibility, administrator-only recovery, confirmation cancellation and live owner-control re-enablement. Browser engine/process/SSH boundaries remain explicitly synthetic and execute no shell/installer; this is not native VM proof.
- **All six equipped jobs passed** in [run 42462999834](https://github.com/SKYDO234/ZVM/actions/runs/42462999834), exact application/test source **`3c0681e09586913ba268827ddaf6c54d3d2d91e2`**. Documentation-only follow-ups do not change that tested source.

| Equipped job | Fresh result |
|---|---|
| Backend Python 3.11 | **439 passed**, 443 cases, 0 failures/errors, 4 native skips |
| Backend Python 3.12 | **439 passed**, 443 cases, 0 failures/errors, 4 native skips |
| Browser | Passed desktop/Pixel 7 suite; the identical local suite contains 20 cases |
| Installer / userspace QEMU | Passed actual root installer, fresh verified Node LTS, real Gunicorn HTTP checks for 17 authenticated routes, connected plan creation, password/session/restart persistence and native blank-QEMU smoke/integration |
| Full OS / SSHX | **1 real Ubuntu/TCG case, 0 failures/errors, 0 skipped**; real running-guest recovery, regular-owner lifecycle/persistence and actual guest-only SSHX |
| Docker / TLS agent | **2 native cases, 0 failures/errors, 0 skipped**; local and verified-TLS agent recovery/lifecycle |

All **nine retained catalog endpoints** passed HTTPS/QCOW2 verification in that same run. The full-OS case proves the named Ubuntu path, not nine successful OS boots or KVM compatibility. Checks API annotations record the one-case `qemu-panel.xml`, two-case `docker-panel.xml`, nine verified OS endpoints and both 443-case `backend.xml` reports.

Native recovery deliberately seeds **interrupted request metadata** while a real guest is running, checks administrator-only non-replaying state inspection locally and over verified TLS, verifies the original request becomes failed/unconfirmed with its guest/allocation retained, then continues actual regular-owner lifecycle/persistence/deletion. This is **not an actual worker-crash test or proof the seeded old Stop ran**. Concurrency, live-worker refusal and authorization changes have separate boundary-controlled regression coverage.

The actual restarted Gunicorn preview on port 31120 passed existing-account login, **17 authenticated routes**, metrics, the non-blocking reminder and 412 px mobile with no overflow/JavaScript errors or fake VPS. The corrected standalone installer HTTP check also passed against a separate disposable DB, including duplicate-start protection, password replacement, session revocation and restart persistence; the existing preview account hashes and VPS count were unchanged. The root installer is never run against the live development database.

The initial [run 42462316220](https://github.com/SKYDO234/ZVM/actions/runs/42462316220), source `af9af483c32b42dd55e570e9839b6a293445ffbd`, passed Docker/TLS-agent, both Python versions and browser but failed an outdated installer-smoke assertion expecting the pre-split `/admin` plan redirect/catalog. That check was updated to `/admin/plans` and all 17 routes; the initial run was cancelled when the follow-up started. It is not substituted for the fresh all-green result above.

See [safe recovery and all page URLs](operations.md). No arbitrary job reset, automatic Force stop, database cleanup script or fake operation success is supplied.

## Earlier owner lifecycle repair

The current repair keeps ordinary owners' backend permissions and makes their controls usable: observed-state Start/Stop/Restart, visible confirmed Delete on Details/My VPS, one verified graceful-stop-then-delete job, and owner-visible admin-requested power jobs with requester audit attribution. Already-running Start is an engine-verified no-op that does not demand a second allocation or retire a live SSHX link. Neither restart nor deletion proceeds after failed/unproven shutdown; unknown deletion keeps agent metadata and reservations intact.

- Final local Python suite: **366 passed, 4 skipped, 1 warning in 179.37 s**. The four documented native skips are not compatibility passes. Final focused owner/lifecycle suite: **49 passed in 39.00 s**, including failed/unproven shutdown, retained agent metadata, suspended-owner deletion, Docker NotFound cleanup and correct admin failure-audit attribution.
- Desktop/Android browser suite: **18 passed in 2.4 minutes**, including ordinary owner Start/Stop/Restart/Delete, confirmation cancellation, foreign-owner denial, live cross-tab button updates, deleted-resource 404 and no mobile overflow/JavaScript errors. The port-5559 engine/SSH fixtures are explicitly synthetic; they never execute a shell or installer.
- **All six equipped CI jobs passed** in [run 42458792864](https://github.com/SKYDO234/ZVM/actions/runs/42458792864), exact application/test source **`4efdf0e3cb797a1110f5f6900a33239af1cdf7cb`**. Native QEMU and Docker/TLS-agent tests create through an admin, assign to a **separate `role=user` account**, then execute owner lifecycle actions and verify job-page/API access. The real Ubuntu/TCG case passed (**1 case, 0 failures/errors, 0 skipped**), including owner restart/persistence, live SSHX preservation on repeated Start, and deletion of the running guest. Local/TLS-agent Docker passed (**2 cases, 0 failures/errors, 0 skipped**), including owner start/stop/restart and running-guest deletion; the local case also verifies explicit force-stop. Python 3.11/3.12, browser and actual installer/userspace-QEMU jobs also passed. Documentation-only follow-ups do not alter this tested application/test source.
- Compile, Ruff `F`, JavaScript syntax and diff checks passed. The locked npm asset build has no unrelated vendor/font changes. No production accounts/guests are inserted by the test harnesses. The actual Gunicorn preview on 31120 passed login, eight authenticated pages, the non-blocking reminder and 412 px mobile checks with no overflow/JavaScript errors; it contains zero fake VPS records and no synthetic engine.

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

**Current equipped acceptance:** [run 42603368894](https://github.com/SKYDO234/ZVM/actions/runs/42603368894), application/test source **`71f6d8e5f095aec08e8db15b819b2e6fba7670f2`**, completed all six jobs successfully. The full-OS check reported **1 case, 0 failures/errors, 0 skipped**. It queues Generate immediately after QMP Start, requires an observed pre-command readiness retry, and proves the actual guest-generated encrypted/displayed link without a separate SSH pre-wait. It also proves read-only closure of deliberately interrupted power-request metadata against the real running guest, admin assignment to a regular owner, owner power/restart/persistence and graceful running-guest deletion, live-link preservation on repeated Start, client stop and reinstall/new-key/orphan recovery. All nine OS catalog endpoints were HTTPS/QCOW2-verified. The earlier `42582152859` run remains historical queue/deadline evidence, not a substitute for this cold-boot test.

To reproduce, install native QEMU/cloud-init/OpenSSH tools on a disposable Linux host; do not require KVM or a privileged guest container. Obtain the image checksum using the distribution-provided Ubuntu cloud-image GPG keyring:

```bash
.venv/bin/python scripts/qemu-smoke-test.py
export SKVM_BOOT_IMAGE_SHA256="$(.venv/bin/python scripts/verified-ubuntu-checksum.py)"
SKVM_RUN_OS_BOOT=1 SKVM_USE_KVM=0 .venv/bin/python -m pytest tests/test_qemu_os_boot.py -q -rs
```

The checksum script validates the vendor HTTPS manifest signature against the **distribution** keyring, not a key fetched beside that manifest. No TLS/signature bypass or unpinned image fallback is used.

`test_qemu_os_boot.py` exercises real Flask login/create/review/one-use confirmation, durable jobs and an **actual queue consumer**:

- Independent 10 GiB QCOW2/CIDATA, **TCG**, 768 MiB / 1 vCPU; Generate is queued immediately after real QMP Start, with a required observed Queued boot-readiness retry. An external SSH helper is used only after successful generation to independently verify the host key and cloud-init; reinstall generation also has no SSH pre-wait.
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

**Current equipped acceptance:** [run 42603368894](https://github.com/SKYDO234/ZVM/actions/runs/42603368894), source `71f6d8e5f095aec08e8db15b819b2e6fba7670f2`, native `docker-panel` check: **2 cases, 0 failures/errors, 0 skipped**. Admin provisioning assigns to a separate regular owner; that owner checks job-page/API access, start/stop/restart and deletion of running containers. Both local and verified-TLS agent cases also seed interrupted request context, deny owner recovery, inspect the actual running container through the administrator route, close the old request as failed/unconfirmed and retain its real allocation before continuing lifecycle.

Tests check real queued panel creation, 128 MiB / 1 CPU / 128 PID limits, UID 1000, no privileges/host mounts/public ports, owned internal network, actual telemetry and persistent data through lifecycle/deletion. The local case also verifies force-stop. The second case goes through a real TLS/bearer agent and both queue consumers. Direct test-only SDK diagnostics are not a public Console API.

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

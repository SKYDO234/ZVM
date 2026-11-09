# SSHX: a terminal inside the selected VM

The former Console, WebSSH pages/APIs and WebSocket transports have been removed. There is no embedded terminal or arbitrary-command endpoint on the panel. The original uploads remain unchanged under `docs/reference/` as historical references only.

## Administrator: create and assign

1. Sign in as an administrator and open **Create VPS**. Select an **enabled owner account**, engine, OS, node and per-instance resources.
2. For SSHX, select a **QEMU VM**. Select **Outbound internet** and explicitly acknowledge its network implications, or leave restricted networking enabled. The global default remains unchanged.
3. Supply the owner's normal guest public key or password. The panel also generates a **unique Ed25519 management key** for this VM. Only its public key enters cloud-init; the private key stays Fernet-encrypted on the panel.
4. Review the **selected owner's plan**, network policy and resources, then confirm. Pending/uncertain creation and incoming assignment jobs reserve the **target owner's** quota, not the requesting administrator's. The worker rechecks the administrator, assigned account, quotas and actual node capacity.
5. A real created instance initially remains **stopped**. Start it, then Generate SSHX. QMP **Running** proves the emulator is running, not that the guest has finished booting; the queued SSHX request now handles bounded SSH readiness waiting automatically.

Normal users cannot access creation/review confirmation or assignment operations. They have a separate **My workspace** at `/user`, listing only their assigned VPS. They retain owner power, resize, reinstall and delete permissions with confirmations and backend ownership checks. Details/My VPS show state-aware power controls and a visible Delete action: deletion of a running VPS requests and verifies graceful shutdown first, without an automatic Force stop. Already-running Start is a verified no-op and preserves its live SSHX link.

An administrator can reassign an existing **stopped QEMU VM** from Advanced controls. The target account must be enabled and have quota. This preserves guest disk data and does **not** rotate its native SSH passwords/keys: review those credentials before transferring a guest between people. The stopped guest cannot retain a running SSHX client. New container ownership is selected at creation; reassignment of existing Docker instances is intentionally not implemented.

## When Generate fails with “Cannot establish verified guest SSH”

That error occurs **before the SSHX installer**: the QEMU process may already be Running while Linux, cloud-init, networking or sshd is still starting. This is particularly common during the first software-emulated TCG boot. The former Generate path made one five-second TCP / ten-second SSH-handshake attempt, so an early click could fail even though the guest would become ready later.

Generate/Stop now retain the **same job** and automatically retry only failures proven to occur **before a guest command**: connection refusal/reset/timeout, an incomplete SSH handshake, command-channel setup failure **before exec submission**, or temporary admission limits. Between attempts the job is **Queued** with “Waiting for guest SSH”, its next-retry interval and remaining boot-readiness budget. A readiness attempt briefly shows **Running**. The execution/VM locks and admission lease are released after a failed pre-command attempt so other eligible VMs can proceed; nothing holds the SSHX worker for the whole boot window.

- Default readiness window: **600 seconds** from the first worker attempt, independent of time spent waiting in the queue. `SKVM_SSHX_READY_SECONDS` accepts **60–900**. Its deadline is retained in the encrypted job context, not reset by another DB session/worker or a changed setting. Each individual connection/handshake remains bounded.
- Automatic retries normally wait **15 seconds**. Existing global/per-user connection and rate limits are unchanged; reaching them defers the request instead of bypassing them. The future client lifetime starts with its actual execution attempt, not with the first failed boot connection.
- **Never boot-retried:** an unproven QEMU endpoint, host-key mismatch, rejected guest credentials, revoked ownership/session, failed installer, potentially submitted command, lost node response or an uncertain outcome. Authentication failure now points to **Repair management access** using the existing guest credential. It does not reset the password or replace the saved key automatically.
- On deadline expiry, the job fails explicitly and confirms **no SSHX guest command was sent by this request**. Check the VM’s actual boot/cloud-init/sshd status and managed forward using your existing native SSH/operator recovery access. After fixing those, Generate again. Do not repeatedly reinstall/reset the VPS or install SSHX on the panel host.
- An administrator can cancel a released **Queued** readiness retry in **Recovery**. Running/uncertain work still cannot be cancelled. Cancelling/hiding a request does not stop an older SSHX client or revoke its copied link.

Update/restart all panel workers and external agents to use this behavior. The authenticated agent returns only fixed pre-command retry codes; HTTP 5xx/network loss/unknown outcomes retain their conservative non-replaying handling. There is no external-node-to-localhost fallback. Existing failed jobs remain failed; after upgrading, submit a new Generate request. Existing **uncertain** jobs still require Recovery inspection or verified VM shutdown.

This wait concerns SSH connection readiness, not a promise that an unsupported/EOL guest finished all optional package setup. A prerequisite, network-policy or installer error remains explicit; see [guest prerequisites](#network-policy-and-prerequisites).

## When Generate SSHX stays queued or running

SSHX Generate/Stop now have their own elected background consumer. A long image download or remote provisioning operation for another VPS no longer occupies that consumer. Standbys keep retrying leadership, and transient consumer-startup failures are retried rather than silently leaving the queue without a worker. An occupied per-VM control lock leaves the request **queued** without blocking the consumer; other eligible VMs can proceed. Live execution locks are not reset or declared interrupted just because another consumer starts.

The guest command has one deadline covering channel setup, command acknowledgement, script submission and output. Paramiko's command-acknowledgement wait is separately bounded to at most ten seconds within that budget; its normal channel socket timeout alone does not bound this wait. A lost acknowledgement is **uncertain**, not proof that the guest did nothing, and the operation is never blindly replayed.

Details updates the actual queued/running/uncertain status and message while polling. A transient failed or hung status fetch is retried; successful completion reloads the Details page to display the real encrypted/stored output link. These changes do not enable restricted networking, waive enrollment/host-key checks, or install SSHX on the panel host.

If requests remain **queued** and the worker was deliberately disabled, check `SKVM_START_WORKER` and the actual panel error log. Use the supported `python skvm.py` or managed Gunicorn entry point, with workers enabled, or run `python skvm.py worker` separately against the **same** configured database/data directory. A plain WSGI factory without the repository's worker hooks does not start a consumer. The fix preserves an explicit operator choice to disable workers; it does not secretly launch host services. Waiting behind live work on the same VM or an admission limit is not permission to clear its lock.

After upgrading, drain/restart **all** old panel workers before using the two queue lanes, and update/restart agents for the bounded guest SSH handling. A pre-existing interrupted job may become **uncertain**, not automatically cancelled. An administrator should use **Recovery → Inspect actual outcome** to recover its original guest operation marker without replaying the installer. If the outcome cannot be proven, stopping the VM through its normal verified shutdown path ends the guest client and settles uncertain SSHX work; no reset/reinstall or arbitrary job deletion is needed. Never forcibly clear a live job lock.

## Owner or administrator: Generate SSHX

Open the selected VPS Details → **SSHX terminal access** → **Generate SSHX**, and confirm the third-party shared-terminal warning.

Over the selected VM's verified SSH connection the application runs:

```sh
curl -sSf https://sshx.io/get | sh
sshx
```

These commands are **never executed on the panel/node host**. The installer is bounded with guest `timeout`; `sshx` is detached in the guest and has its own maximum lifetime. The panel reads the actual client's output, verifies a running managed process, accepts only an `https://sshx.io/s/...#...` URL, encrypts the link, and displays it on **that VPS Details page**. A task failure displays a controlled error rather than a made-up link.

Open/copy the real URL. Links open in a separate tab with `noopener noreferrer` and `referrerpolicy=no-referrer`; responses containing guest data are `Cache-Control: no-store`. A displayed link is a **last-verified result**, not a promise that the external service or client will remain available.

Use **Stop SSHX** to signal only guest processes with this VM’s verified management marker. A fixed guest-side Python helper pins kernel pidfds before rechecking `/proc` identity and signaling, avoiding PID-reuse signals to unrelated processes. It also finds a tagged orphan SSHX client if its timeout/PID record disappeared. Stop/recovery never claims revocation without explicit guest stopped proof. It requests SIGINT so the client can close its upstream session. Regeneration first stops the prior managed client; clearing/hiding a database link alone is never described as revocation. Confirmed VM shutdown, restart, deletion or reinstall invalidates the old stored session. After a lost command response, the job becomes **uncertain**; an administrator can inspect its guest-side operation marker without replaying the installer. Even while an SSHX task is uncertain, Stop/Force stop/Suspend and stop-then-Delete remain available to end the guest and prove the tunnel cannot continue. Uncertain storage/provisioning jobs keep their original stricter reservation rules.

### Treat the URL like a password

Anyone possessing the complete URL can control this guest **outside panel authentication**. Its shell is the provisioned non-root account, which normally has passwordless sudo **inside the VM**. Do not publish URLs in issues, screenshots, CI output or access logs. **Panel logout, password replacement, role changes or disabling an account do not revoke an already copied SSHX link.** Stop SSHX or stop/suspend the guest. Do this before removing a person's guest access.

Each managed client is automatically bounded to **at most one hour** by default. `SKVM_SSHX_MAX_SECONDS` accepts 60–3600; changing it affects newly launched clients, not a previously launched timeout. The panel may hide an expiring link conservatively before its actual client deadline. External service cleanup/availability remains controlled by SSHX.

## Existing VMs: one-time enrollment, no reset

Existing password hashes and public keys cannot be converted back into login credentials. For an existing VM without a management key:

1. Start the guest; open **Enroll existing VM**.
2. Compare its displayed SHA256 SSH host fingerprint through an existing independently trusted connection. For example, inside the guest:
   ```sh
   ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
   ```
   Compare the corresponding RSA/ECDSA key instead if that is what the guest negotiated.
3. Explicitly accept that fingerprint and provide the **existing guest** password or private key/passphrase. This is **not your panel password**. These credentials are used in memory only, never stored in SQLite/session cookies or logged.
4. A fixed, append-only script adds a generated management **public** key to that guest user's `authorized_keys`. Existing keys and passwords remain unchanged. The panel proves authentication with the new key before replacing any saved encrypted management key.

A host-key mismatch aborts **before** guest credentials are sent. For a legitimate out-of-band host-key change, use the same explicit enrollment/verification workflow. A successful panel reinstall installs a fresh management key and clears the previous host-key pin. A failed new-key verification leaves the previous saved key intact. A storage-acknowledgment failure is reported as unconfirmed; refresh/retry with the native guest credential rather than assuming the update failed or resetting the guest. A partial enrollment may leave an additional public key, never a reset of owner authentication. Failed reinstall replacement keeps the previous saved key; interrupted work retains its pending key encrypted until its exact seed generation can be proven during recovery. Enrollment does not reset or reinstall the guest.

Supported enrollment keys are OpenSSH Ed25519/ECDSA/RSA and compatible PEM formats, including encrypted keys. Input is capped at 64 KiB, PEM/private payload at 8 KiB, OpenSSH bcrypt at 256 rounds, and RSA at 8192 bits with a bounded exponent. Excessive KDF work is rejected before decryption.

## Network policy and prerequisites

**Restricted networking remains the default.** It blocks the guest downloads and outbound relay connection SSHX needs. Only an administrator can change an existing VM's network policy, and only while it is stopped. No request silently toggles a global or existing network restriction.

QEMU `restrict=off` allows general outbound connections, **including reachable host/private network services through user networking**. It is not an internet-only firewall. Enable it only for trusted guests, or use an appropriately isolated dedicated external node/network. Do not expose the Docker socket or unauthenticated node services. SSH forwarding itself stays on the node's loopback interface.

The guest needs bash, curl, tar, CA certificates, GNU timeout, setsid/nohup, standard coreutils, **Python 3.9+ and Linux pidfd support (kernel 5.3+)**. Unsupported/inaccessible pidfd control fails explicitly; there is no unsafe raw-PID signaling fallback. Internet-enabled newly created/reinstalled guests check these prerequisites through a fixed cloud-init command. Already-ready images skip package updates; missing prerequisites are installed through the native apt/dnf package manager and verified again. This setup does not install or start SSHX: only Generate does. Wait for cloud-init to finish; unsupported/EOL guest repositories can fail honestly. Existing guests may need prerequisites installed using their native SSH recovery access. The official installer writes `/usr/local/bin`, so the guest account needs its normal passwordless guest sudo. No host privileges or host software installation are substituted when a guest prerequisite is unavailable.

Docker containers deliberately have no injected SSH daemon, management credentials or outbound internet; SSHX is unavailable for them. Their real lifecycle, quotas, persistence and measured cgroup limits are retained.

## External nodes

Update and restart **both** panel and agent. Updated nodes advertise `sshx.protocol_version: 1`. Provisioning a managed-key guest requires the updated agent; an old/missing capability fails explicitly. No panel-localhost fallback exists.

The panel makes a bounded, verified-TLS, bearer-authenticated **HTTPS POST** to `/v1/instances/<uuid>/sshx`. The agent compares the complete managed identity/allocation target, takes its existing per-VM control lock, and runs the same fixed SSH/enrollment code beside its own QEMU guest. The key is sent in memory over TLS, not stored in the agent operation table, manifest or logs. Secret output is returned only over TLS and encrypted on the controller. No WebSocket upgrade/proxy is required. Configure the node proxy with a **180-second** read/send timeout; see [external nodes](external-nodes.md).

Admission is shared across worker processes: at most four guest-control connections globally, two per principal, ten attempts per principal/minute, expiring 180-second leases. SSH handshakes/authentication, command output (64 KiB), command duration and HTTPS response size/read deadlines are bounded. HTTP response-header read timing is not a hard absolute wall-clock guarantee against a malicious slow-drip node; configure only trusted administrator-approved node endpoints. Private Paramiko logging is disabled. Only fixed actions are accepted; browser/node callers cannot supply a host, port, username, arbitrary command, shell flags or installer URL.

## Persistence and upgrading

Back up the panel database **and** its original `data/.encryption-key`, `.session-key`, and appropriate stopped guest storage. Without the original encryption key the panel refuses to decrypt/replace management access silently. Protect the host and its backups: it is the management trust boundary.

Migration is additive: `GuestAccess`, `SSHXSession` and short admission leases are new tables. Accounts, password hashes, guests, keys and disk data are not reset. Unused legacy terminal metadata tables may remain in existing databases; no routes use them. Stop/restart all old panel/agent workers during upgrade so old browser terminals are closed. The installer still installs Node/frontend dependencies, listens on port **31120**, and supports `python skvm.py`. The hashed `admin/admin123` bootstrap and non-blocking password reminder are unchanged.

`SKVM_SSHX_ENABLED=0` disables new guest-control operations; it does **not** terminate an already running guest process. Stop those clients/guests before disabling the feature.

## Third-party trust and verification

The requested installer is mutable third-party software, executed only inside the VM, with the owner's confirmed consent. Its TLS download is not a pinned OS-image verification scheme. Reviewed upstream source: [installer](https://github.com/ekzhang/sshx/blob/3604e8ec5ce0e741bd4a7de2e339b980ca8a2d40/static/get), [client](https://github.com/ekzhang/sshx/blob/3604e8ec5ce0e741bd4a7de2e339b980ca8a2d40/crates/sshx/src/main.rs), [link/session controller](https://github.com/ekzhang/sshx/blob/3604e8ec5ce0e741bd4a7de2e339b980ca8a2d40/crates/sshx/src/controller.rs). The installer fetches the architecture-specific SSHX archive from its upstream S3 distribution. The application never fetches/executes this installer on the management host.

Unit/SSH/TLS protocol fixtures are not guest boots or real SSHX sessions. The equipped, opt-in Ubuntu acceptance test installs/runs the actual client inside its real TCG guest, verifies the returned encrypted/displayed link and guest host key, stops it, then checks a fresh management key and orphan cleanup after reinstall. **The fresh queue/deadline repair passed** in [run 42582152859](https://github.com/SKYDO234/ZVM/actions/runs/42582152859) on application/test source `30d5af4830986fe6ffa0f433743cf1417a6cd932`: one actual Ubuntu/TCG/guest-SSHX case, no failures or skips; all six workflow jobs succeeded. The earlier SSHX-base run `42390315688` remains historical evidence, not a substitute for this repair. See [the exact validation scope and limits](testing.md). The development sandbox still lacks local QEMU/guest-outbound access; no synthetic result is presented as native evidence.

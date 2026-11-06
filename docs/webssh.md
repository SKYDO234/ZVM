# WebSSH: managed guest terminals

The panel's **WebSSH** sidebar item and the **WebSSH** buttons on QEMU instance cards, details and serial-console pages open `/webssh/<instance-uuid>`. The serial console is retained separately; SSH is not a replacement for boot diagnostics.

## Connect

1. Finish provisioning a **real QEMU VM**, start it and wait for the guest SSH service/cloud-init. Open the instance's WebSSH page.
2. Use the **private HTTPS panel URL**. Unencrypted HTTP is accepted only on localhost/loopback for local development. Keep Codespaces port **31120 Private**, set `SKVM_COOKIE_SECURE=1` for HTTPS, and replace the initial panel password in Profile.
3. Select **Connect**, then enter the **guest** password or paste/upload its private key. The username and loopback forward come from the selected VM's managed configuration; they are not editable arbitrary destinations. Your panel login password is not automatically a guest password.
4. On first use, independently compare the displayed **SHA256 host fingerprint**. The serial console is a useful independent path. In the guest, for example:

   ```sh
   ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
   ```

   Use `ssh_host_rsa_key.pub` or the corresponding ECDSA file if the displayed algorithm differs. Then choose **Trust & connect**. The public fingerprint is pinned in SQLite, per instance. **No SSH authentication credentials are sent to the guest before this confirmation.**
5. A changed key is **not silently accepted**. A legitimate reinstall usually generates a new key, but interception can also cause a change. Verify independently, then explicitly acknowledge replacing the saved key. The additional checkbox is mandatory for changed keys.

Password authentication and OpenSSH Ed25519/RSA/ECDSA private keys are supported, including standard AES-256-CTR/CBC encrypted OpenSSH keys. PEM RSA/ECDSA keys (including traditional encrypted PEM) also work. PKCS#8, security-key hardware interaction, SSH-agent forwarding, keyboard-interactive/MFA dialogs, SFTP and browser-specified tunnels are not provided. Use a native SSH client when you need those features.

Key input is capped at **64 KiB**; traditional PEM input and the OpenSSH private payload are each capped at **8 KiB**. OpenSSH bcrypt decryption is limited to **256 rounds**, and OpenSSH RSA keys to **8192 bits** with a bounded exponent. The header is validated before decryption so a malicious key cannot request billions of KDF iterations. Higher-cost keys can still be used with a native client; WebSSH does not modify or weaken them.

## Terminal behavior

- xterm, its fit/web-link addons and JetBrains Mono are **bundled locally**, with licenses. No CDN, Google Fonts, bot token, PIN endpoint or public SSH proxy is required.
- Real full-duplex **WebSockets + SSH PTY** replace the uploaded reference's HTTP polling. UTF-8 stream boundaries, terminal resize and special keys (Ctrl-C, Ctrl-D, Tab, Esc and arrows) are handled.
- **Clear** clears only the browser view. It does not clear guest shell history, stop guest processes or delete files.
- **Disconnect**, leaving/closing the page, or a transport failure closes the SSH channel and its socket; the VM keeps running. Programs that must survive SSH disconnection should use the guest's own `tmux`/`screen` or another appropriate guest process manager.
- Reconnect requires credentials again. There is no automatic reconnect with a cached password or private key.
- **RTT** is a measured round trip between the browser and the WebSSH endpoint (including the node relay, if used). It is **not** an invented/random reading, ICMP ping, guest CPU measurement or external network latency. A missing measurement is shown as `—`.
- Input chunks are limited to **16 KiB UTF-8**, with **128 KiB per browser paste**, bounded input rate and terminal dimensions. A 16-message pending-input queue also bounds input during slow guest SSH handshakes/authentication; overflowing it closes the transport. Slow/non-reading browser or node transports are aborted after a **5-second write deadline**, including close/control frames. Writes are complete and serialized; read timeouts are not shortened. Scrollback is limited to 5,000 lines.
- Default limits: **8 sessions per panel/agent**, **2 per user** (per guest owner on an agent), **10 connection attempts per user per minute**, **10-minute input-idle timeout**, and **1-hour maximum duration**. Transport probes/output do not reset input-idle time. Worker-independent SQLite leases expire after 90 seconds without a heartbeat; lease admission uses a cross-process file lock.

## Authorization and privacy

Every page/upgrade checks panel sign-in and instance ownership or administrator authority. Browser sockets require an exact same-origin `Origin` and a valid session-bound CSRF token in their first message. Tokens and credentials are never placed in WebSocket URLs. Public non-loopback HTTP connections are rejected.

The backend does **not** treat a database port, open TCP port, or manifest alone as proof of guest identity. It verifies the exact live managed QEMU process, its actual `-netdev` loopback-to-guest-22 argument, the TCP listener owned by that process, and running QMP state. It rechecks runtime identity after key exchange and before authentication. There is no host shell, host SSH agent, arbitrary host/username/port, Docker socket, SSH exec-command API or shell-command subprocess in the WebSSH service.

Open sessions recheck fresh database state rather than frozen Flask-Login objects: account disablement/deletion, password/session-version changes, role/ownership changes, VM suspension/deletion/SSH-configuration changes, and node disablement/URL/token changes revoke access. Logout removes that browser session's leases, including terminals in other tabs and Gunicorn workers. Input authority is refreshed at most every 0.5 seconds; idle sockets check every 2 seconds. Revocation cannot recall bytes already delivered to the guest.

Guest passwords/private keys live only in memory; they are not stored in SQLite, files, browser storage, URLs or audit logs. Browser fields and server authentication references are cleared, and upstream SSH/WebSocket wire logging is disabled to avoid recording packet/header secrets. Only connection/trust metadata is audited. The **guest itself** can echo input or record shell history/audits; avoid typing secrets into command lines. Closing/clearing this UI does not erase that guest-side data. Python/browser memory cannot promise forensic zeroization.

## External nodes

Update and restart **both panel and agent**, install the updated Python requirements, and use the WebSocket-capable HTTPS proxy configuration in [external-nodes.md](external-nodes.md). Updated agents advertise `webssh.protocol_version: 1`; older/disabled agents produce an explicit unsupported message. Provisioning protocol version 1 remains backward-compatible; an old agent is not silently assumed to support WebSSH.

The browser connects only to the panel's same-origin WebSocket. The panel opens **WSS over verified TLS** to the node's exact allowlisted HTTPS origin on 443, using the existing bearer header and optional `SKVM_NODE_CA_BUNDLE`. Redirects and environment proxies are not followed/used. Browser cookies and CSRF tokens are **not** forwarded to the agent. The agent refuses browser `Origin` headers and requires its machine bearer before upgrading. The panel sends expected managed identity/allocations; the agent compares them with its trusted local `AgentInstance` and selects its **own** verified QEMU listener.

The agent then makes the guest SSH connection beside the guest and relays the PTY stream. A failed node connection never falls back to the panel's `127.0.0.1`. Remote guest host fingerprints are pinned in the agent database; panel connection metadata remains in the panel database. Node tokens never appear in browser data.

Gunicorn now has **2 workers × 16 threads** for the panel, leaving HTTP capacity alongside bounded terminal sessions. For an agent use at least the documented **16-thread** command. Do not substitute a synchronous one-request worker for long-lived WebSockets.

Set `SKVM_WEBSSH_ENABLED=0` in a panel or agent environment and restart to disable the feature. There is no database reset or existing-account migration required; startup creates only new fingerprint/lease tables.

## Troubleshooting

| Symptom | What to check |
|---|---|
| No instances / disabled Connect | Provision a real QEMU VM. Empty installations have no fabricated destination. Docker has logs/allowlisted diagnostics in Console, not automatically configured managed SSH. |
| Not running / listener cannot be proved | Start the managed VM; check QMP/process identity and same-user process permissions. WebSSH fails closed rather than connecting to a host service. Refresh VM status after starting. |
| Forward exists but handshake times out | The guest may still be booting. Check the serial console, cloud-init, `sshd`, its firewall and guest credentials. A running QEMU process does not prove SSH or the OS is ready. |
| Authentication failed | Use the provisioned non-root guest account's password/key, not your panel credentials. A public-key-provisioned guest may not permit passwords. |
| Key cannot be read | Check the format, passphrase and documented work/size limits; use the matching authorized private key. |
| Host key changed | Verify independently. Do not approve an unexpected change merely to dismiss the warning. |
| Socket cannot open | Refresh for a current CSRF/session cookie; use HTTPS; check VM ownership/availability and HTTP/WebSocket proxy Upgrade settings. |
| Remote node unsupported/unreachable | Update/restart the agent and proxy; verify the exact node allowlist, TLS CA/hostname, token and 443 reachability. Never disable TLS verification or expose raw port 5556. |
| Session closed after inactivity | Reconnect with guest credentials. Idle probes do not extend a terminal indefinitely. |

## Validation boundaries

Local validation on this change: **290 backend tests passed / 4 native tests skipped**, **16 Chromium desktop/Pixel 7-emulation journeys passed**. Real SSH tests cover password/encrypted Ed25519/RSA/ECDSA keys, PTY/resize/Unicode/control input, first/changed fingerprints, failed authentication, owner/Origin/CSRF checks, limits, non-persistence, revocation, actual two-worker Gunicorn, and a real verified-TLS node WebSocket relay (including CA/hostname/bearer/redirect rejection).

Those protocol tests explicitly replace **QEMU endpoint discovery** with a disposable SSH echo/PTY server; they run **no host shell** and do **not** prove an OS guest booted. The dedicated browser SSH test bed uses a separate temporary database and clearly named synthetic protocol-fixture records, never the production database. The real Ubuntu/QEMU opt-in acceptance test additionally exercises unmocked runtime selection, independently checked host fingerprints, guest shell identity, `stty` resize, and explicit changed-key acceptance after reinstall. That test requires an equipped runner and a vendor-pinned image. See [testing.md](testing.md) for results; a local native skip is not a native pass or external WAN/reverse-proxy certification. The equipped WebSSH run on source `724da965` passed all six jobs, including real Ubuntu WebSSH/PTY and changed-key-after-reinstall acceptance; subsequent hardening has its own local results and separate source CI, recorded in that report.

The original user-uploaded HTML is preserved unchanged at `docs/reference/webssh.html` (SHA256 `9686a87be1056b6abf870e6a10cddaa519782f41cfb101061e60d361a85af5eb`). Its layout/controls inform this integrated implementation. Its bot placeholders, token/PIN flow, arbitrary destinations, CDN loaders, nonexistent polling APIs, automatic password config and random latency were deliberately not deployed.

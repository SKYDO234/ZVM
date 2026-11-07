# WebSSH / Console migration notice

The active Console and WebSSH pages, APIs, PTYs, WebSocket relays and xterm assets have been **removed**. The original uploaded `docs/reference/webssh.html` remains unchanged as a historical reference, not an application.

Use [Generate SSHX on VPS Details](sshx.md). The official installer and client run **inside the selected real QEMU VM** over its verified management connection. New guests receive encrypted unique keys; existing guests enroll with their current credential without reset/reinstall. Only administrators create/assign VPS; users have a separate owned-instance workspace.

Upgrade/restart **both** panel and agents, remove obsolete proxy WebSocket configuration, use the [HTTPS node RPC configuration](external-nodes.md), and preserve the database/encryption keys/guest storage. Do not drop old metadata tables to upgrade. `SKVM_WEBSSH_ENABLED` is obsolete; `SKVM_SSHX_ENABLED` controls new guest operations and does **not** revoke existing external SSHX access. Stop the actual client or VM before disabling access.

Earlier WebSSH CI reports validate their named historical source only. [Current validation scope](testing.md).

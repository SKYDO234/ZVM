# Uploaded `n.txt`: provenance, audit, and Python conversion

## Exact source used

- File uploaded by the user: `n.txt`, **42,127 bytes / 1,104 lines**.
- Preserved verbatim at [`reference/n.txt`](reference/n.txt).
- SHA256: `2d1b24f44f3f364d6eada53e04d95a9c9f7395a42250d782da6deaf243638a23`.
- Header: “Enhanced Multi-VM Manager (Pure QEMU Version)”; original in-file attribution to Jishnu / B1 / nobita is retained in the original.
- Read in full (four untruncated sequential sections) before application files were written. The Bash script is **never imported, sourced, executed, or served by a web route**.

## Preserved useful behavior

| Bash feature | Python implementation |
|---|---|
| Nine OS options and default guest usernames | `services/image_manager.py:CATALOG`, persistent `OSImage` model; all nine families retained |
| Dependency checks | `QemuEngine.capabilities`, environment CLI/scripts, UI warnings |
| Pure QEMU / no KVM requirement | TCG default, tested paused-machine probe; explicit and verified KVM opt-in only |
| Download cloud image and size it | Allowlisted HTTPS, live magic verification, bounded download, standalone QCOW2 validation, independent `convert`, grow-only `resize` |
| Per-VM user-data and meta-data | Private per-UUID directory, safe YAML serialization, hashed-password/key authentication, `cloud-localds` seed |
| Memory and virtual CPU settings | Validated `ram_mb`, `vcpus`, `-m`/`-smp`; persistent guest configuration, never host totals |
| SSH host forwarding | Controlled loopback `hostfwd` on a single user-mode network backend |
| Extra forwards | Validated host/guest port pairs on that **same** backend (fixed mismatched IDs) |
| VirtIO disk/network, balloon and RNG | Preserved; TCG uses `-cpu max` for modern x86-64 OS feature compatibility |
| Find/start/stop/delete/info/performance | Exact process identity, QMP state/shutdown, per-instance locks, owner-authorized lifecycle jobs and live metrics |
| Resize VM disk | Stopped-only, quota/capacity checked, growth only; no silent boot-disk replacement |
| Recreate seed / change OS | Explicit stopped-only reinstall with new credentials, old-disk retention until preparation succeeds |
| Config persistence | SQLite guest allocations + mode-0600 JSON manifest/process identity, not shell variables |
| Console mode | Headless guest serial socket/log integrated into the web console |

GTK/OpenGL desktop mode is not carried into a headless Codespaces panel: it depends on graphical host facilities that are not available. Changing a cloud-init seed does not reliably re-run first-boot user provisioning on an already initialized disk; credentials/OS changes therefore use an explicit reinstall instead of pretending a seed rewrite updated the guest. Hostname is derived from the validated instance name. Arbitrary config edits, “remove all lock files”, broad “kill stuck processes”, and disk shrink prompts were intentionally removed as unsafe web features.

## Vulnerabilities/bugs corrected

1. **Executable configurations:** `load_vm_config` used `source "$config_file"`. Bash interpolation in saved unescaped values could become executable code. Python reads JSON/ORM columns and never sources a config.
2. **Credentials:** OS entries had public username=password defaults; configurations, console output, info pages and `chpasswd` exposed plaintext, including a root password. SKVM has no default application/admin password, disables root SSH, accepts SSH keys, hashes guest passwords before persistence, encrypts pending hashes/keys and node secrets, and never audits console text.
3. **Destructive resize fallback:** after `qemu-img resize` failed, `setup_vm_image` deleted the original image and attempted a backing image pointing to the deleted file, falling back to a blank disk. SKVM never replaces a boot disk on a resize error. Original storage is left untouched; shrinking is rejected.
4. **Unsafe process identity:** `pgrep -f "qemu-system.*$vm_name"` and `pkill -f ...` matched names/path substrings (including other instances). SKVM checks exact UUID, exact disk argument, actual executable, PID creation time, QMP, and per-instance locks. Missing identity metadata triggers exact discovery, not broad killing.
5. **False graceful shutdown:** SIGTERM followed by SIGKILL after two seconds is not an OS shutdown. SKVM first uses QMP `system_powerdown`; timeout is reported without escalation. Force stop is explicitly separate.
6. **Lock-file deletion:** deleting “old” or wildcard `.lock` files does not prove a QEMU image is unused. SKVM does not remove image locks or bypass QEMU's native locks. Controller file locks serialize operations; stopped deletion/reinstall also checks open file ownership.
7. **Incorrect forwarding IDs:** Bash used the growing command-array length for separate `-device` and `-netdev` IDs, producing mismatches and unnecessary multiple NICs. SKVM appends validated forwards to a single `net0` backend and checks reserved/bound ports before creation.
8. **Public bind by omission:** `hostfwd=tcp::$SSH_PORT-:22` listens on all interfaces. SKVM explicitly binds `127.0.0.1` and documents SSH tunneling instead of inventing an internet-accessible address.
9. **Shared temporary cloud-init files:** `user-data`/`meta-data` in the working directory could collide across concurrent operations. SKVM uses per-UUID protected directories, safe YAML, and `finally` cleanup.
10. **Blocking process launch:** Bash ran QEMU in the foreground and inferred process state from regexes. SKVM starts independent processes with closed stdin and safe arguments, stores identity, checks monitor readiness, and uses persistent background jobs.
11. **Allocation/host confusion:** `free -h` and `df -h "$IMG_FILE"` were host metrics, not guest RAM/disk capacity. SKVM has distinct allocation, per-instance process/cgroup usage, QCOW2 allocated blocks, and host metrics.
12. **Weak bounds and disk shrink:** numeric validation allowed zero/huge values, unsafe low ports, unvalidated extra forwards, and destructive shrink attempts. SKVM enforces constrained schemas, Linux usernames, real SSH keys, quotas, node capacity, port ranges, storage reserves, and grow-only disks.
13. **Aging images:** no current URL is assumed valid. Debian 13 switches from daily to stable; Fedora 40 uses an archive candidate and an EOL warning. Every image is rechecked from the provisioning host before download. Vendor checksums can be pinned.

## URL verification performed during development

On **2026-11-06**, all nine live range-GET checks initially failed in the supplied sandbox because outbound vendor hosts are not permitted. These failures were recorded as **unavailable**, not verified, and did not create VPS records.

Equipped GitHub Actions runners subsequently performed the actual checks. All **nine HTTPS endpoints returned QCOW2 magic** on application source `c45ded3`:

- The initial Fedora archive candidate returned HTTP 404. Its filename was corrected to `Fedora-Cloud-Base-Generic.x86_64-40-1.14.qcow2`. The exact obsolete factory URL is migrated without overwriting an operator's custom URL or checksum.
- Debian's official redirects required explicit `cdimage.debian.org`, `gemmei.ftp.acc.umu.se`, `laotzu.ftp.acc.umu.se` and `chuangtzu.ftp.acc.umu.se` allowlist entries. Every redirect is still HTTPS/host/public-DNS checked; no wildcard, private-address exception or TLS bypass was introduced.
- Ubuntu 22.04/24.04, Debian 11/12/13, Fedora 40, CentOS Stream 9, AlmaLinux 9 and Rocky Linux 9 retain their original OS identities. EOL warnings remain for the aging releases.

The full Ubuntu 24.04 acceptance also verifies its vendor manifest signature against a distribution-provided cloud-image keyring before accepting the image checksum. It uses real cloud-init, SSH and queued panel lifecycle operations under TCG. Other catalog entries received endpoint checks, **not** full OS boot certification. See [the current execution report](testing.md) for source revisions, reruns and results.

Verification is host/time-specific. The panel and external node recheck selected URLs before downloads, and TLS/format validation without a trusted checksum is not presented as universal publisher-signature verification. The original uploaded reference remains byte-for-byte unchanged.

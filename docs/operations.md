# Admin pages and blocked-operation recovery

The message **“An active or uncertain job already exists for this instance”** is a queue safety check. It does not identify the failed engine action or prove that a worker is dead. Starting another operation, removing a job row, or releasing a storage reservation blindly could race a live mutation or orphan resources.

Details and My VPS now show the **blocking job's type, ID and current status**, with an Open job link when the viewer is authorized. The list and power-button availability refresh from the instance metrics API. Repeating an in-flight power request opens the existing authorized job rather than queuing a duplicate. A different action is explicitly reported as **not queued**; it is not silently substituted with the old operation.

## Separate administrative pages

Every route below requires an enabled authenticated administrator. Ordinary owners retain their separate workspace, authorized job status, and their own power/resize/reinstall/delete controls; hiding navigation is not the authorization boundary.

| Control | Dedicated URL |
|---|---|
| Admin overview / tool shortcuts | `/admin` |
| Users, roles, enabled access and plan assignment | `/admin/users` |
| Instance allocations and management links | `/admin/instances` |
| Resource plans | `/admin/plans` |
| External HTTPS nodes, checks and token rotation | `/admin/nodes` |
| OS catalog, checksums and live URL verification | `/admin/images` |
| Platform / engine policies and limits | `/admin/configuration` |
| Paginated, filterable operation history | `/admin/jobs` |
| Active / uncertain requests and recovery actions | `/admin/recovery` |
| Paginated security audit history | `/admin/audit` |
| Per-VM guest network policy | `/admin/instances/<uuid>/network` |
| Per-VM reassignment | `/admin/instances/<uuid>/ownership` |
| Per-VM administrative suspension | `/admin/instances/<uuid>/suspension` |

Network changes and reassignment still require a stopped, verified QEMU VM. Internet mode needs explicit risk acknowledgement. Reassignment retains the existing disk and native guest credentials, requires credential review, reserves the enabled assignee's quota and rechecks authority in the worker. Docker retains its managed internal network and does not support existing-instance reassignment.

## Resolve a blocked VPS safely

1. Open the blocking job from Details/My VPS. Owners cannot open another principal's legacy job record; that case directs them to an administrator rather than offering a broken/forbidden link. An administrator can select **Jobs & recovery**, optionally filtered by the exact instance UUID.
2. **Queued:** normally wait for the worker. An administrator may confirm **Cancel queued request**. A per-job execution lock and a fresh status check make cancellation mutually exclusive with the worker claiming it. A running or uncertain request cannot be cancelled this way. Cancellation retains the audit/job record, clears the unused encrypted context and never calls the engine. A cancelled create requires a new provisioning review; its old ticket is not reopened.
3. **Running:** follow its real status. There is no force-unlock button. Elapsed time is not proof of exit. On a queue-leader restart, interrupted running work becomes uncertain. Nonblocking recovery refuses a job or instance still held by a worker, even if its DB status is stale.
4. **Uncertain:** select **Inspect actual outcome**. Reconciliation reads owned resource identity, actual state, disk/seed/manifest/limits or authenticated agent operation evidence as appropriate. It never replays the engine mutation. It only applies a proven outcome; missing/incomplete/unreachable evidence retains context and reservations. Current running state alone cannot prove that an interrupted **Restart** occurred.
5. For an interrupted **Start, Stop, Restart or Force stop** with zero new-allocation reservations, an administrator can instead confirm **Close interrupted power request**. This proves the current stable running/stopped state and identity/allocation, checks that no worker owns it, and records the original request as **failed/unconfirmed**, not success. It does not start/stop/restart the guest. The existing VPS, disk and allocation remain. The owner may then submit an appropriate new action.
6. Closing power requests is **not** available for create, delete, disk growth, reinstall, assignment, network-policy or SSHX operations. Those reservations are never released by this shortcut. Restore node access or inspect the actual resource with an operator when the original outcome cannot be proven.

A confirmed shutdown is still required before restart/deletion. There is no implicit Force stop or fallback to deleting a panel row. Other owners' resources are never selected by these actions.

### External agents

The parent cannot close an operation merely because it sees a running guest. It first obtains the authenticated agent's exact operation state. An uncertain agent power request must be inspected/closed **on that agent** under operation, capacity and instance locks; queued/running/completed/unknown work is not guessed failed. A fresh TLS-authenticated instance-state/allocation check is also required before closing the parent request. An offline, incompatible or old agent leaves the parent uncertain. Update/restart **both ends**.

`POST /v1/operations/<uuid>/close-power` is a bearer-authenticated, browser-Origin-rejecting machine endpoint. It accepts no arbitrary target, shell command or reset mode. It only reads the preserved uncertain basic-power context, retains the `AgentInstance`, records failed/unconfirmed state and clears that operation's context after proof. Re-submitting the original request to the agent operation endpoint returns its terminal status; it never re-executes the request. Closing an already-settled request cannot replay it either.

### SSHX capabilities

Inspecting running state is not tunnel revocation. Closing an ambiguous running power request, or reconciling an interrupted Start by observation, hides an unverified old SSHX link as uncertain **without erasing its encrypted capability or claiming the client stopped**. A proven VM shutdown can retire it. To invalidate a copied URL, stop the actual verified client or VM; merely hiding a link or logging out is insufficient. A normal verified no-op Start on an already-running guest still preserves its live link.

## Upgrade without resetting data

Deploy compatible panel/agent source and dependencies; **stop/drain all old worker processes before starting the updated version**. Do not mix old workers with the new queued-cancellation protocol. Do not reset SQLite, guest directories, users, original encryption keys or session keys to remove an error.

For the managed panel, after deploying the source:

```bash
.venv/bin/python scripts/serve-panel.py --stop
bash install.sh --no-start
.venv/bin/python scripts/serve-panel.py --background
```

If graceful panel shutdown is still draining an operation, inspect/wait rather than force-killing or deleting its record. Restart standalone `python skvm.py` or `python node_agent.py` processes through their own terminals/process manager as appropriate. No systemd requirement or privileged container is introduced. Keep forwarded port **31120 Private** and use HTTPS/secure cookies.

## Evidence boundaries

[Testing results](testing.md) identify the exact application/test source. Local regressions mock engine boundaries explicitly; browser fixtures are synthetic and execute no shell or installer. Equipped acceptance separately exercises real QEMU/Docker and verified-TLS agent recovery while deliberately seeding **interrupted request metadata**. That fault-injection check is not a claim that a real worker was crashed or that the seeded old Stop request actually executed. No production guest, account or job is reset by the acceptance fixtures.

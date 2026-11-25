# Privileged helper and authorization protocol

Status: **Step 29B.1 — managed diagnostic probe backend.** A controller CLI signs `CreateLab`
and `ConnectTunnel` and drives the helper's sealed lab and tunnel lifecycle in the Linux runtime;
the helper holds the encrypted WireGuard configs, disables IPv6 and drops DNS transports inside its
labs, resolves a hostname endpoint once and pins it, checks the peer state and the IPv4 addresses,
MTU, rules and routes the kernel reports against the staged config, and stays the source of truth
for lab and tunnel state. A one-shot diagnostic probe (kernel-timed firewall window, unprivileged
worker, handshake check) exists in the backend, not yet reachable over IPC. Windows (WSL2), Linux and macOS (Lima, Keychain) are verified end to
end. No probe or proxy traffic is reachable over IPC yet; the sections from "Typed operations only"
on are partly design.

## Implemented

- Unix-domain socket IPC at `/run/egresslab/helper.sock`, with the `SO_PEERCRED` UID check done
  before anything is read. Other UIDs, root included, are closed without a reply.
- Length-prefixed JSON requests of at most 64 KiB. Unknown fields, nested ones included, and
  trailing content are rejected.
- Read-only `Ping` and `RecoverScan` (the existing `LabRecovery.Scan`).
- Ed25519 capability minting and verification (`internal/helperauth`).
- Each capability is bound to one operation, profile, namespace, target and helper. The target is
  the stage for `ConnectTunnel` and the IPv4 address for `PermitProbe`.
- Short-lived capabilities: 30 seconds at most.
- Cryptographically random 128-bit nonces.
- A random 128-bit helper epoch (the helper ID), generated at every helper start. The operator
  cannot set or reuse one.
- After a restart, capabilities minted for the earlier process are refused, consumed or not.
- Replay protection scoped to the epoch: a process-local replay cache with atomic nonce
  consumption, capped at 4096 live nonces.
- An observed wall-clock rollback permanently disables authorization for the current helper
  process.
- Public-key SHA-256 fingerprints.
- `HelperInfo`, a read-only IPC operation that returns the helper ID, the key fingerprint and the
  runtime ID.
- `AuthorizeCheck`, a dry-run IPC operation.
- Optional root-owned public-key loading in the helper (`-auth-public-key-file`).
- Operator-managed, offline public-key replacement (see "Key replacement").
- Unit tests for signatures, expiry, binding, concurrency, replay, epochs, clock rollback, the
  signing-message golden vectors, `HelperInfo` validation and the key loader.
- Sealed lab lifecycle behind `-enable-lab-lifecycle` (see "Sealed lab lifecycle"):
  - signed `CreateLab`, with helper-generated namespace names;
  - automatic firewall sealing and verification, plus a loopback-only topology check;
  - one namespace per profile, at most eight per helper process;
  - `VerifyLab` and `DeleteLab` with ownership checks;
  - serialized lifecycle operations;
  - rollback, cleanup at normal shutdown, and retention of faulted resources.
- `ListLabs`: the helper's profile-to-namespace registry (bookkeeping only; `VerifyLab` checks the
  kernel).
- The client checks that the production socket is served by root (`SO_PEERCRED`) before it sends
  anything.
- `egresslab-helperctl` covers every helper operation except `AuthorizeCheck`, including
  `stage-info`, `connect-tunnel` and `disconnect`. `create-lab` and `connect-tunnel` read the
  capability from stdin only, never from argv. It refuses to run as root.
- The managed WireGuard vault and `StageInfo` (see "Managed WireGuard vault").
- Signed `ConnectTunnel` and `Disconnect` behind `-enable-tunnel` (see "Signed tunnel lifecycle"),
  on the managed tunnel kernel backend (see "Managed tunnel backend").
- Controller side (see "Controller and runtimes"):
  - an Ed25519 signer for `CreateLab` and `ConnectTunnel`, checked against both golden vectors;
    `ConnectTunnel` is signed only for the profile's own lab in the current helper process and
    the vault's current, compatible stage (see "Controller and runtimes");
  - signing-key storage per platform;
  - runtime providers that reach the helper from each host OS;
  - `egresslab-controller-lab`, which needs `-approve` for every mutation, including
    `connect-tunnel` and `disconnect`;
  - trusted runtimes and persistent profile-to-runtime bindings (see "Trusted runtimes and
    profile bindings").
- A recovery gate and a kernel compatibility check before `CreateLab` (see "Sealed lab
  lifecycle").
- An error code on every refusal (see "Error codes").

## Not implemented

- Automatic trust provisioning. The operator copies the controller's public key to the helper's
  key file; the controller then refuses to sign unless the helper reports that key's
  fingerprint.
- A privileged Desktop API. The controller's HTTP API stays without signing endpoints.
- Linux Secret Service key storage, and the remote runtime (SSH or mTLS).
- Runtime `Start`/`Stop` (they return "not implemented"), and a runtime management UI.
- Open from earlier steps: egress-IP leases across runtimes; a kill-switch independent of the controller; refusing to delete a
  profile that still has runtime resources.
- DNS for applications in the lab (a session resolver, with filesystem and resolver IPC
  isolation, belongs to the worker runtime), DNS refresh or endpoint failover for a running
  tunnel, and IPv6 endpoints. The HTTP controller and the desktop know nothing of labs or tunnels; only the
  lab CLI drives them.
- A controller approval workflow for individual operations.
- Live key rotation and automatic key distribution.
- `PermitProbe` and `RecoverClean` through IPC.
- Persistent lab ownership inside the helper. The controller keeps profile-to-runtime bindings;
  other processes that manage lab namespaces are not coordinated, only refused by the recovery
  gate.
- Per-operation kernel and policy authorization.
- Production privilege hardening: a `CAP_NET_ADMIN`-only helper runtime and systemd.
- A persistent audit log.
- Production route readiness and proxy activation.
- The agent does not call the helper yet.

## Safety boundary

- `AuthorizeCheck` never runs `ip`, `wg`, `nft` or any other network mutation.
- A successful dry-run consumes its nonce. It does not authorize a later operation with the same
  capability.
- A request named `PermitProbe` gets `operation not enabled`, even with a valid capability and
  with every flag set, and the capability stays unused. `ConnectTunnel` and `Disconnect` get the
  same answer unless the helper runs with `-enable-tunnel`.
- A sealed lab is a namespace with a verified default-deny firewall and only `lo`. It is not a
  connected VPN and not a verified egress IP. A `tunnel_configured` lab adds a configured
  WireGuard link and nothing more: no checked handshake, no egress IP, no permitted traffic.
- Every IPC response sets `network_ready=false`, and the client rejects a response that does not.
- `HelperInfo` returns only public metadata. It is not authenticated to the client, so the
  controller compares the fingerprint with its own public key, and never starts trusting a key
  because the helper reports it.
- The controller signs nothing for a profile that lost its unique-IP or kill-switch policy, or
  for a helper reporting another key than the one pinned at `trust-runtime`. It never retries a
  `CreateLab` or `ConnectTunnel`; after an error, `ListLabs` shows what exists.
- A valid signature does not prove IP uniqueness, firewall integrity or route readiness. Those
  must still be verified when an operation runs.

## What is enforced today

- The network agent's HTTP API is read-only. Every route is `GET`, and every other method returns 405
  (`TestAgentHTTPRoutesAreReadOnly`).
- Source files that serve HTTP must not reference lab machinery: namespace manager, firewall,
  VPN lab, vault, lease registry, recovery, or `wg`/`nft` runners
  (`TestHTTPCodeDoesNotReachPrivilegedLabCode`).
- The agent refuses to start as root or with `CAP_NET_ADMIN`, `CAP_NET_RAW` or `CAP_SYS_ADMIN`
  (`RequireUnprivilegedAgent`, `TestCheckAgentPrivileges`).
- The controller still answers `POST /api/v1/endpoints/{id}/start` with `409 ROUTE_NOT_VERIFIED`.
  It treats the agent as healthy only when the agent reports `mode=read-only` and
  `network_ready=false`.
- Privileged changes run from the `egresslab-*-lab` CLIs, which an operator starts with `sudo` in
  a terminal on the VM. The only exceptions are the helper's sealed lab lifecycle, when the helper
  was started with `-enable-lab-lifecycle` and a public key, and its managed tunnel, with
  `-enable-tunnel` as well.
- The helper socket accepts only the configured agent UID. It answers `Ping`, `RecoverScan`,
  `HelperInfo`, the `AuthorizeCheck` dry-run and, with the lifecycle flag, `ListLabs`,
  `CreateLab`, `VerifyLab` and `DeleteLab`, plus `StageInfo` with `-enable-vault` and
  `ConnectTunnel` and `Disconnect` with `-enable-tunnel` (`TestPeerRejection`,
  `TestPeerIdentityAndReadOnlyOperations`, `TestMutationWithValidCapabilityIsRefused`,
  `TestLabLifecycleIPCRefusals`, `TestListLabsRefusals`, `TestStageInfoIPC`, `TestSignedTunnelIPC`,
  `TestTunnelOperationsDisabledWithoutBackend`).

Changing any of these needs the helper below first.

## Process split

| Process | Privileges | Talks to | Never does |
|---|---|---|---|
| Desktop (Tauri) | user | controller (loopback HTTP) | network changes |
| Controller | user | desktop, agent | network changes; holds the signing key |
| Agent | user, no capabilities | controller (loopback HTTP + bearer token), helper (Unix socket) | network changes; reading secrets |
| Helper | `CAP_NET_ADMIN` only (systemd `AmbientCapabilities=`, `NoNewPrivileges=yes`) | agent (Unix socket) | HTTP; running arbitrary commands |

## Transport

- Unix socket at `/run/egresslab/helper.sock`, mode `0660`, group `egresslab`.
  - **Lab bootstrap (Step 22):** the helper runs as root under `sudo egresslab-helper -uid <agent UID>
    -gid <agent GID>`. The socket and `/run/egresslab` (`0750`) belong to `root:<agent's primary
    group>` instead of a dedicated `egresslab` group. The marker directory `/run/egresslab/netns`
    stays `root:root 0700`.
  - The helper never unlinks an existing socket path. After a `SIGKILL` it refuses to start until
    an operator confirms that no helper is running and removes the stale socket by hand. `SIGINT`,
    `SIGTERM` and `SIGHUP` remove the socket on exit.
- On every connection, the helper reads `SO_PEERCRED` and accepts only the agent's configured UID.
  A request from any other UID is closed without a reply.
- One request per connection, framed as length-prefixed JSON (64 KiB maximum). Unknown fields are
  rejected.

## Typed operations only

The helper exposes a fixed set of operations, never a command line:

`CreateLab` (creates and seals), `ConnectTunnel{profile_id, namespace, stage_id}`, `PermitProbe{ipv4}`,
`VerifyLab`, `Disconnect`, `DeleteLab`, `RecoverScan`, `RecoverClean`.

Every argument is validated with the existing patterns: `egresslab-lab-<16 hex>`,
`profile_<16 hex>`, `wgstage_<32 hex>`, and IPv4 literals. Keys never travel over the socket.
`ConnectTunnel` names a stage, and the helper reads that stage from the sealed vault itself.

## Authorization

`CreateLab` and each operation that opens traffic (`ConnectTunnel`, `PermitProbe`) need a
capability that the controller mints. Implemented format, version 1:

```text
claims = {"version":1,
          "intent":{"operation":..., "profile_id":"profile_<16 hex>",
                    "namespace":"egresslab-lab-<16 hex>",  ("" for CreateLab)
                    "stage_id":"wgstage_<32 hex>"          (ConnectTunnel only)
                    "probe_ipv4":"<dotted IPv4>"},          (PermitProbe only)
          "helper_id":"helper_<32 hex>", "nonce":"<32 hex>",
          "issued_at":<unix s>, "not_after":<unix s, at most issued_at + 30>}

message   = "egresslab/helper-capability/v1" || 0x00 || compact JSON of claims, in the field order above
signature = base64url(Ed25519-sign(controller_key, message)), no padding
```

`TestSigningMessageGolden` and `TestCreateLabSigningMessageGolden` pin the exact messages and
signatures for a fixed seed. OpenSSL 3 (`openssl pkeyutl -sign -rawin`) produces the same
signatures, so a non-Go controller can implement the format. A `CreateLab` intent keeps
`"namespace":""` in the signed JSON; dropping the empty field breaks the signature.

- The helper holds only the public key: a root-owned file of 64 hex characters at an absolute
  path. The file and every directory up to `/` must be root-owned, not writable by group or
  others, and not symlinks (so not under `/tmp`). It is provisioned out of band.
- The request carries the intent separately. The helper accepts the capability only when the
  signed intent equals it exactly and `helper_id` matches its own.
- `helper_id` is a random epoch that the helper generates at every start and logs. It cannot be
  configured. The controller reads the current one with `HelperInfo` (through the agent) before
  minting, so a restart invalidates every capability minted for the previous process.
- `HelperInfo` also returns `public_key_sha256`: the lowercase hex SHA-256 of the raw 32-byte
  Ed25519 public key (not of the hex text in the key file).
- The helper keeps a replay cache of nonces until `not_after`, for the current epoch. A
  capability is single-use. Checks that fail before the replay check leave the nonce unused.
- The helper's answer is only `authorization denied`. It does not say which check failed.
- Validity is checked to the second (`issued_at <= now < not_after`) with no clock-skew allowance.
  The controller runs on Windows and the helper in WSL, so their clocks must agree to well under a
  second, or tolerance must be added before the controller mints.
- Clock rollback: if the wall clock reads an earlier second than at a previous signature-valid
  check, authorization stays disabled until the helper restarts. Nonces are pruned only at times
  the helper has recorded, so a pruned nonce can never be accepted again. The guard sees only
  times it observed: an unused capability can still look valid again if the clock steps back
  with no check in between.
- The clock fault is silent. The client gets `authorization denied`, `HelperInfo` still reports
  `authorization_configured: true`, and nothing is logged. On WSL, a backward time correction that
  crosses a second boundary between two checks triggers it; restart the helper.
- The controller mints a capability only after the desktop user confirms the action, and only
  when the profile passes its invariants (unique IP, kill-switch). The lab CLI checks the
  invariants and requires `-approve`; a desktop confirmation flow is not implemented.

Operations that only read or remove (`VerifyLab`, `Disconnect`, `DeleteLab`) need just the peer
UID check, and refuse a capability if one is attached. This keeps cleanup possible even when the
controller is down.

### Key replacement

Rotation is offline and operator-managed:

1. Stop the helper.
2. Provision the new trusted public key file (root-owned, as above).
3. Start the helper. It generates a new epoch, and `HelperInfo` reports the new fingerprint.
4. The controller signs nothing for a fingerprint other than the one pinned at `trust-runtime`
   (`RUNTIME_UNTRUSTED`). After replacing the controller key, run `-approve trust-runtime` again:
   it pins the new fingerprint, only if the helper reports the controller's own key, and keeps
   the profile bindings.

The controller must not trust a new key only because the helper reports a new fingerprint. Live
rotation, automatic key distribution and production private-key management are not implemented.

## Sealed lab lifecycle

| `-auth-public-key-file` | `-enable-lab-lifecycle` | Helper mode |
|---|---|---|
| no | no | read-only |
| yes | no | read-only + `AuthorizeCheck` dry-run |
| no | yes | refuses to start |
| yes | yes | signed sealed lab lifecycle |

`-enable-vault` and `-enable-tunnel` build on the last row (see "Managed WireGuard vault" and
"Signed tunnel lifecycle").

`CreateLab` creates a namespace with a generated name and an ownership marker. It checks that only
`lo` exists, installs the sealed firewall, reads it back against both the session baseline and the
intended policy, then disables IPv6 in the namespace (see "IPv6 isolation"). The capability is consumed just
before the kernel work starts. Refusals for a duplicate profile, a full helper (8 labs) or a busy
helper leave it unused.

- **Seal fails:** the helper deletes the namespace. If that fails too, the lab stays tracked as
  faulted and creation is blocked for the rest of the process.
- **Create fails:** creation is blocked as well, because the kernel state may be uncertain. Later
  creates get `STATE_UNCERTAIN`; check `egresslab-lab-recover`, then restart the helper.
- **`VerifyLab`** re-reads the topology, the firewall (session baseline and intended policy) and
  the IPv6 switches. Any difference marks the lab faulted. It never repairs, and a faulted lab is
  never restored; only `DeleteLab` clears it.
- **`DeleteLab`** refuses a namespace that holds any device besides `lo` or has processes, and
  leaves it for inspection. A namespace removed outside the helper is released.
- **Normal shutdown** (`SIGINT`, `SIGTERM`, `SIGHUP`) waits for a running operation, then deletes
  every lab it safely can. After a `SIGKILL` or crash, the labs and their markers remain;
  `egresslab-lab-recover` reports them as orphans, and `-delete` removes them.

Ownership lives in memory only. If a `CreateLab` response is lost, `ListLabs` shows the namespace,
and `DeleteLab` removes it.

**IPv6 isolation (Step 28A).** The lab firewall already drops IPv6 outside loopback; the kernel's
per-interface switch adds an independent layer. `disable_ipv6=1` removes an interface's IPv6
addresses and routes and refuses new ones. `conf/all` says nothing about existing interfaces, so
each switch is set and read on its own, always inside the lab (`ip netns exec <lab>
/usr/sbin/sysctl`, the binary from the fixed system directories):

| When | Written | Read back (each must be exactly `1`) |
|---|---|---|
| `CreateLab`, after the firewall is sealed and matches the intended policy | `default`, `lo` | `default`, `lo` |
| `ConnectTunnel`, before the endpoint is resolved | nothing | `default`, `lo` |
| `ConnectTunnel`, once the link is `wg0` in the lab (still down, no peer) | `wg0` | `default`, `lo`, `wg0` |
| Before the peer, after the connect, and at every `VerifyLab` with a tunnel | nothing | `default`, `lo`, `wg0` |
| `VerifyLab` without a tunnel | nothing | `default`, `lo` |

A failed write, a failed or unexpected readback, or any value other than `1` refuses: a seal
fails (the helper deletes the namespace), a connect is rolled back before any peer exists, and a
`VerifyLab` faults the lab and removes its tunnel. Drift is never repaired, and `DeleteLab` does
not depend on this check. Only lab namespaces are touched: the VM namespace and the host keep
their own settings. On Linux 6.8 a link moved into a lab already inherits `disable_ipv6=1` from
`default`; the explicit write and readback do not rely on that. A kernel booted without IPv6
(`ipv6.disable=1`) has none of these switches, so sealing should fail there (not tested). Not
yet run on WSL2. Verified on Lima (Linux
6.8, procps-ng 4.0.4): the lab showed no IPv6 address or route with `lo` and `wg0` up (the
`ff00::/8` route on `wg0` is gone), the handshake still completed, the VM's own switches stayed
`0`, and re-enabling IPv6 on `lo` (sealed lab) or `wg0` (tunnel) faulted the lab without being
repaired.

**DNS deny policy (Step 28B).** The seal puts every drop ahead of the loopback accepts, and every
permit added later (by the lab CLIs) comes after all of them:

| Chain | Rules, in order (policy `drop`) |
|---|---|
| `input` | `meta nfproto ipv6 drop`, `iifname "lo" accept` |
| `output` | `meta nfproto ipv6 drop`, `udp dport 53 drop`, `tcp dport 53 drop`, `tcp dport 853 drop`, `udp dport 853 drop`, `oifname "lo" accept` |
| `forward` | none |

Before this step the loopback accepts came first, so a query to a resolver on `127.0.0.1` would
have passed once loopback was up. Reproduced on Linux 6.8 with `lo` up in a scratch namespace:
with the earlier order, UDP and TCP to `127.0.0.1` on 53 and 853 were delivered; with this order
all four are dropped, while other loopback ports still pass. The intended policy
(`sealed_policy.go`) pins the exact rules and their order, so a missing drop, a loopback accept
moved forward, an extra rule or an accept policy is `FIREWALL_DRIFT`; the earlier seal (the real
capture `testdata/nft-lab-sealed.json`) is now refused too. The drops match standard ports only:
DNS over HTTPS (443) and DNS on other ports stay closed by the drop policy alone, so a later
permit for 443 (Step 29) must name its destination. No DNS rule is added in the VM namespace,
where bootstrap DNS (see "Endpoint resolution") and the underlay must keep working.

The diagnostic probe client (`FetchEgressTrace`, used by `egresslab-vpn-lab`) dials through
`pinnedProbeDial`: only the pinned IPv4 address, TCP port 443, as `tcp4`; any other host, port,
network or address family is refused before a dial, and no hostname ever reaches a resolver. It
takes no proxy from the environment, follows no redirect and keeps no connection; TLS
verification is unchanged. Traced on Lima with `strace`: one `connect` to `1.1.1.1:443`, no
`resolv.conf`, `nsswitch.conf` or `/etc/hosts` opened, and a hostname URL made no connection.

Resolver boundaries: no `/etc/netns/<lab>/resolv.conf` is written. A namespace-specific
`resolv.conf` does not stop an NSS backend from handing a lookup to a resolver daemon over IPC, so
filesystem, process and socket isolation belong to the future worker launcher, as does the
session resolver: it will run in the VPN namespace, only once the tunnel is verified, and never
fall back to the bootstrap resolver. Verified on Lima with the real tunnel up: the chains read as
above, `VerifyLab` stayed `tunnel_configured`, and UDP/TCP 53 and 853 to `1.1.1.1` from inside
the lab were all blocked; the cycle through `Disconnect`, `VerifyLab` and `DeleteLab` passed.
Not yet run on WSL2.

**Probe window (Step 29A).** `PermitEgressProbe` of the legacy VPN lab adds permanent accepts: a
crash after it leaves them in place. The managed tunnel will instead open a window whose lifetime
the kernel enforces. `withManagedProbeWindowLocked` (an internal primitive; no IPC operation calls
it yet) applies one transaction:

```text
add set inet egresslab_lab egresslab_probe4 { type ipv4_addr; flags timeout; size 1; }
add element inet egresslab_lab egresslab_probe4 { 1.1.1.1 timeout 30s }
add rule inet egresslab_lab output oifname "wg0" ip daddr @egresslab_probe4 tcp dport 443 accept
add rule inet egresslab_lab input iifname "wg0" ip saddr @egresslab_probe4 tcp sport 443 ct state established accept
```

Both permits match through the same set, so when the element expires neither direction matches
any more, even with the helper gone; no general `ct state established` rule exists. The permits
come after every sealed rule, so the IPv6 and DNS drops still win.

- **Before opening**, the seal must match both the session baseline and the intended policy.
- **After opening, and again when the probe returns**, the readback must be exactly the seal plus
  the set (one element, `1.1.1.1`, timeout 30, time left) and the two permits, each last in its
  chain. Any other destination, interface, port, lifetime, element, set, flag or rule refuses.
- **The probe callback** gets its own 12 s deadline; the kernel's 30 s bounds the permission.
- **Closing** always runs, with its own context, even after a failed probe: it deletes the two
  permits by the handles just verified and the set, in one transaction, then requires the sealed
  policy again. An expired set (the kernel then lists no element) can still be closed. If the
  close cannot be confirmed, the namespace is marked drifted and the error carries
  `ErrProbeCleanup`; the caller (Step 29B) must then fault the tunnel and discard any result.
- The window is never recorded as a session script or in the baseline, so a later `Reconcile`
  cannot bring it back.

The JSON is pinned to real captures (nft 1.0.9, Linux 6.8): `testdata/nft-lab-probe-window.json`
(one second after opening) and `nft-lab-probe-expired.json`. nft 1.0.9 prints set membership with
`"=="` and lists no `elem` once the element has expired; another rendering is refused. Verified on
Lima in two scratch namespaces joined by a veth named `wg0`, with `1.1.1.1` held by the peer (no
Internet traffic): with the seal alone nothing passed; with the window open only `1.1.1.1:443`
passed (not port 8443, not another address); after 30 s everything was blocked, including a
connection opened inside the window; the close by handle left exactly the sealed ruleset. Not yet
run on WSL2.

**Diagnostic probe (Step 29B.1).** `ManagedTunnelBackend.ProbeConfigured` makes one observation of
the tunnel's public IPv4 address. It runs only on a backend built with
`NewManagedProbeTunnelBackend` (the helper still uses the probe-less constructor, and no IPC
operation reaches it yet), under the namespace manager's lock:

1. The whole tunnel state verifies (`VerifyConfigured`), and `ip netns pids` lists no process in
   the lab: nothing may share the window.
2. The probe window opens (see above), and the worker runs inside it with a 12 s deadline.
3. The window closes. Then the lab must again hold no process (the worker is gone), the tunnel
   state must verify, and `wg show wg0 latest-handshakes` must report exactly the staged peer with
   a handshake at most 180 s old, not zero and not in the future.
4. Only then is `{ipv4, observed_at, handshake_at, source: "cloudflare_trace", network_ready:
   false}` returned. The address passes the same public-IPv4 policy as every egress candidate.

No handshake is required before the probe: the request itself may trigger it. The 180 s bound is
a freshness policy, not proof that the handshake served this request. Once an attempt starts, any
failure (a foreign process, drift, an HTTPS error, a private address, a missing or stale
handshake, an unconfirmed window close) discards the result, faults the tunnel and removes it; if
that removal cannot be proven, the tunnel stays tracked as uncertain. A refusal before the attempt
(no runner, another namespace, a cancelled request) changes nothing. The observation is not a
lease and opens nothing.

The worker is `/usr/local/bin/egresslab-probe`, a separate executable: no HTTP client runs in the
root helper. The helper checks that it is a root-owned regular executable without setuid or
setgid, in directories that only root can write, then runs `ip netns exec <lab> setpriv
--reuid=<uid> --regid=<gid> --clear-groups --inh-caps=-all --ambient-caps=-all
--bounding-set=-all --no-new-privs -- /usr/local/bin/egresslab-probe` with a fixed minimal
environment (no proxy, TLS, HOME or loader variables). The worker takes no arguments, refuses to
run as root, with supplementary groups, with any capability set or without no_new_privs, and then
fetches only `https://1.1.1.1/cdn-cgi/trace` through the pinned numeric dialer (Step 28B), with
TLS verification. Its output is capped at 4 KiB and its stderr is discarded. It runs as a
dedicated system user (`egresslab-probe`), not the agent's UID.

Verified on Lima with the real Proton tunnel: the worker refused root, an undropped user and an
argument; the `setpriv` command left all capability sets empty with `NoNewPrivs: 1`; and through
`ProbeConfigured` the observed address was the provider's exit IPv4, with a handshake 1 to 3 s
old, the window gone and the tunnel still verifying afterwards. A process left in the lab refused
the probe and removed the tunnel. The first call with the production runner failed and, as
designed, removed the tunnel; its cause is unknown, because the worker collapses its errors and
the runner discards its stderr. It did not recur: 37 later probes succeeded (two with the
production runner, the others with a temporary build that also reported the worker's error), and
the results of 8 more were not captured. Under the current policy a transient failure costs a
full reconnect. Not yet run on WSL2.

**Recovery gate.** Before consuming a capability, `CreateLab` scans with the helper's own namespace
manager. Any lab resource this helper does not own refuses creation with `RECOVERY_REQUIRED`: a
crashed session's orphans, another live process's labs, unmarked namespaces, stale markers and
underlay tables. The gate never cleans. The helper logs the leftovers at startup. Way out:
`egresslab-lab-recover -delete` for orphans and stale markers; stopping the other process; or
inspecting and removing the rest by hand. `ListLabs`, `VerifyLab` and `DeleteLab` stay available.

**Kernel check.** If a tunnel module is loaded, the kernel adds fallback devices (`tunl0`, `gre0`,
`gretap0`, `erspan0`, `sit0`, `ip6tnl0`, `ip6gre0`, ...) to every new namespace while
`net.core.fb_tunnels_only_for_init_net` is 0, its default. `1` keeps them in the initial namespace
only, and `2` creates none (kernel sysctl documentation). The helper reads both and refuses
`-enable-lab-lifecycle` with `KERNEL_INCOMPATIBLE`; it re-checks before each `CreateLab`. It never
sets the sysctl or loads or unloads modules, and the lo-only rule stays strict. The incompatible
path is unit-tested only; the tested WSL kernel loads no tunnel modules.

### Error codes

Every refusal carries a `code`. Clients act on it; the message is for people. On failure,
`egresslab-helperctl` exits 1 and still prints the response, with its code, on stdout.

| Code | Meaning |
|---|---|
| `AUTHORIZATION_DENIED` | capability refused; the check that failed is not disclosed |
| `OPERATION_DISABLED` | not enabled on this helper (no key; no lifecycle, vault or tunnel flag; always for `PermitProbe`) |
| `RUNTIME_UNAVAILABLE` | helper unreachable, shutting down, or not served by root |
| `INVALID_REQUEST` | malformed frame, version, fields or arguments |
| `LAB_BUSY` | another lab operation is running, or the managed tunnel slot is held (until `Disconnect` or `DeleteLab`; not worth retrying) |
| `LAB_NOT_FOUND` / `LAB_EXISTS` / `LAB_LIMIT` | no lab for the profile / one already / 8 reached |
| `OWNERSHIP_MISMATCH` | the profile's lab is another namespace |
| `FIREWALL_DRIFT` / `LAB_FAULTED` | the lab no longer matches (firewall / topology, or already faulted); delete it |
| `RECOVERY_REQUIRED` | leftover lab resources block creation |
| `KERNEL_INCOMPATIBLE` | new namespaces would get extra devices |
| `STATE_UNCERTAIN` | a create, tunnel connect or cleanup may have left kernel state behind; delete the lab, or check recovery and restart the helper |
| `STAGE_NOT_FOUND` | the vault holds no such stage for the profile (`StageInfo`, `ConnectTunnel`); the lab is untouched |
| `INTERNAL` | anything else; details are in the helper log |

The controller adds `RUNTIME_UNTRUSTED`, and reports a `CreateLab` or `ConnectTunnel` that failed
without a definite refusal as `STATE_UNCERTAIN`.

## Controller and runtimes

The desktop and the controller run on Windows, macOS and Linux; the network runtime is always
Linux. `egresslab-controller-lab` reaches it through a runtime provider. Every provider runs
`/usr/local/bin/egresslab-helperctl` inside the runtime as the normal user, so the private key
never enters Linux and only the signed capability crosses, on stdin.

| Host | Runtime (`-runtime`) | Signing-key storage | Tested |
|---|---|---|---|
| Windows | `wsl` (`wsl.exe --exec`) | DPAPI, current user (`controller-signing.dpapi`) | yes, end to end |
| Linux | `native` (direct exec) | file, mode 0600 (`controller-signing.key`) | yes, end to end |
| macOS | `lima` (`limactl shell`) | login Keychain (`security`) | yes, end to end (macOS 15.3.2, Lima 2.3.0) |
| any | `remote` | — | not implemented |

`-runtime auto` picks by host OS. The key sits in the controller data directory
(`EGRESSLAB_DATA_DIR`, default `<user config dir>/EgressLab`), next to `state.json`. The
controller signs only for a profile that exists in `state.json`, and fetches the helper epoch
right before each signature.

- **DPAPI** protects the key against other Windows accounts and copies of the disk, not against
  programs running as the same user.
- **The Linux file key** is protected by Unix permissions only. A Secret Service backend is not
  implemented.
- **The macOS key** is a generic password in the login Keychain (service
  `dev.egresslab.controller-signing`, one account per data directory), written through
  `security -i` on stdin, never in argv. It protects the key against other macOS accounts, not
  against programs running as the same user. Only an unlocked Keychain has been tested.
- **Lima:** `limactl shell` forwards stdin, which `create-lab` and `connect-tunnel` need
  (verified with Lima 2.3.0). The command line reaches the guest through ssh, so the transport
  passes only plain tokens.
- **Clocks:** the Windows controller mints with the Windows clock, and the helper checks with
  the WSL clock. With no skew allowance, a WSL clock behind Windows across a second boundary
  refuses a fresh capability.

### Tunnels from the controller

`egresslab-controller-lab` adds `stage-info PROFILE_ID`, `-approve connect-tunnel PROFILE_ID
NAMESPACE STAGE_ID` and `-approve disconnect PROFILE_ID NAMESPACE`; `verify-lab` and `list-labs`
show `tunnel_configured`. The same transport serves WSL2, Lima and native Linux. Before signing a
`ConnectTunnel`, the controller requires, in this order:

1. a trusted runtime whose helper reports the pinned runtime ID and public-key fingerprint (also
   required for `CreateLab` and `stage-info`);
2. the profile's binding to that runtime, naming this namespace and the current helper epoch;
3. the stage the operator named to be the vault's current stage for the profile
   (`STAGE_NOT_FOUND` otherwise), and compatible (`INVALID_REQUEST` otherwise, so the helper never
   faults the lab on it);
4. a fresh `VerifyLab` answering `sealed` (`LAB_BUSY` if the lab already has a tunnel).

The capability then binds profile, namespace, stage and helper epoch, for 30 seconds. A
`ConnectTunnel` without a definite answer is reported as `STATE_UNCERTAIN` and never retried;
`LAB_BUSY` is not retried either. `disconnect`, `verify-lab` and `delete-lab` need no signing
key, so a broken key store cannot strand a tunnel. `runtimes.json` keeps ownership only: the
tunnel state is read from the helper, and `RoutingProfile.Status` stays `unconfigured`.

### Trusted runtimes and profile bindings

The helper reports a **runtime ID**: `runtime_` plus 128 bits of HMAC-SHA256 keyed with
`/etc/machine-id`, so the raw machine ID is never disclosed. It names the Linux installation: it
is stable across helper restarts and differs between installations that hold the same public
key. Images cloned from one installation share it. One installation reached two ways (WSL and
native) reports the same ID. A missing machine ID means no runtime ID, and no trust.

The controller lab CLI keeps `runtimes.json` next to `state.json`:

- **`trust-runtime`** (with `-approve`) pins the reported runtime ID to the provider and target it
  was reached through. It requires a named WSL distribution, because the default can change, and a
  helper that holds this controller's key, whose fingerprint it pins too. Lab commands refuse an
  untrusted target, or one that now answers with another ID, with `RUNTIME_UNTRUSTED`; signing
  commands (`create-lab`, `connect-tunnel`, and `stage-info`) also refuse a helper that reports
  another key. Trusting again after a controller key replacement pins the new key and keeps the
  bindings.
- **A profile is bound to one runtime for good**, from its first `create-lab`. The binding is saved
  before the kernel changes, so an uncertain result can only be a lab on that runtime.
- **The lab record** (namespace and helper epoch) is valid only while that helper process runs. A
  record from an earlier epoch is stale: a normal stop deleted that lab, and the recovery gate
  covers a crash. So a restart never strands a profile.
- **`verify-lab`, `disconnect` and `delete-lab`** never depend on the controller's record: without
  a current one (or without any binding, for example after `untrust-runtime`), the helper's
  registry decides, and `verify-lab` writes the record back.
- **`unbind-profile`** releases a profile once its runtime owns no lab for it. **`untrust-runtime`**
  removes a runtime that is gone, with its bindings. Labs inside it are not touched.

Concurrent lab CLI runs are not coordinated. The HTTP controller does not read `runtimes.json`
yet.

## Managed WireGuard vault

The helper can hold one encrypted WireGuard config per profile, inside the Linux runtime:

| Path | Content |
|---|---|
| `/etc/egresslab/vault/wg-vault.key` | AES-256 key, root `0600` |
| `/var/lib/egresslab/vault/wg-vault.json` | configs encrypted with AES-256-GCM, bound to profile and stage IDs |
| `/var/lib/egresslab/vault/vault.lock` | exclusive `flock` |
| `/var/lib/egresslab/vault/import.conf` | plaintext import slot, consumed by a successful `vault-stage` |

- Both directories must be root-owned `0700`, and no directory above them may be writable by
  anyone but root or be a symlink. Vault files must be root-owned, regular, `0600` and have one
  link. The paths are fixed; no client can make the helper open a path.
- The offline commands `egresslab-helper vault-init`, `vault-stage PROFILE_ID` and
  `vault-revoke PROFILE_ID` run as root and are never reachable through the socket. `vault-init`
  never replaces a key. `vault-stage` reads `import.conf`, prints only the stage metadata, and
  removes the plaintext file on success (kept on failure, for the operator to fix). Staging again
  gives a new stage ID and replaces the old stage.
- A helper started with `-enable-vault` (it requires `-enable-lab-lifecycle` and a public key)
  holds the vault lock for its lifetime, so the offline commands refuse with "vault is in use".
  The kernel releases the lock when the helper exits, crash included; never delete
  `vault.lock` to get around it.
- `StageInfo` (`egresslab-helperctl stage-info PROFILE_ID`) returns the profile ID, stage ID and
  `vpn_lab_compatible`, nothing else: no endpoint, key or config crosses the socket. For the
  helper the field means compatible with the managed tunnel (the import summary's
  `managed_vpn_compatible`, which accepts DNS names); it keeps its name for the controller. It is
  a static check: `StageInfo` never resolves anything.
- Internally, a config is lent only for the exact profile and current stage ID, under the vault's
  read lock, and only if it is compatible. A replaced or revoked stage cannot be selected.
- A stage is used only by `ConnectTunnel` on a helper with `-enable-tunnel` (see "Signed tunnel
  lifecycle"). `PermitProbe` stays disabled and `network_ready` stays false.

Nothing stops the legacy `egresslab-wg-vault-lab` from opening these paths without the lock: do
not point it at the managed vault. The vault protects configs at rest, not against root in the
runtime.

## Signed tunnel lifecycle

A helper started with `-enable-tunnel` (it requires `-enable-vault`, and so the lab lifecycle and
a public key, plus a runtime ID) adds two operations on an existing lab:

| Operation | Authorization | Result |
|---|---|---|
| `ConnectTunnel{profile_id, namespace, stage_id}` | a capability signed for exactly that profile, namespace and stage | `tunnel_configured` |
| `Disconnect{profile_id, namespace}` | agent UID and lab ownership | `sealed`, or `faulted` after a failed attempt; the namespace stays |

`VerifyLab` on a connected lab re-checks the tunnel (link, firewall, underlay, peer) instead of the
sealed topology, and `DeleteLab` removes the tunnel before the namespace. In helperctl:
`connect-tunnel PROFILE_ID NAMESPACE STAGE_ID < capability.json` and
`disconnect PROFILE_ID NAMESPACE`; in the controller lab CLI: `stage-info`, `connect-tunnel` and
`disconnect` (see "Tunnels from the controller").

- `tunnel_configured` means a configured WireGuard link, nothing more. `network_ready` stays false.
- One tunnel, or one unfinished attempt, per helper. While it exists, `CreateLab` and every
  `ConnectTunnel` get `LAB_BUSY`; it clears only with `Disconnect` or `DeleteLab`. (The recovery
  gate would otherwise see the tunnel's own underlay table.)
- Busy, faulted and uncertain-state refusals come before the capability is consumed. It is
  consumed just before the kernel work.
- A stage the vault does not hold (replaced, revoked, another profile's) gets `STAGE_NOT_FOUND`;
  the vault refuses before anything runs, so the lab stays sealed. Read `stage-info` and sign
  again.
- Any other failed connect leaves the lab `faulted` and the slot held, even after a clean
  rollback (`STATE_UNCERTAIN`). That includes a stage with `vpn_lab_compatible=false` (an IPv6
  endpoint or a reserved domain, for example), so check `stage-info` before signing, and a
  hostname that does not resolve to an acceptable address. `Disconnect` then releases the tunnel
  and answers `faulted`; only `DeleteLab` clears the lab.
- A failed `VerifyLab` faults the lab and removes the tunnel at once.
- When removing a tunnel fails (on `Disconnect`, `DeleteLab`, a failed verify or shutdown), the
  lab, its namespace and the slot stay; nothing is deleted around a tunnel whose removal is
  unproven.
- Normal shutdown deletes every lab the way `DeleteLab` does, tunnel first. After a crash with a
  tunnel up, the namespace, its underlay table and perhaps the link remain; recovery never removes
  underlay tables, so they are cleaned by hand.
- An operation gets 80 s, plus up to 40 s for a tunnel rollback; the helper answers within 125 s
  and the client waits 130 s.

Tested on WSL2 (Ubuntu 22.04, kernel 6.6) with a synthetic config whose endpoint is a
documentation address, so no handshake: connect, verify, list, the busy refusals, disconnect,
replay, a stale stage, a failed verify (an extra rule in the lab firewall), reconnect, and
`SIGTERM` with the tunnel up, which left no namespace, table or link. A failed connect, a failed
cleanup and a crash ran against fakes only. Not yet run with a real VPN provider.

## Managed tunnel backend

`agent.ManagedTunnelBackend` (Step 27B.1) brings a staged config up as `wg0` in a sealed lab. It
shares the sealed lab backend's namespace manager and firewall, and holds at most one tunnel. The
helper calls it only from the signed tunnel lifecycle above (`ConnectStage`, `VerifyConfigured`,
and `CleanupStage`, which removes whatever it tracks for a namespace). It checks no capability
itself, so it must never be wired to the HTTP agent.

`ConnectStage(profile, namespace, stage)` proceeds only when each check passes, in this order:

1. The vault lends the config for the exact profile and current stage (see "Managed WireGuard
   vault").
2. The recovery gate and kernel check pass (`Preflight`).
3. The config is a full IPv4 tunnel, and the endpoint a unicast IPv4 literal or a DNS name
   outside local and reserved domains (a static check: nothing is resolved yet).
4. No tunnel is tracked and the lab holds only `lo`.
5. The lab firewall matches both the session baseline and the intended sealed policy (the rules
   written out in `sealed_policy.go`, not the state read back after sealing). A mismatch marks the
   lab drifted. An nft version that prints the same rules differently is refused as well, and so
   is a table with any flags (a `dormant` table still lists its rules but enforces none). The
   lab's IPv6 switches for `default` and `lo` read `1` (see "IPv6 isolation").
6. No `egwg*` link and no managed alias exists in the VM namespace.
7. A DNS name is resolved once and one IPv4 address is pinned (see "Endpoint resolution"). A
   failed or refused lookup stops here, before any kernel change.
8. The expected peer state is written down from the vault config alone: the interface public key
   (`wg pubkey`, the private key on stdin), the peer key, the pinned IPv4 endpoint and port, and
   the keepalive. A key that cannot be derived, or equals the peer's, stops here. So is the
   expected network state: the planned IPv4 addresses (distinct unicast prefixes) and the MTU
   (the config's, or 1420).
9. The root underlay table is installed. Then the link is created with an alias
   `egresslab-managed:<namespace>:<link>`, moved into the lab and renamed `wg0`. Its name, alias
   and kind (`wireguard`) are read back, and IPv6 is disabled on it and read back while it is
   still down.
10. After the fwmark and private key are set, and before any peer exists, the lab firewall, the
    IPv6 switches, the underlay table and the fwmark are read back again, and the kernel must report the expected
    interface public key and no peer.
11. The peer, addresses, MTU and default route are configured; without an MTU in the config,
    1420 is set explicitly. The link, firewall, IPv6 switches and underlay are checked once more,
    and so are the peer (see "Peer verification") and the network (see "Network verification").

What the backend guarantees:

- The lab firewall stays loopback-only. WireGuard may send handshakes to the configured endpoint
  (the underlay table allows nothing else with the tunnel's mark), but no probe or proxy traffic is
  permitted. "Configured" means none of: handshake done, egress IP checked, `network_ready`.
- The link is looked up by name, alias and kind in both the VM and the lab namespace. A foreign
  device in the lab, a link with the name but not the alias (or the reverse), or a second match
  stops any automatic removal.
- A failed connect is rolled back: link first, confirmed gone by a fresh inventory, then the
  underlay table. If the removal cannot be proven (the link vanished on its own, a deletion
  failed, the underlay install failed), the table is kept and the tunnel stays tracked as faulted.
  New tunnels are then refused until `Disconnect` succeeds or the helper restarts and recovery is
  done by hand.
- `VerifyConfigured` re-reads the link, firewall, IPv6 switches, underlay, peer and network; a
  failure faults the tunnel, and a later correct readback does not clear the fault.

**Peer verification.** Each property is read on its own with `wg show wg0 <property>`, never with
`showconf` or `dump`, which print the private and preshared keys, and compared exactly with the
expected state; nothing is learned from the kernel. A value read is never put in an error.

| Property | Must be |
|---|---|
| `public-key` | the key derived from the vault's private key |
| `peers` | exactly one: the staged peer key |
| `endpoints` | the pinned IPv4 address (staged, or resolved at connect) and UDP port |
| `allowed-ips` | exactly `0.0.0.0/0` |
| `persistent-keepalive` | the staged value, or `off` when it is 0 |
| `fwmark` | the tunnel's mark (as before) |

WireGuard follows a peer that answers from another address (roaming). EgressLab does not accept
that: the underlay table keeps the tunnel's packets to the pinned endpoint, and a verification
that finds another endpoint faults the tunnel. A server that answers from another address
therefore faults the lab at the next `VerifyLab`, or fails the connect. Each check sees the state
of that moment only: a change that reverts before it (for example, roaming back to the pinned
endpoint) is not seen. Moving to another endpoint will need a controlled transition. The
preshared key is never read back, so it is not verified; a wrong one only breaks the handshake.
The formats are pinned by a real capture (`testdata/wg-show-peer.json`).

**Network verification (Step 27C.2).** A `default dev wg0` route alone proves little: Linux picks
a routing table through policy rules (by source, fwmark, UID or interface), so the addresses, the
rules, every table and the kernel's own route choice are read back together, with `ip -4 -json`
in the lab namespace. The expected state comes from the vault config alone.

| Readback | Must be |
|---|---|
| `addr show` | only `wg0` has IPv4 addresses: exactly the planned ones (prefix length, scope `global`, no expiry), with the planned MTU and the flags `UP`, `POINTOPOINT` and `NOARP`. `lo` stays without an address |
| `rule show` | exactly the three default rules: `0 local`, `32766 main`, `32767 default` |
| `route show table all` | every route on `wg0`. Main table: one `default` route (scope `link`, no gateway) and the kernel's connected route for each planned prefix shorter than /32. Local table: the `local` route of each planned address and the broadcast routes derived from them. No other table |
| `route get 1.1.1.1` | `wg0`, with a planned address as source |

Any attribute the check does not know (a gateway, metric, fwmark, nexthop, encapsulation, ...)
fails it, as does an unreadable or empty readback. `UP` is the administrative state only, and
`route get` is a kernel lookup that sends no packet: neither proves a handshake or working
traffic. The check is IPv4 only and sees one moment, like the peer check. Both compatibility
flags of the import summary also require the planned addresses to be distinct unicast IPv4
prefixes, so the controller refuses such a stage before signing. The formats come from real
captures (iproute2 6.1, Linux 6.8, Ubuntu 24.04), kept in `managed_tunnel_network_test.go`. This
check has run end to end on Lima only, not yet on WSL2 (Ubuntu 22.04, an older iproute2): since
the readbacks are decoded strictly, a format difference there would fault every tunnel. The
controller reports only `LAB_FAULTED`; the helper log names the readback that drifted.

**Endpoint resolution (Step 27C.3).** The managed tunnel accepts `Endpoint = name:port`. The name
is resolved once, during `ConnectTunnel`, and the result is pinned; DNS is never consulted again
for that tunnel. This is bootstrap DNS to find the VPN server, in the VM namespace with the
runtime's own resolver (`/etc/hosts`, then the servers in `/etc/resolv.conf`; none is
hardcoded). It opens nothing inside the lab, where ports 53 and 853 stay dropped.

| Case | Behaviour |
|---|---|
| IPv4 literal | unchanged: any unicast IPv4 address, staged by root |
| DNS name | needs a dot and an alphabetic top-level label; `.local`, `.localhost`, `.internal`, `.home.arpa`, `.invalid`, `.test`, `.example` and `.onion` are refused without a lookup |
| Lookup | IPv4 (A) only, as an absolute name (no search domain), 5 s timeout, at most 16 answers |
| Any answer private, loopback, link-local, multicast, shared (100.64/10), documentation, benchmarking, reserved, or not IPv4 | the whole response is refused |
| Several acceptable answers | the numerically lowest is pinned |
| Lookup fails or is refused | the connect stops before any kernel change |
| The name later resolves elsewhere | nothing changes; `VerifyLab` compares with the pinned address |
| The server roams | the underlay table and the peer check still hold the pinned address |

The pinned address is the one the underlay table allows, the one `wg set ... endpoint` gets, and
the one the peer check expects. To follow a new DNS answer, disconnect and sign a new
`ConnectTunnel`; there is no refresh or failover. The legacy `egresslab-vpn-lab` still needs an
IPv4 literal (`vpn_lab_compatible` in the import summary). Verified on Lima with a real provider
hostname: the resolved address was pinned in both the peer and the underlay table, a changed
answer (through `/etc/hosts`) did not move it, and a private answer was refused with no link or
table created.

Known gaps:

- One tunnel per helper (see "Signed tunnel lifecycle"); more need a tunnel registry that the
  recovery gate understands.
- A failed underlay install leaves the tunnel uncertain even when nft refused the script before
  changing anything: the lab cannot be deleted, `CreateLab` stays `LAB_BUSY` for the rest of the
  process, and shutdown leaves the namespace (and perhaps the table) for manual recovery.
- If `ip link del` removes the link but reports an error (a timeout), or the inventory after it
  fails, later `Disconnect` calls find no link and stay uncertain: the table is kept until the
  operator recovers by hand.
- A failed endpoint lookup faults the lab and reads `STATE_UNCERTAIN`, although nothing was
  changed: delete the lab and create a new one (no helper restart is needed). The helper log
  names the cause.
- Nothing monitors the tunnel continuously; drift is found only by `VerifyLab`, as of that
  moment.

## Invariants the helper keeps

- Before any opening operation, it reads back the firewall (`LabFirewall.Verify`). Drift blocks the
  operation until an explicit reconcile.
- The underlay policy is installed before the tunnel link exists. It is removed only after the
  link is gone (`VPNEgressLab.Disconnect`); the managed tunnel backend also requires that it
  deleted the link itself and that a fresh inventory confirms it.
- Sticky IP: an active profile observed on a different IP is cut off, and the active lease is kept.
- `network_ready` stays `false` until a real egress check passes for the exact profile.
- Every request and its result is appended to an audit log (`0600`). The log never contains secrets.

## Not covered yet

- Remote (non-loopback) controllers. Supporting them needs mutual authentication between the
  controller and the agent.
- Live rotation of the controller signing key (only offline replacement exists, see "Key
  replacement"), and rotation of the vault key.

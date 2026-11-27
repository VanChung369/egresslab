# Privileged helper and authorization protocol

Status: **Step 34 — SOCKS5 proxy runtime.** A controller CLI signs `CreateLab`,
`ConnectTunnel`, `PermitProbe`, `PermitMultiProbeV2`, `ReserveEgressCandidateV1`,
`PrepareEgressLeaseV1`, `RevokeEgressLeaseV1` and `RecoverRetiredGenerationV1` and drives the helper's sealed lab, tunnel and diagnostic probes in the Linux
runtime; the helper holds the encrypted WireGuard configs, disables IPv6 and drops DNS transports
inside its labs, resolves a hostname endpoint once and pins it, checks the peer state and the IPv4
addresses, MTU, rules and routes the kernel reports against the staged config, and stays the source
of truth for lab and tunnel state. A single-source probe yields one observation of the tunnel's
public IPv4 address, and a multi-source probe the unanimous evidence of two independent HTTPS
sources; both are printed only. The helper can consume that evidence once into a local egress
candidate (`ReserveEgressCandidateV1`, also through helperctl), and the controller has the shared
authority that holds each address for one tunnel owner, durably and across controller processes (an
append-only journal under an OS file lock), and a workflow that chains the verification, the
candidate and the durable reservation, which `reserve-egress` runs against an explicitly provisioned
per-user authority (`init-reservations`). The helper can also bind its candidate to such a durable
reservation as a sealed, generation-bound prepared lease (`PrepareEgressLeaseV1`), which
`reserve-egress` signs right after the durable commit, in the same operation; neither a reservation
nor a prepared lease is an active lease. The helper keeps a bounded retirement record of every
candidate for its epoch and answers a signed `RevokeEgressLeaseV1` with a receipt only once that
candidate's tunnel generation is confirmed removed; `release-egress` signs that revocation for a
durable hold and records the release in the authority's journal. After a helper crash and a reboot
of the Linux guest, `recover-egress` has a later helper epoch attest, from its boot-bound witnesses,
that the reboot ended the original generation (`RecoverRetiredGenerationV1`). While a lease is
prepared, the helper re-verifies its generation's address with the same two sources about every 20 s;
drift or a failed check faults and removes the tunnel, and the durable hold stays. Since Step 36 a
source that gives no answer only renews nothing: the check runs again, and the tunnel is cut if
the health expires first. A loopback
SOCKS5 proxy (`serve-socks`) carries IPv4 TCP streams through the prepared generation: each CONNECT
is a signed `OpenProxyStreamV1`, the socket is opened inside the lab by an unprivileged worker and
handed to the helper, and its traffic passes only a kernel-timed gate that the helper renews while
the monitoring health is fresh. Windows (WSL2), Linux and macOS (Lima, Keychain) are
verified end to end, except that the multi-source probe has run on WSL2 and Lima only, not on native
Linux. No lease or proxy traffic exists; the sections from "Typed operations only" on are partly
design.

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
  kernel). It answers `LAB_BUSY` while another lifecycle operation runs, since that operation's lab
  may not be settled yet. Since Step 36 it answers while the lifecycle lock is held only by the proxy
  streams' traffic windows or the egress monitor's check: those change a lab only to fault it.
- The client checks that the production socket is served by root (`SO_PEERCRED`) before it sends
  anything.
- `egresslab-helperctl` covers every helper operation except `AuthorizeCheck`, including
  `stage-info`, `connect-tunnel`, `disconnect`, `probe-egress`, `multi-probe-policy`,
  `multi-probe-target` and `probe-egress-multi` (V2 only). `create-lab`, `connect-tunnel`, `probe-egress` and `probe-egress-multi`
  read the capability from stdin only, never from argv. It refuses to run as root.
- The managed WireGuard vault and `StageInfo` (see "Managed WireGuard vault").
- Signed `ConnectTunnel` and `Disconnect` behind `-enable-tunnel` (see "Signed tunnel lifecycle"),
  on the managed tunnel kernel backend (see "Managed tunnel backend").
- Signed `PermitProbe` behind `-enable-probe`, with a dedicated probe UID and GID: one diagnostic
  observation through a kernel-timed firewall window and an unprivileged worker (see "Signed
  probe").
- Instead, signed, generation-bound `PermitMultiProbeV2` and the read-only `MultiProbePolicy` and
  `MultiProbeTarget` behind `-enable-multi-probe`, with the ident.me pin from
  `/etc/egresslab/multi-probe-pin` (see "Trusted multi-source provisioning" and "Sticky IP");
  `PermitMultiProbeV1` (Steps 29C.4a to 30B.1) is disabled in that mode.
- `ReserveEgressCandidateV1` in the same mode: one verified V2 attempt consumed into a local
  candidate (see "Egress candidates"). helperctl sends it (Step 31D.1), and so does the controller's
  `reserve-egress` (Step 31D.2).
- `PrepareEgressLeaseV1` in the same mode: that candidate bound once to a controller-signed durable
  reservation as a prepared lease, which opens nothing (see "Egress candidates"); helperctl
  (`prepare-egress-lease`) and the controller's `reserve-egress` send it (Step 31D.3b).
- `RevokeEgressLeaseV1` in the same mode: the signed retirement of one candidate's tunnel
  generation, prepared or not, expired or not, with a receipt only after a confirmed cleanup (see
  "Generation-bound revocation"); helperctl sends it (`revoke-egress-lease`), and so does the
  controller's `release-egress` (Step 31D.3d.2).
- `RecoverRetiredGenerationV1` in the same mode: a later helper epoch's signed attestation, from the
  persistent epoch witnesses, that a kernel reboot ended the original epoch's generation (see
  "Reboot-bound reservation recovery"); helperctl's `revoke-egress-lease` carries it, and the
  controller's `recover-egress` sends it (Step 31E.3).
- `OpenProxyStreamV1` with `-enable-proxy`: one IPv4 TCP stream to one destination for the prepared
  reservation of this helper epoch (see "SOCKS5 proxy runtime"); helperctl's `proxy-stream` carries
  it, and the controller's `serve-socks` sends one per CONNECT (Step 34).
- Controller side (see "Controller and runtimes"):
  - an Ed25519 signer for `CreateLab`, `ConnectTunnel`, `PermitProbe`, `PermitMultiProbeV2`,
    `ReserveEgressCandidateV1`, `PrepareEgressLeaseV1`, `RevokeEgressLeaseV1`,
    `RecoverRetiredGenerationV1` and `OpenProxyStreamV1` (the `PermitMultiProbeV1` signer stays for
    compatibility tests), checked against the ten golden vectors the helper also pins;
    `ConnectTunnel` is signed only for the profile's own lab in the current helper process and the
    vault's current, compatible stage, and the probes only for that lab once its tunnel is
    configured, `PermitMultiProbeV2` also only for the tunnel generation and policy that helper
    generation reports right before signing (see "Controller and runtimes" and "Generation-bound
    controller integration");
  - signing-key storage per platform;
  - runtime providers that reach the helper from each host OS;
  - `egresslab-controller-lab`, which needs `-approve` for every mutation, including
    `connect-tunnel`, `disconnect`, `init-reservations`, `reserve-egress`, `release-egress` and
    `recover-egress`, `serve-socks` and `serve-endpoint` (`list-reservations` is read-only);
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
- Journal compaction, key rotation and authority migration, and the release of a hold whose
  generation the backend contradicted, whose helper restarted without a reboot of the guest, or whose
  original epoch has no witness (a hold made before Step 31E.3a); a crashed helper's hold is
  recovered only after a reboot (Step 31E.3).
- Open from earlier steps: egress-IP leases across runtimes; a kill-switch independent of the controller; refusing to delete a
  profile that still has runtime resources.
- DNS for applications in the lab (a session resolver, with filesystem and resolver IPC
  isolation, belongs to the worker runtime), DNS refresh or endpoint failover for a running
  tunnel, and IPv6 endpoints. The HTTP controller and the desktop know nothing of labs or tunnels; only the
  lab CLI drives them.
- A controller approval workflow for individual operations.
- Live key rotation and automatic key distribution.
- `RecoverClean` through IPC.
- Storing probe observations, egress-IP leases from them, and multi-source verification (Step 29C).
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
- A request named `PermitProbe` gets `operation not enabled`, even with a valid capability, and
  the capability stays unused, unless the helper runs with `-enable-probe`. `ConnectTunnel` and
  `Disconnect` get the same answer unless the helper runs with `-enable-tunnel`.
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
  was started with `-enable-lab-lifecycle` and a public key, its managed tunnel, with
  `-enable-tunnel` as well, and its diagnostic probe, with `-enable-probe`.
- The helper socket accepts only the configured agent UID. It answers `Ping`, `RecoverScan`,
  `HelperInfo`, the `AuthorizeCheck` dry-run and, with the lifecycle flag, `ListLabs`,
  `CreateLab`, `VerifyLab` and `DeleteLab`, plus `StageInfo` with `-enable-vault` and
  `ConnectTunnel` and `Disconnect` with `-enable-tunnel`, `PermitProbe` with `-enable-probe`, and
  `MultiProbePolicy`, `MultiProbeTarget`, `PermitMultiProbeV2`, `ReserveEgressCandidateV1`,
  `PrepareEgressLeaseV1` and `RevokeEgressLeaseV1` with `-enable-multi-probe` (`TestPeerRejection`, `TestPeerIdentityAndReadOnlyOperations`,
  `TestMutationWithValidCapabilityIsRefused`, `TestLabLifecycleIPCRefusals`, `TestListLabsRefusals`,
  `TestStageInfoIPC`, `TestSignedTunnelIPC`, `TestTunnelOperationsDisabledWithoutBackend`,
  `TestSignedProbeIPC`, `TestProbeDisabledOverIPC`, `TestMultiProbePolicyIPC`,
  `TestGenerationProbeIPC`, `TestGenerationProbeDisabledOverIPC`, `TestCandidateReservationIPC`,
  `TestCandidateReservationDisabledWithoutGenerations`, `TestPreparedLeaseIPC`,
  `TestPreparedLeaseIPCDisabledWithoutGenerations`, `TestRevokedLeaseIPC`,
  `TestRevocationDisabledWithoutGenerationsOverIPC`).

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

`CreateLab` (creates and seals), `ConnectTunnel{profile_id, namespace, stage_id}`,
`PermitProbe{profile_id, namespace, probe_ipv4}` (fixed to `1.1.1.1`),
`PermitMultiProbeV1{profile_id, namespace, probe_ipv4}` (the provisioned ident.me pin),
`PermitMultiProbeV2{profile_id, namespace, probe_ipv4, tunnel_generation}` (V1 bound to one tunnel),
`MultiProbeTarget{profile_id, namespace}` (read-only),
`ReserveEgressCandidateV1{profile_id, namespace, probe_ipv4, tunnel_generation, evidence_nonce}`
(consumes one verified V2 attempt),
`PrepareEgressLeaseV1{…, reservation_nonce, runtime_id, authority_id, reservation_id, egress_ipv4}`
(binds that candidate to a durable reservation),
`RevokeEgressLeaseV1{the same fields}` (retires that candidate's tunnel generation),
`VerifyLab`, `Disconnect`, `DeleteLab`, `RecoverScan`, `RecoverClean`.

Every argument is validated with the existing patterns: `egresslab-lab-<16 hex>`,
`profile_<16 hex>`, `wgstage_<32 hex>`, and IPv4 literals. Keys never travel over the socket.
`ConnectTunnel` names a stage, and the helper reads that stage from the sealed vault itself.

## Authorization

`CreateLab`, each operation that opens traffic (`ConnectTunnel`, `PermitProbe`,
`PermitMultiProbeV1`, `PermitMultiProbeV2`), `ReserveEgressCandidateV1`, `PrepareEgressLeaseV1` and
`RevokeEgressLeaseV1` need a capability that the controller mints. Implemented format, version 1:

```text
claims = {"version":1,
          "intent":{"operation":..., "profile_id":"profile_<16 hex>",
                    "namespace":"egresslab-lab-<16 hex>",  ("" for CreateLab)
                    "stage_id":"wgstage_<32 hex>"          (ConnectTunnel only)
                    "probe_ipv4":"<dotted IPv4>",          (PermitProbe, PermitMultiProbeV1, V2, Reserve...)
                    "tunnel_generation":"tunnelgen_<32 hex>",  (PermitMultiProbeV2 and the three below)
                    "evidence_nonce":"<32 hex>",           (ReserveEgressCandidateV1, Prepare..., Revoke...)
                    "reservation_nonce", "runtime_id", "authority_id", "reservation_id",
                    "egress_ipv4"},                        (PrepareEgressLeaseV1, RevokeEgressLeaseV1 only)
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
  creates get `STATE_UNCERTAIN`; check `egresslab-lab-recover`, then restart the helper (which loses
  the egress retirement records of Step 31D.3c).
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

A failed write, a failed or unexpected readback, or any value other than `1` refuses: a seal fails
(the helper deletes the namespace), a connect is rolled back before any peer exists, and a
`VerifyLab` faults the lab and removes its tunnel. Drift is never repaired, and `DeleteLab` does not
depend on this check. Only lab namespaces are touched: the VM namespace and the host keep their own
settings. On Linux 6.8 a link moved into a lab already inherits `disable_ipv6=1` from `default`; the
explicit write and readback do not rely on that. A kernel booted without IPv6 (`ipv6.disable=1`) has
none of these switches, so sealing should fail there (not tested). Verified on Lima (Linux 6.8,
procps-ng 4.0.4): the lab showed no IPv6 address or route with `lo` and `wg0` up (the `ff00::/8`
route on `wg0` is gone), the handshake still completed, the VM's own switches stayed `0`, and
re-enabling IPv6 on `lo` (sealed lab) or `wg0` (tunnel) faulted the lab without being repaired. On
WSL2 (Linux 6.6), every seal, connect and `VerifyLab` of the Step 30B.2 run passed the write and
readback; the drift cases ran on Lima only.

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
On WSL2 (nft 1.0.2), the seal and its readback against the intended policy passed in the Step
30B.2 run; blocking from inside the lab was not exercised there.

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
connection opened inside the window; the close by handle left exactly the sealed ruleset. On
WSL2 (nft 1.0.2), the real probes of the Step 30B.2 run opened and closed the window without a
readback failure, and the ruleset was back to the seal afterwards; the negative cases ran on Lima
only.

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
environment (no proxy, TLS, HOME or loader variables). For this probe the worker takes no arguments
(the multi-source mode of Step 29C.3 passes `--source SOURCE_ID IPV4`), refuses to
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
the runner discards its stderr. 37 later probes in that session succeeded (two with the
production runner, the others with a temporary build that also reported the worker's error), and
the results of 8 more were not captured. It recurred in Step 29B.2b: the first signed probe through
the controller failed the same way (see "Probes from the controller"). Under the current policy a
transient failure costs a full reconnect. On WSL2 (2026-11-25, Step 30B.2 build), the first
probe of the session failed the same way and the next ones succeeded (see "Probes from the
controller").

**Signed probe (Step 29B.2a).** `PermitProbe{profile_id, namespace, probe_ipv4}` runs one whole
probe; the controller cannot ask the helper to keep the firewall open. It needs `-enable-probe`
(on top of `-enable-tunnel`) with `-probe-uid` and `-probe-gid`: a non-root identity that is
neither the agent's UID nor its GID. Without the flag the operation answers `OPERATION_DISABLED`.
In order, before the nonce is consumed:

1. The intent names a valid profile and namespace, no stage, and `probe_ipv4` exactly `1.1.1.1`
   (helperauth accepts any unicast IPv4; the helper only its fixed destination), else
   `INVALID_REQUEST`.
2. The lifecycle lock is free (`LAB_BUSY`), the helper is not shutting down and creation is not
   blocked (`STATE_UNCERTAIN`).
3. The profile owns a lab (`LAB_NOT_FOUND`) in exactly that namespace (`OWNERSHIP_MISMATCH`), the
   lab is `tunnel_configured` (`LAB_FAULTED` otherwise) and holds the tunnel slot.
4. The capability verifies for that exact intent, epoch, lifetime and unused nonce
   (`AUTHORIZATION_DENIED`).

While the probe runs the lab is recorded as faulted, so ownership is never lost. On success the
lab is `tunnel_configured` again and the response carries `probe: {profile_id, namespace, ipv4,
observed_at, handshake_at, source: "cloudflare_trace"}` with `network_ready: false`. Any failure,
an observation that fails the helper's own checks, or an expired operation context leaves the
lab `LAB_FAULTED` after the tunnel is cleaned up (only `DeleteLab` clears it); if that cleanup
cannot be confirmed, the answer is `STATE_UNCERTAIN` and the tunnel slot stays held. An
unconfirmed rollback now outranks every other code, for every operation. Nothing is retried.

The client accepts a `probe` object only on a successful `PermitProbe`, for the profile and
namespace it asked about, with a public IPv4 address, the fixed source and a handshake at most
180 s before the observation. The operation runs under the usual 80 s context, but its cleanups
have their own deadlines, so the server allows 185 s for the answer, the client 190 s and
`egresslab-helperctl probe-egress PROFILE_ID NAMESPACE < capability.json` 200 s; helperctl takes
no destination, URL or port. Verified on Lima: the real helper refused every invalid flag
combination before creating its socket, logged `signed sealed lab, managed tunnel and diagnostic
probe enabled; proxy disabled`, still answered `HelperInfo` and `ListLabs`, and routed
`PermitProbe` to the lifecycle (`LAB_NOT_FOUND` for a missing lab) while a helper without the
flag answered `OPERATION_DISABLED`. The first real probes over IPC, signed by the controller, ran
in Step 29B.2b (see "Probes from the controller"). On WSL2, the helper started with
`-enable-probe` and logged the same mode (Step 30B.2 run); the invalid flag combinations ran on
Lima only.

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
| `OPERATION_DISABLED` | not enabled on this helper (no key; no lifecycle, vault, tunnel or probe flag) |
| `RUNTIME_UNAVAILABLE` | helper unreachable, shutting down, or not served by root |
| `INVALID_REQUEST` | malformed frame, version, fields or arguments |
| `LAB_BUSY` | another lab operation is running, or the managed tunnel slot is held (until `Disconnect` or `DeleteLab`; not worth retrying) |
| `LAB_NOT_FOUND` / `LAB_EXISTS` / `LAB_LIMIT` | no lab for the profile / one already / 8 reached |
| `OWNERSHIP_MISMATCH` | the profile's lab is another namespace |
| `FIREWALL_DRIFT` / `LAB_FAULTED` | the lab no longer matches (firewall / topology, or already faulted); delete it |
| `RECOVERY_REQUIRED` | leftover lab resources block creation |
| `KERNEL_INCOMPATIBLE` | new namespaces would get extra devices |
| `STATE_UNCERTAIN` | a create, tunnel connect or cleanup may have left kernel state behind; delete the lab, or check recovery before restarting the helper, which loses the egress retirement records (a revocation's answer says to keep it running) |
| `STAGE_NOT_FOUND` | the vault holds no such stage for the profile (`StageInfo`, `ConnectTunnel`); the lab is untouched |
| `EVIDENCE_UNAVAILABLE` | no fresh, unconsumed V2 evidence matches the reservation (none, expired or already consumed); since Step 36 also a multi-source probe whose source gave no answer, with the lab left configured: approve a new attempt |
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

### Probes from the controller

`egresslab-controller-lab -approve probe-egress PROFILE_ID NAMESPACE` runs one signed probe (Step
29B.2b); it takes no URL or destination. Before signing, the controller requires, in this order:

1. the profile in `state.json`, still `unconfigured` with its unique-IP and kill-switch policies;
2. a trusted runtime whose helper reports the pinned runtime ID and public-key fingerprint;
3. the profile's binding to that runtime, naming this namespace and the current helper epoch
   (`OWNERSHIP_MISMATCH` otherwise, also after a helper restart);
4. `ListLabs` showing the profile's lab in that namespace as `tunnel_configured` (`LAB_NOT_FOUND`,
   `OWNERSHIP_MISMATCH` or `LAB_FAULTED` otherwise).

The capability binds profile, namespace, helper epoch and `probe_ipv4` `1.1.1.1`, for 30 seconds;
the signed JSON is pinned by a golden vector in both modules (cross-checked with OpenSSL 3). The
helper's answer must be a successful `PermitProbe` carrying exactly one `probe` object and no lab
metadata, for that profile and namespace, with a public IPv4 address (the network agent's
candidate policy), the fixed source and a handshake at most 180 s before the observation. The
controller then requires the observation to be at most 90 s old when it arrives, not before the
capability was issued, and its timestamps within 5 s of the host clock; the capability only had to
be valid when the helper accepted it. A lost or unreadable answer, or a rejected observation, is
`STATE_UNCERTAIN` (inspect `list-labs`); a helper refusal keeps its code. Nothing is retried, the
binding is not changed, and the observation is printed with `network_ready: false`, neither stored
nor turned into a lease.

Verified on Lima with the real Proton tunnel, signing with the Keychain key: a sealed lab was
refused before signing. The first signed probe answered `LAB_FAULTED`: the worker failed for an
unknown reason (its error is not reported) and the cleanup worked, leaving a lab with only `lo` and
no underlay table. Recovery is `delete-lab`, `create-lab`, `connect-tunnel` and a new probe; the
helper need not restart. The next 8 probes all succeeded in about a second each, two of them after
5 idle minutes, returning the provider's exit IPv4 with a handshake 1 s old; afterwards the lab's
ruleset held no probe set or permit, no worker process remained, `verify-lab` still answered
`tunnel_configured`, and a second probe on the same lab succeeded. Both observed failures were
the first probe of a session; their cause is unknown.

Verified on WSL2 (Ubuntu 22.04, Linux 6.6, nft 1.0.2, iproute2 5.15) on 2026-11-25, with the Step
30B.2 helper, helperctl and worker, the Windows controller signing with its DPAPI key through
`wsl.exe`, and the same real tunnel. A sealed lab was refused before signing (`LAB_FAULTED`). The
first signed probe of the session answered `LAB_FAULTED` again; the helper log said only `probe
failed: managed egress probe failed`, and the cleanup left only `lo`. On a fresh lab the next two
probes succeeded with the same exit address as on Lima and a handshake 1 and 3 s old; afterwards the
lab had no process and no probe set or permit, and `verify-lab` answered `tunnel_configured`.

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
| `/var/lib/egresslab/vault/helper-epochs.json` | helper epoch witnesses (Step 31E.3a), root `0600` |
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
  lifecycle"); `PermitProbe` (with `-enable-probe`) probes the tunnel that stage configured.
  `network_ready` stays false.

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
cleanup and a crash ran against fakes only. It has since run with a real VPN provider (from
Step 27B.3 on).

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
check has also run end to end on WSL2 (Ubuntu 22.04, iproute2 5.15, Linux 6.6): every
`connect-tunnel` and `verify-lab` of the Step 30B.2 run decoded its readbacks and verified. The
readbacks are decoded strictly, so an iproute2 that prints differently would fault every
tunnel. The controller reports only `LAB_FAULTED`; the helper log names the readback that drifted.

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

## Multi-source public IP verification

The probe of Step 29B relies on one source (`https://1.1.1.1/cdn-cgi/trace`), so its answer rests
on one operator. Step 29C requires several independent sources that must all agree:

| Step | Content |
|---|---|
| 29C.1 | Source policy and strict consensus engine |
| 29C.2 | Pinned HTTPS sources and their timed firewall |
| 29C.3 | Managed multi-source probe lifecycle |
| 29C.4a | Signed multi-source helper IPC |
| 29C.4b | Trusted provisioning and helperctl |
| 29C.4c | Controller integration and real VPN verification |

### Strict consensus policy (Step 29C.1)

`verifyManagedProbeConsensus` (`managed_probe_consensus.go`) judges the observations of one
verification attempt against a source policy. The policy is trusted local configuration; an
untrusted caller never supplies it. It holds 2 to 8 sources, each with its own source ID and
operator name (`^[a-z][a-z0-9_]{0,31}$`) and its own public IPv4 destination (the network agent's
candidate policy). A distinct operator name is a declaration, not proof of independence: no code
checks who runs a source; that is reviewed by hand when a destination is provisioned (see "Pinned
HTTPS sources and timed firewall").

The evidence is accepted only when every required source returned exactly one observation, each a
valid public IPv4 address observed inside the attempt's interval (at most 80 s, the helper's
operation context; Step 29C.3 runs the whole attempt under one deadline of that length), and all
of them the same address. It is refused when:

- a required observation is missing, or there are more observations than sources;
- an observation names an unknown source, or a source twice;
- the observed addresses disagree;
- an address is invalid, IPv6 (IPv4-mapped included), private, shared, loopback, documentation
  or otherwise reserved;
- an observation falls outside the interval, or the interval itself is invalid.

There is no majority vote (two of three agreeing is refused) and no fallback to fewer sources or
to one. A refusal returns no evidence. Accepted evidence carries the earliest observation time, so
its freshness is that of its oldest part. It does not activate a profile, allocate an egress
lease, authorize application traffic or promise that the address stays the same afterwards. A
provider whose exit address depends on the destination (destination-dependent NAT) will always
be refused in this strict mode.

At Step 29C.1 the engine is pure Go and unit-tested on its own; it is not wired into the managed
probe, and no binary behaves differently. HTTPS sources, their kernel firewall policy and signed IPC follow in
the next steps.

### Pinned HTTPS sources and timed firewall (Step 29C.2)

The source policy (`managed_probe_sources.go`) holds the two mandatory sources:

| Source | Operator | URL | TCP destination | Response | TLS name |
|---|---|---|---|---|---|
| `cloudflare_trace` | Cloudflare | `https://1.1.1.1/cdn-cgi/trace` | `1.1.1.1` | trace key-value | IP SAN |
| `ident_me` | ident.me | `https://4.ident.me/` | a provisioned IPv4 pin | one plain-text IPv4 | `4.ident.me` |

The HTTPS identity and the TCP destination are separate. `pinnedProbeHostDial` accepts exactly the
source's authority (`host:443`) and dials its numeric pin through `pinnedProbeDial`, so no hostname
reaches a resolver; TLS still verifies the certificate for that host against the system trust
store (SNI and `Host` unchanged). The ident.me pin must come from trusted provisioning outside the
lab: never from an IPC request, an environment variable or a DNS lookup at probe time. The provider
does not promise a stable address, so a changed address makes the probe fail; nothing switches to
another address. The transport takes no proxy from the environment, follows no redirect, reuses no
connection, sends `Accept-Encoding: identity` and refuses any other content encoding in any
`Content-Encoding` field (not only the first), caps headers
at 16 KiB and the body at 4096 bytes, and requires HTTP 200. Each body is parsed in its source's
format: one `ip=` field for the trace; for ident.me exactly one IPv4 address with at most one
trailing line ending. Every address then passes the network agent's public IPv4 policy.

The probe window now takes its destination: `managedProbeRulesFor(destination)` opens the same set
and the same two permits (wg0, TCP 443, 30 s kernel timeout) with that one element, and the
verifying and closing code requires exactly that element. A window holding another address, public
or not, is refused and is not closed by a request for another destination. An expired window (no
element listed) is accepted for cleanup only. The rule Step 29C.3 follows when it sequences the
sources: each source gets its own window, closed and verified before the next one opens, and a
window that cannot be closed stops the attempt. The single-source
`PermitProbe` still opens only the 1.1.1.1 window, now through the destination-aware functions.

Host preflight on 2026-11-25 (an observation, not the provisioned pin): `4.ident.me` resolved to
one address, `65.108.151.63` (TTL 3600),
announced by Hetzner (AS24940), not Cloudflare (AS13335). An HTTPS request pinned to it returned
HTTP 200 with a verified certificate and a bare IPv4 address of 12 bytes with no line ending, the
same address the Cloudflare trace reported. The ASN lookup shows two different networks; it does
not prove the operators independent. This was a host check, not a managed observation: it
fed no registry and no lease. The source code was unit-tested here (a local TLS server stands in
for the sources); it first ran against the real endpoints through the tunnel in Step 29C.4c. Step
29C.3 calls it from the multi-source lifecycle.

### Managed multi-source probe lifecycle (Step 29C.3)

`ProbeConfiguredMulti` (`managed_multi_probe.go`) observes the tunnel's public IPv4 address from
every mandatory source, one after another, through the same configured tunnel. The namespace
manager lock is held for the whole attempt and the attempt has one 80 s deadline, so no backend
operation can disconnect, reconnect or change the tunnel between two observations. The lock does
not stop another privileged process on the host from changing kernel state, so the kernel is
checked again throughout:

| Gate | When |
|---|---|
| Backend configuration, source policy, tunnel ownership | before the attempt starts |
| Full tunnel verification (link, sealed firewall, IPv6, underlay, peer, network) | before the first window and after every window |
| Empty namespace process inventory | before and after every window |
| Kernel route lookup for the source's own destination (wg0, planned source address) | before every window |
| Window readback (exact destination, time left) | after opening and when the worker returns |
| Window close and sealed policy readback | after every source, with its own context |
| Recent handshake with the expected peer, judged at the finish time | after the last source |
| Strict consensus against the whole mandatory policy | before any evidence is returned |

Each source gets its own kernel-timed window for its own destination. The next window cannot open
until the previous one is closed and verified and the worker has exited; a window that cannot be
closed marks the namespace drifted and stops the attempt. There is no retry per source: the
second source only gets the time the first one left.

The worker receives only a built-in source ID and its numeric IPv4 pin (`egresslab-probe --source
cloudflare_trace 1.1.1.1` or `--source ident_me <pin>`); the host name, path and response format
come from code, and it accepts no URL, host, port, proxy or TLS setting. It runs through the same
`ip netns exec … setpriv` drop as the single-source probe, with no supplementary groups, no
capabilities, no_new_privs and no inherited environment, and its output is capped at 4 KiB. The
parent parses and validates every body itself in the source's format.

Before the attempt starts, a refusal (no multi-source configuration, an invalid source policy,
another namespace, a faulted tunnel, a cancelled context) changes nothing. Once it has started, any
failure discards every observation, faults the tunnel and removes it; an unconfirmed removal keeps
the faulted tunnel tracked (`ErrManagedTunnelUncertain`).

The one exception (since Step 36) is a source that gives no answer:
- **What counts.** The source sent nothing at all, not a byte at any layer, and the attempt timed
  out or the connection was refused, reset or closed. The worker reports it as its own line
  (`HTTPS_NO_ANSWER`). Any byte that came back makes it an answer, cut off or not; so does a server
  that completed TLS and then went silent.
- **What does not count.** A response that arrived and was refused is still a failure: a
  certificate, a host name, a TLS alert, a reply that is not TLS, a status, an encoding or a body.
  So is an older worker, which reports every failure the same way.
- **The result.** If the source's window then closed as opened, with nothing else joined to the
  error, and the worker is gone, the tunnel verifies as staged, the clock checks pass and the
  attempt's context is still live, the attempt returns
  `ErrManagedProbeSourceUnavailable`. It yields no evidence, sets no pin, and leaves the tunnel and
  its firewall as they were. Anything more on top of it (a cleanup, a readback, a context, a busy
  namespace or a tunnel check) faults as before. All timestamps are wall-clock UTC, and each one is
checked against monotonic time: if the wall clock moved more than 1 s away from it since the
attempt started or since the previous reading (a clock step in either direction), or if a
reading is earlier than the previous one, the attempt fails closed.

A successful attempt returns the agreed IPv4 address, the start and finish times, the earliest
source observation time, the handshake time, per-source evidence (source, destination, address,
time) and `network_ready=false`. It authorizes no lease and no application traffic.

The multi-source backend is enabled only by its own constructor,
`NewManagedMultiProbeTunnelBackend`, which takes the ident.me pin from trusted local provisioning.
It leaves the single-source runner disabled, so a failed multi-source attempt cannot fall back to
one source; `NewManagedProbeTunnelBackend` (single source) and `NewManagedTunnelBackend` (no
probe) are unchanged. `egresslab-helper` still uses the single-source backend; Step 29C.4a adds the
signed operation, and Step 29C.4b enables it in the helper. In this step the lifecycle was tested
against fakes; the `--source` worker and the window for the ident.me pin first ran in a real
namespace in Step 29C.4c.

### Signed multi-source helper IPC (Step 29C.4a)

`PermitMultiProbeV1{profile_id, namespace, probe_ipv4}` authorizes one multi-source verification
attempt (Step 29C.3) against the fixed V1 source policy: the Cloudflare trace at `1.1.1.1` and
ident.me at its provisioned pin, both over pinned HTTPS in their own timed windows, with unanimous
consensus. The operation name is the policy version; `probe_ipv4` binds the one variable, the
ident.me pin, which must be a canonical public IPv4 address other than `1.1.1.1` (helperauth keeps
its own copy of the agent's public IPv4 policy, and a test checks that the two agree at every
reserved-range edge). Changing the sources, their endpoints or the verification semantics needs a
new operation name, not a new meaning for this one. The signature domain, Ed25519, nonces and the
30 s capability lifetime are unchanged, and a `PermitProbe` capability cannot authorize this
operation or the reverse.

The helper reads the pin from its own backend (`MultiProbePolicyPin`) and builds the expected
intent from it; the request and the capability never choose a destination. A capability validly
signed for another pin is refused as `INVALID_REQUEST` without consuming its nonce. In order, the
helper requires a matching intent, an enabled multi-source backend, no other running operation,
the profile's own lab and namespace, a configured tunnel it owns and a readable local policy, then
verifies the capability for this helper epoch and consumes its nonce. A refusal before that point
leaves the lab and the capability untouched.

While the attempt runs, the lab is held as faulted. The helper then checks the evidence again,
independently of the agent's consensus engine: exactly the two V1 sources in execution order with
their destinations (`1.1.1.1`, then the signed pin), one public IPv4 address they all report,
observation times in order inside an interval of at most 80 s that started after the capability
was issued and after the helper accepted it (1 s tolerance) and did not end after the helper's
own check,
`observed_at` equal to the earliest source, and a handshake at most 180 whole seconds old at
`finished_at`, judged like the agent. Any failure after the nonce is consumed discards the
evidence, keeps the lab faulted and removes the tunnel; an unconfirmed removal answers
`STATE_UNCERTAIN` and keeps the ownership. Only `DeleteLab` clears a faulted lab. On success the lab
returns to `tunnel_configured` with the firewall sealed again. The capability only has to be valid
when the helper accepts it; the attempt may finish after it expires.

A lifecycle built with `NewMultiProbeLifecycle` refuses `PermitProbe` (`OPERATION_DISABLED` over
the socket), even if a single-source backend were also set, so nothing falls back to one source.
A helper without the multi-source backend answers `OPERATION_DISABLED` to `PermitMultiProbeV1`.
The response carries a `multi_probe` object only on a successful `PermitMultiProbeV1`; the client
(`ProbeEgressMulti`) applies the same evidence checks against its own request and capability,
requires the attempt to lie between writing the request and reading the answer (1 s tolerance at
the start only: the helper and its client share the VM's clock, so evidence never ends in their
future), and refuses a failure that carries evidence, unsolicited evidence, a `probe` object or
`network_ready=true`. A helper from before this step refuses the operation without naming it (its
echo rule allowed letters only); the client maps exactly that bare refusal to
`OPERATION_DISABLED` and treats any other unnamed answer as invalid. The response budget is the single-source probe's (185 s on the helper side,
190 s on the client). The server now echoes an operation name made of a letter followed by up to
31 letters or digits (it was letters only), so the versioned name is echoed; other names still are
not.

The `multi_probe` response is diagnostic evidence only: `network_ready` stays false, and no lease
or application traffic exists. Step 29C.4b enables the operation in `egresslab-helper`, and Step
29C.4c adds the controller signer and end-to-end verification over the VPN. The lifecycle is
tested with a fake kernel backend, including over a real Unix socket with the real framing,
dispatcher and verifier on Lima.

### Trusted multi-source provisioning (Step 29C.4b)

`-enable-multi-probe` (with `-enable-tunnel` and a dedicated `-probe-uid`/`-probe-gid`, like
`-enable-probe`) enabled `PermitMultiProbeV1` and `MultiProbePolicy` in this step; since Step 30B.2
it enables `PermitMultiProbeV2`, `MultiProbePolicy` and `MultiProbeTarget` instead, with the same
flags and pin. Every UID and GID, the
agent's and the worker's, must be a non-root 32-bit ID other than `(uid_t)-1`, checked before the
worker's are compared with the agent's, so a value that would be truncated cannot alias them. The two probe modes are
mutually exclusive: starting with both is refused, and in multi-source mode `PermitProbe` answers
`OPERATION_DISABLED`, so nothing falls back to one source.

| Flags | `PermitProbe` | multi-source (`PermitMultiProbeV2` since Step 30B.2) |
|---|---|---|
| neither | disabled | disabled |
| `-enable-probe` | enabled | disabled |
| `-enable-multi-probe` | disabled | enabled |
| both | start refused | start refused |

The ident.me pin comes from `/etc/egresslab/multi-probe-pin` only: never from a flag, an
environment variable, an IPC request or a DNS lookup. The file holds one canonical public IPv4
address other than `1.1.1.1`, optionally followed by one LF, and nothing else (no CR, spaces,
second line, port, URL or `KEY=` prefix), at most 64 bytes. It must be a regular file owned by
root and not writable by group or others (0600 recommended), in real, root-owned directories that
nobody else can write, up to `/`; a symlink (the file or a parent), a FIFO, a directory, an empty
or oversized file and an invalid address are refused. The file is opened with `O_NOFOLLOW` and
`O_NONBLOCK` and must be the same file that was checked (`os.SameFile`). This assumes root and the
root-owned directories are trusted; it does not defend against a malicious root process. The path
must be absolute and canonical (no `..`, `//` or trailing `/`): it is not cleaned, so the file
checked is the file a rename of the same path replaces.

The helper reads the pin after checking its flags and before the authorization key, the socket,
the vault or the kernel backend: a missing, unsafe or invalid pin refuses the start
(`multi-source probe configuration: …`) and changes nothing, and the helper never starts in
another mode instead. The pin is fixed for the helper's lifetime; changing it means trusted
provisioning and a restart, which also starts a new helper epoch, so every capability minted for
the old process is refused. The start log names the policy and the pin. The mode needs the Step
29C.3 worker (`--source`); an older `egresslab-probe` passes the binary checks but would fail the
first attempt, so the upgrade reinstalls it (`docs/DEV-LINUX-VM.md`). `sudo egresslab-helper
check-multi-probe-pin PATH` applies the same rules to a staged file and prints the pin, so a
rotation can be checked before it replaces the working file (see `docs/DEV-LINUX-VM.md`).

`MultiProbePolicy` is read-only: it takes no intent or capability (`INVALID_REQUEST` if it gets
one), creates no lab, opens no window, runs no worker and consumes no nonce. It answers
`{policy, ident_ipv4, helper_id, runtime_id, public_key_sha256}`, the policy version and pin bound
to the helper epoch, runtime ID and public-key fingerprint they belong to, so the controller can
compare them with what it trusts before it signs (Step 29C.4c). It does not wait behind a running
operation (`LAB_BUSY`; shutdown is reported first, as `RUNTIME_UNAVAILABLE`), and answers `OPERATION_DISABLED` without the multi-source mode,
`RUNTIME_UNAVAILABLE` while shutting down or without a readable policy, and `STATE_UNCERTAIN` when
the kernel state is uncertain, including while a tunnel whose removal was not confirmed is still
tracked on its faulted lab. The client checks every field (the policy name, a valid pin, the
identity formats) and refuses the metadata on any other operation or on a failure. Reading it is
not authorization: `PermitMultiProbeV1` still needs a capability for exactly that pin. The
fields are not added to `HelperInfo`, which older controllers decode strictly.

`egresslab-helperctl multi-probe-policy` prints the policy, and `egresslab-helperctl
probe-egress-multi PROFILE_ID NAMESPACE < capability.json` runs one signed attempt (200 s client
budget, like `probe-egress`). There is no destination, URL, host, port or TLS argument; any extra
argument is a usage error, and the capability is read from stdin only and checked against the
V1 intent before the helper is contacted.

Provisioned on Lima on 2026-11-25 (an observation, not a constant): `4.ident.me` resolved to
`65.108.151.63` only, from the host and from the VM, the address recorded in Step 29C.2. A pinned
HTTPS request from the VM returned HTTP 200 with a verified certificate and no redirect, and a
12-byte body that was one IPv4 address, the same one the Cloudflare trace reported (neither was
printed). The pin file was installed root:root 0600 by an atomic rename, and the new binaries
were installed. The helper refused to start in multi-source mode before the file existed (before
creating `/run/egresslab`), and refused both probe modes together, also while another helper was
running. Started with `-enable-multi-probe` (against a throwaway public key whose private half was
never stored, and an empty vault), it logged the policy and pin; `multi-probe-policy` returned
them with the same epoch, runtime ID and fingerprint as `helper-info`; `probe-egress-multi`
without a capability or with a destination argument was refused as `INVALID_REQUEST` by
helperctl, and `PermitProbe` as `OPERATION_DISABLED` by the helper; `list-labs` and
`recover-scan` were empty, and SIGTERM stopped it and removed the socket. No signed probe ran in
this step; Step 29C.4c added the controller signer and the VPN verification. No lease or
application traffic is authorized.

### Controller multi-source integration (Step 29C.4c)

In this step `egresslab-controller-lab -approve probe-egress-multi PROFILE_ID NAMESPACE` signed one
`PermitMultiProbeV1` through the existing runtime providers and key stores (since Step 30B.2 it signs
`PermitMultiProbeV2` only; see "Generation-bound controller integration"). Before signing it
requires, like `probe-egress`, a strict, unconfigured profile, a trusted runtime with the pinned
public-key fingerprint, the current helper epoch, the profile's binding to that runtime and
namespace, and the profile's own configured tunnel (`ListLabs`). It then reads `MultiProbePolicy`
right before signing and accepts it only for that same helper generation: policy `PermitMultiProbeV1`,
a valid pin, and the runtime ID, helper epoch and fingerprint of both `HelperInfo` and the trusted
runtime record (`RUNTIME_UNTRUSTED` otherwise). The capability signs `{PermitMultiProbeV1, profile,
namespace, probe_ipv4: the advertised pin}` for that epoch, with the usual nonce and 30 s
lifetime; a fourth golden vector, pinned in both modules and cross-checked with OpenSSL 3, keeps the
controller's bytes identical to the helper's. It travels on stdin only; the launcher gets
`probe-egress-multi PROFILE_ID NAMESPACE` and no destination. A capability already expired on the
controller's clock is not sent. `egresslab-controller-lab multi-probe-policy` prints the policy
read-only.

The controller checks the evidence again, independently of the helper and the agent: exactly the
two V1 sources in order with their destinations, the ident.me destination equal to the signed pin
(not one the response chose), one public IPv4 address that every source reports, observation
times in order inside at most 80 s, `observed_at` equal to the first source, and a handshake at
most 180 whole seconds old at `finished_at`. It then binds the evidence to the request: started
after the capability was issued and after the request was sent, finished before the answer
arrived, `observed_at` at most 90 s old and the handshake at most 185 s old at receipt, all with
5 s of host/runtime clock skew. That allowance covers the evidence only: the helper checks the
capability's `issued_at` against its own clock with none, so a runtime clock behind the host's
refuses fresh capabilities. Strict JSON decoding refuses unknown fields, and a failure
document that carries any metadata field, even as `null`, is treated as a runtime failure, not a
coded refusal. A well-formed policy the controller does not accept (an unknown version or an
invalid pin) answers `RUNTIME_UNTRUSTED`.

Nothing is retried, and nothing falls back to `PermitProbe`. A lost connection, an internal error
or refused evidence answers `STATE_UNCERTAIN`: the helper may or may not have consumed the nonce or
rolled the tunnel back, so `list-labs` and `recover-scan` come before any new operation (refused
evidence can even leave the tunnel configured and sealed). The observation is printed with
`network_ready: false` and stored nowhere: no profile, binding, routing or lease state changes.
Agreement of two sources says nothing about the address later, about destination-independent NAT
for other destinations, or about uniqueness across concurrent sessions.

Verified on Lima on 2026-11-25 with the real Proton tunnel, a scratch Keychain key and a scratch
profile (both removed afterwards): through the controller, `helper-info` and `multi-probe-policy`
named the same epoch, runtime ID and fingerprint, the fingerprint of the controller key; a sealed
lab was refused before signing (`LAB_FAULTED`). The first signed attempt of the session failed:
the `cloudflare_trace` worker exited with an error about a second after the window opened, the
helper faulted the lab and removed the tunnel cleanly (no wg0, underlay table or probe set left).
The helper discards the worker's stderr, so the cause is unknown; it matches the first-attempt
failure seen in Steps 29B.1 and 29B.2b. After deleting that lab, six attempts all succeeded
(2.9 to 4.0 s per controller command): two on one tunnel, and one on each of four more tunnels in
fresh create, connect and probe cycles, the last as the first attempt after a helper restart. Each returned the same VPN exit address from both
sources (egress A, not the host's address; since Step 36 the docs call the two VPN egress addresses of
the Lima runs egress A and egress B), `observed_at` equal to the Cloudflare
observation, and `network_ready: false`. After a successful attempt the lab verified as
`tunnel_configured`, the namespace had no process, the handshake was 16 s old, no
`egresslab_probe4` set or permit remained, and the output chain was back to the sealed rules
(`policy drop`; IPv6, DNS and DoT drops; `lo` accept). `disconnect` returned the lab to `sealed`
and `delete-lab` removed it. This V1 form was not run on WSL2; the V2 path ran there (see
"Generation-bound controller integration"). Not run on native Linux.

## Sticky IP

| Step | Content |
|---|---|
| 30A | Tunnel generations and sticky IP enforcement in the helper |
| 30B.1 | Signed generation binding and trusted evidence in the helper |
| 30B.2 | Controller integration and the V2 runtime cutover |

### Generation-scoped sticky IP (Step 30A)

Every managed tunnel gets a new generation before its first kernel change: `tunnelgen_` and 32 hex
characters, 128 random bits. A generation is one tunnel lifetime, not a profile, namespace or
helper process: disconnecting and connecting again, with the same profile, namespace and config,
starts a new generation. It is an identifier, not a secret or an authorization. A generation's
expected public IPv4 address starts unset and lives on the tracked tunnel itself, under the
namespace manager lock, in memory only: never on disk and never from IPC, the controller, a
single-source observation or an earlier tunnel.

Only a complete `ProbeConfiguredMulti` sets it, at the very end, once every source answered, every
window is closed and verified, the tunnel and a recent handshake with the expected peer are
verified, strict consensus holds and the deadline has not passed; the lock is held throughout. The
first such consensus pins the address; every later one must match it. There is no way to override,
replace or forget the pin of a live generation. Consensus and the pin are separate checks: two
sources agreeing on a new address pass consensus and still fail the pin
(`ErrManagedStickyIPChanged`). A violation, like any failure after the attempt starts, returns no
evidence, faults the tunnel and removes it; if the removal is not confirmed, the faulted generation
stays tracked with its original pin and refuses further probes. A failed attempt never sets or
changes the pin. A confirmed removal clears the backend's active tunnel, so the next connect starts
a new, unpinned generation. The single-source `ProbeConfigured` refuses to run on a multi-source
backend (even with a runner set by mistake), so its evidence cannot bypass the pin.

The pin detects a change only when a verification runs; EgressLab cannot make a provider keep an
address. It is not a lease, a reservation or proof that the address stays the same, and it says
nothing about other profiles (uniqueness comes separately). Step 30B.1 puts the generation in the
signed protocol (not the pin); no continuous monitoring and no application traffic exist.

Verified on Lima on 2026-11-25 with the real Proton tunnel (scratch Keychain key and profile,
removed afterwards), through the controller: two separately approved `probe-egress-multi` attempts
on one configured tunnel returned the same address from both sources (egress A), the
second passing the pin the first had set; afterwards the lab verified as `tunnel_configured` with
no namespace process, no probe set or permit and the sealed output chain, and `disconnect` and
`delete-lab` cleaned up. The first attempt of the session again failed in its `cloudflare_trace`
worker and faulted the lab; as in Step 29C.4c it was the first probe after a long idle period, and
a fresh lab then succeeded. A metadata-only `strace` of the helper (program names
and exit codes) during the successful cycle showed four workers exiting 0; the failure was not
captured. A provider changing its address was tested with a synthetic runner only, not provoked on
the real tunnel.

### Signed tunnel generation binding (Step 30B.1)

A `PermitMultiProbeV1` capability names the profile, namespace and pin, and the helper epoch, but
not the tunnel: one minted for a tunnel that was then disconnected and reconnected, unused and
still within its 30 s, would be accepted for the new tunnel. Replay protection does not help, as
it was never used. `PermitMultiProbeV2` closes this by signing the tunnel generation too. V1 keeps
its meaning and its bytes; the operation name is the policy version.

| | `PermitMultiProbeV1` | `PermitMultiProbeV2` |
|---|---|---|
| profile, namespace, pin, helper epoch, single-use nonce | yes | yes |
| tunnel generation | no | yes |
| trusted evidence record | no | yes |

`tunnel_generation` (`tunnelgen_` and 32 hex characters) is the last intent field and is omitted
when empty, so every earlier intent signs exactly the bytes it did before (all four earlier golden
vectors are unchanged); it is mandatory for V2 and refused on every other operation, including in
the helper's own validators for read-only, lifecycle, stage and single-source requests. A fifth
golden vector, cross-checked with OpenSSL 3, pins the V2 bytes.

`MultiProbeTarget{profile_id, namespace}` is read-only: it takes an intent naming the lab and never
a capability (`INVALID_REQUEST` otherwise). It answers one snapshot of the lab's tracked tunnel
generation and the V2 policy of this helper generation: `{profile_id, namespace,
tunnel_generation, policy: PermitMultiProbeV2, ident_ipv4, helper_id, runtime_id,
public_key_sha256}`. It reports helper state, not a verified kernel, and authorizes nothing; it
creates nothing, opens no window and consumes nothing, and does not wait behind a running
operation. A sealed lab has no tunnel to target (`INVALID_REQUEST`), a faulted one answers
`LAB_FAULTED`, and a generation the backend cannot vouch for or any uncertain state
`STATE_UNCERTAIN`.

For V2 the helper reads the current generation from the backend and builds the expected intent
from it and the trusted pin. A capability for another generation is `AUTHORIZATION_DENIED` before
its nonce is consumed; one for another pin is `INVALID_REQUEST`. The agent checks the generation
again under the namespace manager lock (`ProbeConfiguredMultiForGeneration`) and refuses a mismatch
before anything starts, leaving the tunnel untouched; the helper lifecycle lock is held throughout,
always taken before the manager lock. The evidence must name that generation (the one the agent
probed, never the one the request named) and the capability's nonce (`attempt_nonce`); V1
evidence carries neither field. The client checks the same, against its own request.

A successful V2 attempt records trusted evidence in the helper, in memory only: the signed intent,
the helper epoch, the nonce, the agreed address and the oldest observation time. It is never built
from anything a client sends, and it is neither a reservation nor a lease. It expires at the
earlier of 60 s after the helper accepted the capability and 60 s after the oldest observation, on
the monotonic clock; a reading earlier than the record, or a wall-clock step of more than 1 s
against monotonic time, makes it unusable. Since nothing recorded later could be used, a V2
attempt's context ends 60 s after acceptance (the cleanups keep their own deadlines). A refusal before the nonce is consumed and every read
leave it as it is. An accepted attempt drops it at once, a failed one leaves none, a sticky
violation drops it, and so do `Disconnect`, `DeleteLab` of that lab, a failed `VerifyLab`, a
reconnect and shutdown. Nothing consumes the evidence yet (Step 31). Expiry does not touch the
sticky pin.

A lifecycle built with `NewGenerationProbeLifecycle` enables V2 only: `PermitMultiProbeV1` and
`PermitProbe` are refused (`OPERATION_DISABLED` over the socket) and `MultiProbePolicy` advertises
`PermitMultiProbeV2`. A plain multi-source lifecycle keeps V1 and refuses V2 and
`MultiProbeTarget`. The installed helper was unchanged in this step: it kept the V1 lifecycle,
because the controller signed V1 only until Step 30B.2 switched both together. The V2 path was
tested with a fake kernel backend, including over a real Unix socket on Lima.

### Generation-bound controller integration (Step 30B.2)

The controller discovers `MultiProbeTarget` right before signing every multi-source verification
attempt and never reuses one: the profile binding outlives the tunnel, so the generation is not
stored in it. The target must name the profile and namespace of the binding, the trusted runtime,
the current helper epoch, the pinned public-key fingerprint and policy `PermitMultiProbeV2`
(`RUNTIME_UNTRUSTED` otherwise). The controller then signs `{PermitMultiProbeV2, profile, namespace,
probe_ipv4: the advertised pin, tunnel_generation}` with the usual nonce and 30 s lifetime; the
fifth golden vector, pinned in both modules, keeps the bytes identical. The capability travels on
stdin only: the launcher gets `multi-probe-target PROFILE_ID NAMESPACE` and `probe-egress-multi
PROFILE_ID NAMESPACE`, and no generation, nonce or destination. `egresslab-controller-lab
multi-probe-target PROFILE_ID NAMESPACE` prints the target read-only (no `-approve`).

The controller checks the evidence again, independently: everything of Step 29C.4c, plus the
signed generation and the nonce of the capability it sent (`attempt_nonce`). That is a
request-response binding, not a signature over the evidence; the helper stays the trusted runtime
that checks the kernel. The controller also requires the evidence to be younger than 60 s at
receipt, by its own clock against `observed_at` with no skew allowance; the helper's monotonic
evidence deadline stays authoritative. Evidence without the V2 fields answering a V2 request, or
with them answering a V1 one, is refused, as is a target or evidence on any other operation or
in a failure document.

The production multi-source mode now builds `NewGenerationProbeLifecycle`: `PermitMultiProbeV1`
and `PermitProbe` answer `OPERATION_DISABLED`, and `MultiProbePolicy` advertises
`PermitMultiProbeV2`. helperctl sends V2 only and refuses a V1 capability before contacting the
helper. There is no version negotiation, automatic retry or fallback, so an older controller and a
newer helper (or the reverse) refuse each other; upgrade helper, helperctl and controller together.
The V1 definitions and their golden vectors stay, covered by tests only.

A reconnect makes a new generation, even with the same profile, namespace, config and public
address. If the tunnel is reconnected between discovery and submission, the capability names the
old generation and the helper refuses it (`AUTHORIZATION_DENIED`) before consuming the nonce; the
controller does not discover again and re-sign by itself. A successful attempt creates the helper's
short-lived evidence record of Step 30B.1, not an egress lease: a controller-side check passing does
not mean the record is still usable, so Step 31 must check the helper's deadline. `network_ready`
stays `false`, and no application traffic or lease is authorized.

Verified on Lima on 2026-11-25 after installing the helper, helperctl and worker built from this
step, with the real Proton tunnel, a scratch Keychain key and a scratch profile (both removed
afterwards; the provisioned pin was unchanged), VM and host clocks within 0.1 s. The helper logged
policy `PermitMultiProbeV2`, and `multi-probe-policy` returned it with the epoch, runtime ID and
fingerprint of `helper-info`, the fingerprint of the controller key. The Step 30B.1 controller
(V1) refused the V2 helper's policy as `RUNTIME_UNTRUSTED`, also for a configured tunnel, before
signing anything. On a sealed lab `multi-probe-target` answered `INVALID_REQUEST` and the probe
`LAB_FAULTED`. The first signed attempt of the session, the first probe after the helper started,
failed again in its `cloudflare_trace` worker about a second after submission, and the helper
faulted the lab and removed the tunnel cleanly (only `lo` left, no process, no probe set). On a
fresh lab, two attempts on one tunnel (3.0 and 2.9 s per controller command) returned the
generation `multi-probe-target` had reported, the same address from both sources
(egress A), two different 32-hex nonces and `network_ready: false`. After `disconnect`,
`multi-probe-target` answered `INVALID_REQUEST`; the reconnect got a different generation, and an
attempt on it returned that generation, the same address and a new nonce. The lab then verified as
`tunnel_configured` with no namespace process, no `egresslab_probe4` set or permit and the sealed
output chain, and `disconnect` and `delete-lab` cleaned up. The stale-generation refusal is covered
by tests only (no capability was minted by hand), and the path was not run on native Linux.

Verified on WSL2 (Ubuntu 22.04, Linux 6.6, nft 1.0.2, iproute2 5.15) on 2026-11-25, with the helper,
helperctl and worker built from this step, the Windows controller (DPAPI key) through `wsl.exe`, the
same real tunnel, and an ident.me pin provisioned on WSL2 as in `docs/DEV-LINUX-VM.md` (AS24940,
pinned HTTPS with a valid certificate), VM and host clocks within the same second. The helper logged
`PermitMultiProbeV2` and the pin, and `multi-probe-policy` returned them with the epoch, runtime ID
and fingerprint of `helper-info`. On a sealed lab `multi-probe-target` answered `INVALID_REQUEST`;
on the connected tunnel the single-source `probe-egress` answered `OPERATION_DISABLED`. The first
attempt succeeded this time; the helper had just been restarted after a single-source session whose
first probe failed (see "Probes from the controller"). Three attempts (2.9 to 3.1 s each) returned
the same address from both sources, the same exit address as on Lima, and `network_ready: false`:
two on one tunnel, with the generation `multi-probe-target` had reported and different nonces, and,
after `disconnect` (`multi-probe-target` then answered `INVALID_REQUEST`) and a reconnect, one with
the new generation and a new nonce. Afterwards the lab had no process and no `egresslab_probe4` set
or permit, the sealed ruleset remained, and `verify-lab` answered `tunnel_configured`; `disconnect`,
`delete-lab` and the helper's stop left no namespace, underlay table or worker process.

## Egress candidates

| Step | Content |
|---|---|
| 31A | Trusted evidence consumption and a local candidate in the helper |
| 31B | A shared atomic IP registry in the controller |
| 31C | Durable reservations and inter-process locking |
| 31D.1 | Signed candidate transport and durable reservation orchestration |
| 31D.2 | Authority provisioning and controller CLI integration |
| 31D.3a | Helper-owned prepared lease |
| 31D.3b | Signed lease integration in the controller |
| 31D.3c | Generation-bound revocation |
| 31D.3d.1 | Durable release journal and release admission |
| 31D.3d.2 | Controller revocation transport and the release command |
| 31D.3e | Complete reservation lifecycle smoke test |
| 31E | Concurrent collision and recovery tests |
| 31E.1 | Real multi-runtime IP collision test |
| 31E.2 | Concurrent reservation and release races |
| 31E.3a | Persistent helper epoch witness |
| 31E.3 | Reboot-bound reservation recovery |
| 32 | Continuous egress monitoring of a prepared generation |
| 33 | Kernel-timed traffic gate (kill-switch) |
| 34 | SOCKS5 proxy runtime |
| 35 | Endpoint-to-runtime integration; several streams per runtime |

The states stay separate; none of them is an `active` flag:

| State | Meaning |
|---|---|
| Observation | an address seen by one probe |
| Verified evidence | a V2 attempt the helper checked (Step 30B.1), for 60 s at most |
| Local candidate | that evidence, consumed once, bound to its tunnel generation (Step 31A) |
| Global reservation | an address held exclusively by the shared authority (Steps 31B, 31C) |
| Prepared lease | a reservation bound by the helper to its tunnel generation (Step 31D.3a); not active |
| Retired generation | a candidate's tunnel generation whose removal the helper confirmed (Step 31D.3c), for its epoch only |
| Monitoring health | a prepared generation's address verified again by the helper (Step 32), for 60 s at most; renews no evidence or authorization |
| Traffic window | a kernel-timed gate for the proxy user of the prepared generation (Step 33), 10 s at most, on fresh monitoring health; opened again and again by a proxy stream (Step 34) |
| Proxy stream | one signed IPv4 TCP stream through those windows (Step 34); it ends with the prepared lease |
| Active lease | the right to use the address as a whole (later steps): DNS and the desktop's control |
| Network ready | application traffic allowed |

`EgressCandidateRegistry` and the lease registry of the earlier lab CLIs are not that authority:
they take observations from their caller, keep no helper epoch or tunnel generation, and lock one
process only. Two runtimes, each with its own helper, can see the same exit address.

### Trusted egress candidate reservation (Step 31A)

`ReserveEgressCandidateV1{profile_id, namespace, probe_ipv4, tunnel_generation, evidence_nonce}`
consumes the helper's verified evidence of one `PermitMultiProbeV2` attempt. `probe_ipv4` is the
ident.me pin of that attempt's source policy and `evidence_nonce` its capability nonce; no field
names an address, which comes only from the helper's evidence. The intent is signed like the others
(the sixth golden vector, cross-checked with OpenSSL 3), and only this operation may carry an
`evidence_nonce`. Only the generation-bound (V2) lifecycle answers it; a Step 31A helper in any
other mode answers `OPERATION_DISABLED`. An older helper rejects the request frame itself, because
its strict decoder does not know `evidence_nonce`, and the client reports that as an invalid
response, not as `OPERATION_DISABLED`; recognizing older helpers is still open: through the
controller transport (Step 31D.1) that reply is an uncertain outcome, while an older helperctl,
which does not know the command, answers `INVALID_REQUEST`.

Before accepting the capability, under the lifecycle lock, the helper requires a configured tunnel
(`INVALID_REQUEST` for a sealed lab, `LAB_FAULTED` for a faulted one), fresh evidence
(`EVIDENCE_UNAVAILABLE` when there is none, it expired or it was consumed), a request equal to the
one intent that evidence backs, the V2 policy with the evidence's helper epoch and pin, the
evidence's tunnel generation as the current one, and a reservation nonce other than the evidence's
(`AUTHORIZATION_DENIED` otherwise, also for a bad or expired signature). These refusals leave the
evidence untouched.

Accepting the capability consumes the evidence, under the same lock: two requests for one attempt,
even with different signed nonces, yield at most one candidate (the other gets `LAB_BUSY` or
`EVIDENCE_UNAVAILABLE`). From then on nothing restores it. The helper verifies the tunnel again
(link, firewall, underlay, peer, addresses and routes) and checks that the generation did not
change; any failure faults the lab and removes the tunnel as `VerifyLab` does, and returns no
candidate. The receipt names the profile, namespace, generation, V2 policy and helper identity, the
evidence and reservation nonces, the address, `observed_at` and `expires_at`, with
`network_ready: false`; the client checks it against its request and refuses it once expired.

The candidate keeps the evidence's own deadline: consuming evidence 20 s after it was recorded
leaves 40 s, not a new 60. `expires_at` is wall-clock metadata; the helper keeps the monotonic
deadline, and the verification runs under it. If the deadline passes during that verification, the
lab is faulted like any other failed verification. The helper holds one candidate; a new authorized
attempt, `Disconnect`, `DeleteLab`, a reconnect, a failed verification or cleanup and helper
shutdown drop it, and an expired one is no longer fresh. A candidate is not a global reservation, an
active lease or permission to send traffic: two helpers can still produce candidates for the same
address, and the shared authority decides durable ownership afterwards (Steps 31B to 31D.1).
helperctl sends it since Step 31D.1 and the controller's `reserve-egress` since Step 31D.2; the tests
use real Unix sockets and signatures with the fake kernel backend, and it ran on a real tunnel in
Step 31D.3e (`docs/DEV-LINUX-VM.md`). In Step 31E.1 two Lima runtimes produced candidates for the
same address, and the authority refused the second one with `EGRESS_IP_COLLISION`.

### Shared atomic reservation registry (Step 31B)

A local candidate does not make an address unique across runtimes. The controller's reservation
registry (`internal/control/egress_reservation.go`, see `docs/ARCHITECTURE.md`) admits a candidate
only when the helper's receipt agrees with the trusted runtime, the original signed V2 probe and the
signed reservation request, and the receipt must come from the trusted runtime transport, never from
user input. Checking the controller's own signatures proves that this controller issued the
capabilities, not that the helper ran them: the receipt carries no helper signature. Under one mutex
the registry checks and holds one public IPv4 for one tunnel owner (profile, runtime, helper epoch,
namespace, tunnel generation), so no two profiles or runtimes using the same registry instance hold
the same address; a profile holds at most one reservation, and a reconnect or a move to another
runtime does not get a second one. Expiry never releases a hold. A reservation is not a lease:
before any later activation the helper must confirm its candidate and local deadline again. The
sixth golden vector is pinned in both modules now. Step 31C makes the registry durable and shared
between processes, and Step 31D.2 puts it behind a provisioned authority; application traffic stays
disabled.

### Durable reservations and process coordination (Step 31C)

The shared authority now lives in an append-only journal in the per-user authority directory (Step
31D.2), under an exclusive OS file lock for every write (`LockFileEx` on Windows, `flock` on Linux
and macOS; see `docs/ARCHITECTURE.md`); since Step 35 reads take it shared. Every reservation attempt reloads and validates the whole journal under
that lock before it checks uniqueness, appends one checksummed record and flushes it, so two
controller processes using the same journal cannot hold the same address, and a process started
later still sees it held. A process exit releases the lock, not the ownership. Records read back are
recovered holds: without the monotonic clock of the process that wrote them they keep their address
but never authorize an activation, and expired holds keep their address too. An incomplete or
invalid journal blocks every reservation and inspection; nothing truncates it or replaces it with an
empty one, and a missing journal is refused, never created implicitly. The helper's candidate and
its monotonic deadline stay authoritative for any later activation. There is no release and no lease
activation yet, and application traffic stays disabled.

### Signed candidate transport (Step 31D.1)

`egresslab-helperctl reserve-egress-candidate PROFILE_ID NAMESPACE` takes the signed
`ReserveEgressCandidateV1` capability on stdin and nothing else: no address, generation, evidence
nonce or expiry in argv, and the client refuses a capability whose intent names another profile or
namespace before it contacts the helper. The address in the receipt comes only from the helper's
verified evidence. The controller's transport sends the capability once, maps
`EVIDENCE_UNAVAILABLE`, and accepts a receipt only when it is well formed and names the signed
profile, namespace, generation, pin, helper epoch and both nonces; a lost response, a runtime
failure or a mismatched receipt is an uncertain outcome (`STATE_UNCERTAIN`), because the helper may
have consumed the evidence. The controller workflow (`docs/ARCHITECTURE.md`) checks the journal
first, discovers the generation, signs one `PermitMultiProbeV2`, validates the observation, signs
one `ReserveEgressCandidateV1` for exactly that attempt and validates the receipt against the
original generation-bound probe; the durable registry then arbitrates ownership across all
participating runtimes. An unsuccessful global reservation restores no evidence and authorizes no
application traffic, and candidate freshness and generation identity must be checked again before
any later lease preparation. Step 31D.2 runs the workflow from `reserve-egress`; it first ran on a
real tunnel in Step 31D.3e.

### Provisioned reservation authority (Step 31D.2)

The production controller workflow runs only against an explicitly provisioned authority (`-approve
init-reservations`), whose marker and journal must agree with the controller's current signing key;
runtime configuration overrides such as `EGRESSLAB_DATA_DIR` do not select another authority (see
`docs/ARCHITECTURE.md`). `-approve reserve-egress PROFILE_ID NAMESPACE` checks the trusted runtime,
the profile's binding and the helper's configured lab, then signs and submits one
`PermitMultiProbeV2` and one `ReserveEgressCandidateV1` and commits the address durably; a profile
bound to another runtime, or a sealed lab, is refused before anything is signed. A successful run
persists an exclusive IPv4 hold. The helper-local candidate may expire or be dropped after the hold
is committed, and no CLI receipt authorizes application networking: a future signed lease
preparation must revalidate the candidate against the exact tunnel generation, evidence nonce,
reservation nonce and authority. Holds are not released on expiry, controller exit or tunnel
teardown, so the command was not run against a real tunnel until the release command (Step
31D.3d.2) existed; Step 31D.3e ran it on Lima. On Windows on 2026-11-25, `-approve init-reservations` provisioned the
per-user authority in `%APPDATA%\EgressLab` with the controller's DPAPI key (the fingerprint pinned
for the trusted WSL2 runtime), `list-reservations` listed it with no reservations, the 91-byte V2
journal header carried the SHA-256 of the 210-byte marker, no temporary file was left, and a second
`init-reservations` answered `RESERVATION_AUTHORITY_EXISTS`.

### Signed lease preparation (Step 31D.3a)

`PrepareEgressLeaseV1` consumes the helper's local candidate and binds it to a controller-signed
durable reservation. The intent binds the profile, runtime, namespace, tunnel generation, authority
ID, reservation ID, the source policy's pin, the verified public IPv4 and the original evidence and
candidate reservation nonces; the capability adds the helper epoch and a preparation nonce of its
own. `probe_ipv4` stays the ident.me pin, `egress_ipv4` is the reserved address; the helper rebuilds
every network-related field from its own candidate, so only the authority and reservation IDs come
from the controller, and the controller cannot change the address. The helper does not read or
attest the controller's journal: the controller must sign the preparation only after its durable
uniqueness transaction committed (Step 31D.3b). Under the lifecycle lock the helper requires the
configured tunnel, its current generation and policy, a fresh candidate and a request equal to the
one intent that candidate backs; these refusals leave the candidate untouched
(`AUTHORIZATION_DENIED`, `EVIDENCE_UNAVAILABLE`). Accepting the capability consumes the candidate
for good; the helper then verifies the tunnel again, the sealed firewall included, and checks that
the generation did not change, faulting the lab and removing the tunnel on any failure as
`VerifyLab` does. The prepared lease keeps the original monotonic evidence deadline; preparation
adds no time and nothing refreshes it. One prepared lease occupies the tunnel slot: a second
preparation answers `LAB_BUSY`, and so do a new diagnostic probe and a new candidate, even after the
lease expired, until a disconnect, `DeleteLab`, a failed verification, a reconnect or helper
shutdown drops it. Dropping it is not proof of a confirmed kernel cleanup and never releases durable
ownership. The receipt carries `network_ready: false`, and no application traffic is opened.
helperctl and the controller send it since Step 31D.3b; the tests use real signatures and a real
Unix socket with the fake kernel backend.

### Controller preparation integration (Step 31D.3b)

helperctl exposes `prepare-egress-lease PROFILE_ID NAMESPACE` with the signed capability on stdin;
argv names no authority, reservation or address. `reserve-egress` now runs the verification, the
candidate, the durable reservation and the preparation in one approved operation, so it signs three
capabilities: `PermitMultiProbeV2`, `ReserveEgressCandidateV1` and `PrepareEgressLeaseV1`. The
controller signs the preparation only for the live hold this operation just committed, after
confirming the matching record in its authority's journal; a reservation read back from the journal
never authorizes one. The capability binds the authority, reservation, runtime, helper epoch, tunnel
generation, verified address and both candidate nonces. The controller requires at least 5 s of
eligibility left when it signs and sends, so the helper never starts its tunnel verification with
the deadline about to pass; the original evidence deadline is never extended. It accepts the receipt
only when it matches both the signed capability and the durable hold, the evidence timestamps and
the key fingerprint included. A prepared lease receipt activates no application traffic. A lost,
rejected or late preparation answers `EGRESS_PREPARATION_UNCONFIRMED`: the durable hold stays,
nothing is retried or released, and the helper may or may not hold a prepared lease. The command
first ran against a real tunnel in Step 31D.3e, once a hold could be released.

### Generation-bound revocation (Step 31D.3c)

Dropping the local candidate or prepared lease proves no cleanup: `invalidateEvidenceLocked` runs
before the kernel cleanup, whatever its outcome. The helper therefore keeps a retirement record for
every candidate receipt it returns, created under the lifecycle lock before the receipt and kept
apart from the candidate's and the lease's freshness: the original candidate (profile, namespace,
generation, runtime, helper epoch, key fingerprint, address and nonces), the authority and
reservation bound by the first accepted preparation or revocation (never changed afterwards), the
preparation nonce, and whether the generation is retired. It holds no capability or key. At most
1024 records exist per helper epoch; at the limit a new candidate is refused (`LAB_LIMIT`, before
its evidence is consumed), and nothing is evicted or expired, because an old record may still back
a durable hold. A helper restart loses them all, and a missing record never implies retirement.

A record is retired only when `CleanupStage` of the managed tunnel backend succeeded for the slot
that tracked its generation; the backend clears its active tunnel only after the WireGuard link is
confirmed gone and the underlay table deleted. If the backend names another generation than the
one the slot tracks, at any read while the slot holds it, the contradiction is remembered until the
slot is released: a faulted tunnel that later names no generation cannot turn it into proof, and no
new candidate or preparation is accepted on that generation. The cleanup still runs but proves
nothing: the lab is faulted and the answer is `STATE_UNCERTAIN`, also
for `DeleteLab` (a second `DeleteLab` removes the namespace). A failed
cleanup proves nothing either and keeps the slot. A connect is refused while the slot still tracks
a candidate-bearing generation.

`RevokeEgressLeaseV1` carries the same fields as `PrepareEgressLeaseV1` with its own operation, so
no preparation capability can serve as a revocation. The helper rebuilds every network field from
the retained record and needs no fresh evidence: an expired or never-prepared candidate, or one
whose preparation failed or lost its response, can be revoked. Unless the record is already
retired, the slot must still track exactly that generation, in a configured or faulted lab; a
configured tunnel whose generation cannot be read, or a backend naming another generation, is
`STATE_UNCERTAIN`, before the capability is consumed. The signed capability is then consumed, and
the helper disconnects the tunnel (`Disconnect`'s cleanup, ignoring `blockCreation`, which only
stops new resources). The receipt follows the confirmed retirement alone: a sealed lab that fails
its check after the cleanup, or runs out of the operation's time there, is faulted but still gets
its receipt, and the cause is logged off the lifecycle lock and off the response path. A record that is already retired is confirmed without touching the slot, so
a late revocation of generation A never disconnects a newer generation B. The receipt
(`revoked_lease`) names the signed intent, the helper epoch, the key fingerprint and the revocation
nonce, with `generation_retired: true` and no deadline. A replayed capability is refused; a fresh
signed one confirms the same retirement without another cleanup, which is how a lost receipt is
recovered. A revocation answering `STATE_UNCERTAIN` says to keep the helper running, unlike the other
operations: a restart loses the records, while the same epoch can still confirm the retirement with
a new signed revocation once `list-labs` and `recover-scan` show the cause. helperctl sends it with `revoke-egress-lease PROFILE_ID NAMESPACE` and the capability on
stdin only; there is no unsigned revocation by reservation ID, and `disconnect` stays an emergency
cleanup that releases nothing durable.

The receipt proves the retirement of one managed generation within the helper backend's cleanup
contract, not that the runtime carries no other traffic. No durable reservation is released in this
step, no controller signs a revocation yet (Step 31D.3d.1 pins the eighth golden vector and the
durable release, Step 31D.3d.2 adds the signer and the command), and application networking stays
disabled. It is tested with real signatures and a
real Unix socket on Lima, against the fake kernel backend, and ran on the real kernel in Step 31D.3e.

### Durable release admission (Step 31D.3d.1)

The controller's authority can append a release of one hold to its journal (`docs/ARCHITECTURE.md`,
"Durable release journal"), only with a retirement receipt for exactly that hold: the receipt must
answer a `RevokeEgressLeaseV1` capability this controller signed (checked against the pinned public
key) and submitted while it was valid, name the hold's authority, reservation, profile, namespace,
runtime, tunnel generation, address and nonces, and come from the hold's own helper epoch, trusted
runtime and controller key. The intent is rebuilt from the hold itself, so a recovered or long
expired hold can be released: revocation never needs fresh probe evidence, and the cleanup may
outlast the capability's 30 s. The receipt's chronology is checked against the hold and the
controller's clock.

The controller's signatures authorize its requests; they do not authenticate the helper's receipt,
so only a response from the trusted runtime transport can supply retirement evidence, never a receipt
someone imports. A timeout, an expired or missing prepared lease or a lost receipt never authorizes a
release; a helper restart loses its retirement records, so a hold of an earlier epoch cannot be
released yet. The journal keeps every reservation ID and owner after their release. The eighth golden
vector pins the revocation's bytes in both modules. The revocation transport, its signing
orchestration and the release command came in Step 31D.3d.2.

### Controller revocation transport (Step 31D.3d.2)

`egresslab-controller-lab -approve release-egress RESERVATION_ID` takes nothing but the ID: the
profile, namespace, runtime, helper epoch, generation, address and nonces come from the durable hold
itself, so the wrong tunnel cannot be named. The controller reads the hold, requires the runtime the
provider selects to be the hold's trusted runtime, asks that runtime for `HelperInfo` and requires
the hold's own helper epoch and key, and only then signs one `RevokeEgressLeaseV1`, which helperctl
receives on stdin (`revoke-egress-lease PROFILE_ID NAMESPACE`). A different helper epoch, after a
restart, cannot attest the retirement of the original generation, and is refused before anything is
signed; after a reboot of the guest, `recover-egress` handles that hold (see "Reboot-bound reservation
recovery"). Release needs no fresh probe evidence and no surviving profile, binding or lab: a lab
already disconnected or deleted is no obstacle, since the helper kept its retirement record.

The receipt must match the reservation, authority, generation, helper epoch, runtime and revocation
nonce of the capability sent, and the controller checks it before it opens the journal, then again
under the journal's lock (see "Durable release admission"). A lost, uncertain or mismatched receipt
keeps the hold (`EGRESS_REVOCATION_UNCONFIRMED`, with the controller's own advice to keep the helper
running, since a restart loses its retirement record, and the helper's when it sent one); a newly
approved `release-egress` signs a fresh capability, and the helper confirms the
retirement it already recorded without another cleanup. A busy journal, or a hold released by
another process meanwhile, after a confirmed retirement keeps the hold too
(`EGRESS_RELEASE_UNCONFIRMED`), and a failed write is `STATE_UNCERTAIN`: inspect `list-reservations`.
A release written but not reported is `STATE_UNCERTAIN` as well, also when the reader closed stdout
(the CLI ignores `SIGPIPE`, so the write fails instead of ending the process), and is never rolled
back. The
durable authority never accepts a retirement receipt supplied from outside, and nothing is retried,
forced or replaced by an unsigned `disconnect`. Step 31D.3e ran it against the real tunnel on Lima
(`docs/DEV-LINUX-VM.md`, "Reservation lifecycle smoke test"); application networking stays disabled.

### Persistent helper epoch witnesses (Step 31E.3a)

Before Step 31E.3, a hold whose helper crashed could not be released: the new epoch cannot attest
the retirement of the old generation, and a namespace, WireGuard interface or socket can outlive the process that made
it. The recovery of Step 31E.3 uses a real reboot of the Linux guest as the
boundary that ends the old generation, which needs a trusted record of the boot each helper epoch
belonged to. This step only records it.

A helper started with `-enable-multi-probe`, the only mode that serves `ReserveEgressCandidateV1`,
`PrepareEgressLeaseV1` and `RevokeEgressLeaseV1`, registers its epoch before it creates the IPC
listener, while it already holds the vault lock:

| Identity | Changes when |
|---|---|
| Runtime ID | the Linux installation changes |
| Helper epoch | the helper process restarts |
| Boot ID | the Linux kernel reboots (`/proc/sys/kernel/random/boot_id`) |
| Tunnel generation | the managed tunnel reconnects |

- Each witness binds the helper epoch to its runtime ID, the kernel boot ID and the controller's
  public-key fingerprint. The boot ID comes only from the kernel; no client, flag or file supplies
  it.
- The ledger `helper-epochs.json` lives in the root-owned `0700` vault directory under the existing
  exclusive vault lock, not under the volatile `/run`. It must be root-owned, regular, `0600` and
  have one link, and is read only in its canonical encoding with a SHA-256 over the entries, so
  unknown or duplicate fields, duplicate epochs, invalid IDs, truncation, another version, an
  oversized file or a value changed into another well-formed one are refused. The checksum detects
  corruption, not root in the runtime.
- An update keeps every earlier entry and replaces the file atomically: a private temporary file is
  written and synced, renamed over the ledger, and the directory synced. An epoch is never
  registered twice, and an existing entry never changes.
- The ledger holds at most 4096 epochs and evicts none, since an old epoch may still own a durable
  hold; at that limit a multi-probe helper refuses to start, so capacity and a recovery-only start
  must be handled before long-term use.
- A corrupt or unsafe ledger, or any write failure, refuses the start: the socket is never
  created. A missing ledger is created for the new epoch, which proves nothing about earlier
  epochs; an epoch without a witness can never use the reboot-bound recovery.
- An unsafe socket directory or a leftover `helper.sock` (after a crash) refuses the start before
  the epoch is recorded, so repeated refused starts do not use up the ledger. A start that fails
  later, while creating the socket, keeps its witness, which authorizes nothing.

A witness is not a retirement receipt and authorizes no release by itself; the reboot-bound recovery
of Step 31E.3 builds on it. A helper restart within one boot is never enough; a missing witness, a
wrong runtime or controller key, or a corrupt ledger refuses; a timeout or an empty recovery scan
releases nothing. Recovery assumes the Linux guest is a trusted runtime, never cloned, rolled back to a
snapshot or restored onto an old kernel; it is not hardware-backed attestation. Holds made before
this step, whose helper is gone, stay unreleasable; there is no forced release.

### Reboot-bound reservation recovery (Step 31E.3)

`egresslab-controller-lab -approve recover-egress RESERVATION_ID` may release an orphaned
reservation only after the trusted runtime confirms a kernel reboot. It is a separate, explicitly
approved command, never a fallback when `release-egress` fails:

| Command | Requires |
|---|---|
| `release-egress` | the hold's original helper epoch, with its retirement record |
| `recover-egress` | a later epoch of the same runtime and key, witnesses of both epochs, and a guest kernel reboot in between |

- The controller rebuilds the hold's `RevokeEgressLeaseV1` intent and signs it as
  `RecoverRetiredGenerationV1` with one more field, `original_helper_id`, the hold's epoch; the
  capability's `helper_id` names the recovering epoch. The field is omitted from every other
  operation, so their signed bytes do not change, and the ninth golden vector pins the new one in
  both modules. The controller refuses before signing when the runtime still reports the original
  epoch.
- The helper verifies and consumes the capability, then reads its witness ledger and the kernel's
  boot ID: both epochs must have witnesses with the same runtime ID and key fingerprint, the current
  epoch must be the latest witness and run on the current boot, and the two boot IDs must differ. It
  touches no network resource; the reboot already ended the old generation. The receipt is a
  `RevokedLeaseInfo` naming the recovery intent and both boot IDs; it travels the same helperctl
  command (`revoke-egress-lease`), and the signed operation tells the two apart.
- The existing release transaction validates the receipt: a revocation only from the original epoch,
  a recovery only from another one, naming exactly that hold and its epoch, with two distinct boot
  IDs; then it locks, reloads, compares the exact hold, appends and syncs one release record. Journal
  replay applies the same check. There is no new record type, journal or store.
- Same-boot restarts, missing witnesses, wrong identities, a corrupt ledger and uncertain
  persistence fail closed with the hold kept: a refusal from the helper is
  `EGRESS_REVOCATION_UNCONFIRMED`, with the advice to check `list-reservations`. Nothing is retried.
- Older journals stay readable. A controller built before this step reports a journal holding a
  recovery release as `RESERVATION_JOURNAL_CORRUPT`, which refuses everything but changes nothing:
  every controller that shares the authority must be upgraded before the first recovery, and there is
  no downgrade afterwards.

VM cloning, snapshot rollback and untrusted root administration are outside the guarantee.
Application networking remains disabled. Step 31E.3 ran it on Lima through a real helper crash and
guest reboot (`docs/DEV-LINUX-VM.md`, "Crash and reboot recovery smoke test").

### Continuous egress monitoring (Step 32)

A provider can change the public address while the WireGuard tunnel stays up. A helper started with
`-enable-multi-probe` therefore runs a monitor, owned by its startup, that re-verifies the prepared
lease's exact tunnel generation:

| Setting | Value |
|---|---|
| Interval | 20 s, earlier when the health would expire within one probe budget |
| Probe budget | 30 s, never past the current health deadline |
| Tick | 1 s (a due check only; no probe) |
| Policy | the mandatory V2 policy: Cloudflare and the ident.me pin, unanimous |

- The monitor mints no capability and creates no evidence, candidate or authorization. It reuses the
  backend's generation-bound probe and the same observation checks as a signed attempt (timestamps,
  handshake, both sources and their consensus), split out of the capability check
  (`validMultiProbeObservation`), and checks the generation before and after the probe.
- A success renews only the prepared generation's monitoring health, at most 60 s after its oldest
  source observation. The original evidence and the prepared receipt keep their own deadline and
  are never renewed: a receipt never becomes a new authorization.
- A changed address, a disagreement between the sources, a probe failure, a changed generation or
  policy, or expired health faults the lab, drops its local authorization and cleans up the tunnel.
- A source that gives no answer, with the tunnel verified unchanged (since Step 36), renews nothing
  and faults nothing:
  - the health keeps its expiry, and the check runs again 2 s later;
  - no traffic window opens until a check succeeds, so new streams wait;
  - established streams still flow through the monitor's overlay during the checks, until 14 s
    before the expiry;
  - if no check succeeds before the health expires, at most 60 s after the last source observation,
    the tunnel is faulted as before, also when a check without an answer itself ends past it.

  A path that answers nothing is therefore cut when the health expires rather than at the first
  failed check, though nothing new crosses it meanwhile. An address change is still caught by the
  first source that answers. This is a bounded re-check, not a retry: the attempt still renews
  nothing without two sources that agree.
  A confirmed cleanup retires the generation in the existing retirement record, so `release-egress`
  then releases the hold; a failed cleanup, or a generation the backend contradicted, retires
  nothing, and the hold stays. The durable hold always stays with the controller; nothing reserves
  a new address.
- The monitor takes the lifecycle lock with `TryLock`: a busy lifecycle skips the check and renews
  nothing, and health that expired meanwhile faults the tunnel at the next check. While a monitor
  probe runs (a few seconds in every check), other lifecycle operations answer `LAB_BUSY`, release
  and disconnect included; the controller does not retry, so the operator approves the command
  again. Teardown has no priority over a running probe.
- Its log lines go through a bounded queue: a stalled log sink drops lines rather than stop the
  monitor or the helper's shutdown, which stops the monitor before closing the labs and the vault.
- A failed probe worker now names a fixed reason in the helper's error (`HTTPS_REQUEST_FAILED`,
  `HTTPS_NO_ANSWER` since Step 36, `WORKER_PRIVILEGE_CHECK_FAILED`, `WORKER_STATUS_UNAVAILABLE`, `WORKER_INVALID_REQUEST`,
  `WORKER_EXECUTION_FAILED`); its raw stderr is never logged.

Polling cannot detect an address change instantly, and a preparation that lands close to its
evidence deadline leaves the first check little time, so it may fault. The controller, the journal
and the IPC protocol did not change. Application networking remains disabled; kernel-level
enforcement and the right to open application traffic belong to Steps 33 and 34.

### Kernel-timed traffic gate (Step 33)

A hung or crashed helper cannot be trusted to close network access, so the expiry lives in the
kernel. The data-plane gate reuses the probe window's design (Step 29) with a different set:

| Object | Content |
|---|---|
| `egresslab_app4` | a one-element `ifname` set holding `"wg0"`, `timeout 10s`, expired by the kernel |
| output permit | `meta nfproto ipv4 oifname @egresslab_app4 meta skuid UID meta l4proto tcp ct mark set MARK accept` |
| input permit | `meta nfproto ipv4 iifname @egresslab_app4 meta l4proto tcp ct state established ct mark MARK accept` |

- Both permits match through the set, so neither direction survives the element: there is no
  unconditional "established" accept, and an open connection stops passing data in either
  direction when the element expires. The sealed IPv6 drop and DNS drops (53, 853) still come
  first, and UDP, other UIDs and root stay closed by the drop policies.
- The output permit marks the connections it admits (`MARK` is `0x65676c01`; no other lab rule sets
  a mark), and only replies of marked connections come back. A flow admitted earlier, such as a
  probe's connection still in conntrack, gets nothing through an open gate.
- The UID is the dedicated proxy user (`egresslab-proxy`), from trusted local provisioning; never
  from an application or an IPC request.
- One shared verifier (`verifyTimedWindowPolicy`) checks any timed window: exactly its set and two
  permits, each last in its chain, and the sealed policy for everything else. The gate's permits
  are compared with the canonical form nft 1.0.9 printed (real captures in
  `testdata/nft-lab-traffic-*.json`); another rendering is refused.
- `withTrafficGateLocked` opens the gate only while the health it rests on outlasts the whole kernel
  timeout and a 2 s close budget (otherwise it refuses before writing anything), verifies the active
  gate on a readback, runs the worker with a deadline 1 s before the element can expire, and always closes the gate with its own context:
  only the verified objects are deleted, and the sealed policy is required afterwards. An
  unconfirmed close marks the namespace drifted. The gate is never recorded as a session baseline,
  so a Reconcile cannot bring it back after a crash.
- `ManagedTunnelBackend.WithTrafficWindow` requires the exact namespace, tunnel generation and
  sticky address of a configured, unfaulted tunnel, a verified tunnel and an idle namespace before
  and after the window (probe and traffic windows never overlap). `LabLifecycle.
  WithPreparedTrafficWindow` adds the exact prepared reservation and fresh monitoring health, gives
  way to a due monitor check (`LAB_BUSY`), and never runs past the monitor's renewal deadline (30 s
  before the health expires; until Step 34, the next routine check); it needs more than 14 s of that
  left. A refusal before anything opened is `LAB_BUSY` and leaves the tunnel; any other failed window
  faults the tunnel, and the durable hold stays.
- Since Step 34 windows chain through the routine check interval, so the gate closes only while the
  monitor probes. Bounded to the routine check, a window could start only in the first ~6 s of a
  ~23 s cycle, and a server-push TCP stream stalled for good (see "SOCKS5 proxy runtime").
- Only the proxy stream of Step 34 opens it; no IPC operation exposes the primitive itself.

### SOCKS5 proxy runtime (Step 34)

`egresslab-controller-lab -approve serve-socks RESERVATION_ID PORT` listens on `127.0.0.1:PORT`
only, with a random username and password shown once at start, and carries SOCKS5 CONNECT for
IPv4 destinations. Domain names (no safe resolver yet), IPv6, BIND and UDP ASSOCIATE are refused, as
are the probe sources (Cloudflare, the ident.me pin), DNS ports, private and reserved addresses. It
runs in the foreground until interrupted and changes no global readiness.

- **Authorization per CONNECT.** The controller reads the trust record again, asks the runtime for
  `HelperInfo` and signs one `OpenProxyStreamV1` for the hold's own helper epoch: the preparation
  intent of the hold plus `destination_ipv4` and `destination_port` (appended, omitted elsewhere; the
  tenth golden vector pins them). The durable hold only proves ownership: the helper also requires
  its prepared lease for that reservation and fresh monitoring health, so a recovered hold never
  opens a stream.
- **Socket handoff.** `egresslab-proxy-dial` runs inside the lab namespace through `setpriv` as the
  dedicated proxy user (no groups, capabilities or new privileges), connects, passes the socket to
  the helper over an inherited Unix socket (`SCM_RIGHTS`) and exits. The socket keeps the
  namespace's routes and firewall and its creator's UID, so the gate's `meta skuid` still matches,
  and no process stays in the namespace, which the monitor's probe requires. A failed dial is a
  SOCKS error with a coded reason in the helper log; it never faults the tunnel, and the helper never
  dials by itself.
- **Traffic windows.** Since Step 35 the streams of the prepared reservation share one keeper. It
  chains windows (6 s each, 250 ms apart) while any stream or request remains, giving way to a due
  monitor check; the gate closes only while the monitor probes. A request's capability is consumed
  on arrival, so the wait for a window cannot outlast it; inside an open window the keeper binds
  each queued request to the prepared lease (and refuses it if a wall-clock rollback has been seen
  since) and dials, but only while at least 6 s of the window are
  left (later requests wait for the next window), and every dial ends 2 s before the window's
  deadline, so its worker's cleanup never runs the window past it; a late dial may hold the window
  past 6 s, never past its deadline. A stream's own failure never fails the window. The last stream
  to end ends the windows. At most eight streams per helper, admitted and waiting together: each
  keeps one of the helper's sixteen connections, and a ninth is refused with `LAB_BUSY` before its
  capability is consumed. A client that half-closes keeps its download; while the download runs, one
  whose connection to the helper is gone entirely (the socket reports a hang-up) ends its stream even
  if the destination neither sends nor reads, so a stale stream never holds a slot. (Step 34 had one stream per helper, and a new one replaced it.) A stream lives at most
  30 minutes, and ends with the prepared lease: monitoring faults, disconnects, releases and new
  tunnels close every stream before anything else.
- **Preemption.** The keeper holds the lifecycle lock through its windows almost continuously. A new
  stream joins the running keeper without the lock; with no keeper it waits up to 5 s for the lock (a
  monitor check), and a first request that meanwhile finds another first request's keeper joins it.
  A release whose capability already checks out (verified, not yet consumed) cancels the keeper and
  every stream and waits up to 5 s for the lock; meanwhile new requests are refused with `LAB_BUSY`
  at once and a plane started just before is cancelled again, so no new stream can take the lock
  first. An unauthorized request never interrupts them. The
  windows open on the helper's own context, so cancelling the streams never fails a window or faults
  the tunnel, and no request is admitted or dialed once they are cancelled. Every caller that closes
  the streams returns only after all their sockets are closed. A request still waiting when a window
  fails gets that failure's code (`LAB_FAULTED`, `STATE_UNCERTAIN`), not an authorization refusal;
  if the tunnel's cleanup is still running when its wait ends, `STATE_UNCERTAIN`.
  Other operations (verify, disconnect, delete) answer `LAB_BUSY` while streams run:
  stop the listener or release first. `ListLabs` still answers (since Step 36; before, it was
  `LAB_BUSY` too), and so it does during a monitor check.
- **Transport.** The controller runs `egresslab-helperctl proxy-stream` through the runtime launcher.
  The capability travels in a frame on stdin, the helper's acknowledgement comes back as a frame,
  then both directions are framed (data, FIN, and END from the guest), because neither a killed
  launcher nor a closed stdout crosses `limactl shell`; EOF on stdin closes the stream. A destination
  FIN does not end the upload. A pending request whose client left never dials.
- **Client handling.** Up to eight clients are served at once (one at a time in Step 34), as many
  as the helper admits; up to eight more wait up to 10 s for a slot, the rest are refused. After the
  destination finished, an idle client is closed after 30 s.

Limits of this prototype: since Step 35 a short pause remains around each monitor check (see Monitor
traffic overlay below); native Linux has not run it (WSL2 did on 2026-11-26, two Lima runtimes on
2026-11-27, see `docs/DEV-LINUX-VM.md`). Application networking as a whole stays disabled.

### Endpoint-to-runtime integration (Step 35)

`egresslab-controller-lab -approve serve-endpoint ENDPOINT_ID` serves a SOCKS5 endpoint stored by
the desktop or the HTTP API (`state.json`): only `socks5` on `127.0.0.1` with a port of at least
1024. The command takes no runtime flag; it resolves the endpoint's profile, the profile's runtime
binding (runtime, namespace, helper epoch), that runtime's trust record and the profile's durable
hold, requires them all to agree and the runtime's helper to be the epoch that prepared the hold, and
then serves exactly that reservation and generation. For every CONNECT, after the helper call,
minting looks the pinned hold up once, under the journal's shared read lock: a released hold, or a
later hold for the profile on the same helper (the binding is then unchanged), is not found
(`reservation is not held`). Then the endpoint, the binding and the trust record are re-read, and
the capability is sent only if they still agree (`endpoint binding changed` otherwise: another
helper epoch, namespace, runtime or key). Both are refused until a new approved start. The HTTP API
only stores endpoint definitions; its start still answers 409. On Windows, these per-CONNECT reads
and the API's saves of the same files no longer collide: readers share delete access, and saves
rename with POSIX semantics, retrying transient refusals.

Several streams per runtime (Step 35): the helper's streams share one keeper and its traffic windows
(see Traffic windows and Preemption above), and `serve-socks` and `serve-endpoint` serve up to eight
clients at once, each CONNECT with its own capability. The IPC protocol, helperctl and the workers
did not change.

### Monitor traffic overlay (Step 35)

While the egress monitor checks a prepared generation whose proxy streams are running, each probe
window also carries a traffic overlay, in the same nft transaction. It has the gate's set
(`egresslab_app4`, element `wg0` with the gate's 10 s kernel timeout) and input permit. Its output
permit keeps only the established connections the gate already marked:

```text
add rule inet egresslab_lab output meta nfproto ipv4 oifname @egresslab_app4 meta skuid UID meta l4proto tcp ct state established ct mark 0x65676c01 accept
```

- **No new connection.** The overlay marks nothing, so no new connection leaves while the monitor
  probes, whatever its UID.
- **Order and readback.** The policy is: sealed rules, then the overlay's permits, then the probe's,
  each window's permits last in their chains. The readback takes the probe window out first, then the
  overlay, and requires the sealed policy for the rest. Any other set or rule, another order or a
  duplicate is refused.
- **Eligibility.** The overlay is used only when all of these hold:
  - the proxy plane belongs to the monitored reservation and profile;
  - the plane has running streams, and its UID comes from the helper's own configuration;
  - the health the streams were admitted on is fresh;
  - that health leaves 2 s to open the overlay, plus the 10 s kernel timeout and the 2 s close
    budget.

  Eligibility is checked again before each source's window, so streams that ended get none.
- **Expiry and close.** The overlay's element expires on its own after 10 s, which can pause the
  streams before a long probe ends; it is never renewed within the window. After the probe, an
  expired overlay element is accepted, an expired probe element is not. Both windows close together,
  by handle, in one transaction; an unconfirmed close drifts the namespace.
- **Check timing.** While streams run, the check is due as soon as no traffic window may open any
  more (14 s before the renewal deadline), so the overlay follows the last window. Checks then come
  about every 17 s instead of 24 s. Before this, the gate stayed closed for about 7 s before each
  check, and TCP's retransmission backoff turned that into 8 to 18 s stalls.
  - A check that itself ended past that point keeps the routine schedule, so slow checks never run
    back to back. After such a check, no window opens until the next check, as before Step 35, and
    new streams wait.
  - No check starts while an authorized release waits for the lock. A release that arrives during a
    check still waits for it, up to 5 s.
- **A changed address.** A source whose address differs from the generation's pin ends the attempt
  at once, without asking the second source. The tunnel is faulted and every stream closed; the
  durable hold stays with the controller.

Short pauses remain:
- between the last traffic window and the overlay;
- between the two sources' windows;
- when a probe outlives the overlay's element.

On WSL2, the longest request on one kept-alive connection across eight checks took 2.8 s; on Lima
(nft 1.0.9), 1.85 s and 1.53 s across six checks each. The real nft captures and the kernel
behaviour are in `docs/DEV-LINUX-VM.md`.

### Isolated DNS for domain names (Step 35)

`serve-socks` and `serve-endpoint` accept domain names (SOCKS5 address type 3). Nothing asks the
host's resolver.

- **Transport.** Each name is resolved by DNS over HTTPS through the same signed proxy stream
  transport as a CONNECT: one `OpenProxyStreamV1` to `8.8.8.8:443` per query, with the same trust,
  reservation, binding and capability checks. The query goes to Google Public DNS's JSON API
  (`https://dns.google/resolve`, `type=A`, `edns_client_subnet=0.0.0.0/0`).
- **TLS.** The SNI and the certificate name are `dns.google`. The certificate is verified only
  against built-in roots: GTS Root R1, R3 and R4, from Ubuntu's ca-certificates 20260816. dns.google
  chains to R4 through WE2. The platform verifier is never used, since on Windows and macOS it may
  fetch certificates over the host's own network. Any other CA fails closed.
- **What is refused.**
  - Names: local and special names (`.local`, `.localhost`, `.internal`, `.home.arpa`, `.onion`,
    `.invalid`, `.test`), and labels outside `a-z0-9-`.
  - Responses: a redirect, any status other than 200, a body over 64 KiB, a DNS status other than
    0, a truncated answer, or a question that does not match.
  - Aliases: more than eight CNAMEs, a loop, or a name that has an alias and also has a second
    CNAME or any address record (of either family, well formed or not).

  Only a public IPv4 answer counts, by the controller's own test. Answers the mint would refuse (the
  probe sources) are skipped, so that a later allowed one is taken. There is no cache and no
  fallback.
- **The CONNECT.** The resolved address is dialed like any IPv4 destination: the destination
  policy and the signed capability still decide. Ports 53 and 853 are refused before resolution.
- **The query's stream.** It is closed before the CONNECT. After an answer, and only while the
  listener runs, the resolver waits up to 3 s for the runtime process to exit; a client that leaves
  meanwhile does not shorten the wait. The helper releases the
  slot on its own, without acknowledging it, so with seven other streams running, a domain CONNECT
  may occasionally get `LAB_BUSY`.
- **Privacy.** Google sees the queried names, coming from the VPN's address, without the client
  subnet.

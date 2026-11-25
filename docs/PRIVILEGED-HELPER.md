# Privileged helper and authorization protocol

Status: **Step 27C.1 — WireGuard peer verification and endpoint pinning.** A controller CLI
signs `CreateLab` and `ConnectTunnel` and drives the helper's sealed lab and tunnel lifecycle in
the Linux runtime; the helper holds the encrypted WireGuard configs, checks the peer state the
kernel reports against the staged config, and stays the source of truth for lab and tunnel
state. Windows (WSL2) and Linux are verified end to end; macOS (Lima, Keychain) is
implemented but has not been run. Probes and proxy traffic are still not implemented; the
sections from "Typed operations only" on are partly design.

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
- A macOS run of the Lima and Keychain paths.
- Open from earlier steps: `VerifyLab` still compares the firewall with the state read right
  after sealing (only the managed tunnel backend also checks the intended policy); egress-IP
  leases across runtimes; a kill-switch independent of the controller; refusing to delete a
  profile that still has runtime resources.
- Interface address, MTU, routing table and policy routing verification (Step 27C.2); hostname
  endpoints, DNS policy and endpoint selection (Step 27C.3). The HTTP controller and the desktop
  know nothing of labs or tunnels; only the lab CLI drives them.
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
`lo` exists, installs the sealed firewall and reads it back. The capability is consumed just
before the kernel work starts. Refusals for a duplicate profile, a full helper (8 labs) or a busy
helper leave it unused.

- **Seal fails:** the helper deletes the namespace. If that fails too, the lab stays tracked as
  faulted and creation is blocked for the rest of the process.
- **Create fails:** creation is blocked as well, because the kernel state may be uncertain. Later
  creates get `STATE_UNCERTAIN`; check `egresslab-lab-recover`, then restart the helper.
- **`VerifyLab`** re-reads the topology and the firewall. Any difference marks the lab faulted.
  It never repairs, and a faulted lab is never restored; only `DeleteLab` clears it.
- **`DeleteLab`** refuses a namespace that holds any device besides `lo` or has processes, and
  leaves it for inspection. A namespace removed outside the helper is released.
- **Normal shutdown** (`SIGINT`, `SIGTERM`, `SIGHUP`) waits for a running operation, then deletes
  every lab it safely can. After a `SIGKILL` or crash, the labs and their markers remain;
  `egresslab-lab-recover` reports them as orphans, and `-delete` removes them.

Ownership lives in memory only. If a `CreateLab` response is lost, `ListLabs` shows the namespace,
and `DeleteLab` removes it.

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
| macOS | `lima` (`limactl shell`) | login Keychain (`security`) | no: written from the docs, not run |
| any | `remote` | — | not implemented |

`-runtime auto` picks by host OS. The key sits in the controller data directory
(`EGRESSLAB_DATA_DIR`, default `<user config dir>/EgressLab`), next to `state.json`. The
controller signs only for a profile that exists in `state.json`, and fetches the helper epoch
right before each signature.

- **DPAPI** protects the key against other Windows accounts and copies of the disk, not against
  programs running as the same user.
- **The Linux file key** is protected by Unix permissions only. A Secret Service backend is not
  implemented.
- **Lima (unverified):** its docs do not say whether `limactl shell` forwards stdin, which
  `create-lab` and `connect-tunnel` need, or whether a guest shell re-parses arguments. The transport therefore
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
  `vpn_lab_compatible`, nothing else: no endpoint, key or config crosses the socket.
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
  rollback (`STATE_UNCERTAIN`). That includes a stage with `vpn_lab_compatible=false` (a hostname
  endpoint, for example), so check `stage-info` before signing. `Disconnect` then releases the tunnel and answers `faulted`; only
  `DeleteLab` clears the lab.
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
3. The endpoint is a unicast IPv4 address and the config is a full IPv4 tunnel.
4. No tunnel is tracked and the lab holds only `lo`.
5. The lab firewall matches both the session baseline and the intended sealed policy (the rules
   written out in `sealed_policy.go`, not the state read back after sealing). A mismatch marks the
   lab drifted. An nft version that prints the same rules differently is refused as well, and so
   is a table with any flags (a `dormant` table still lists its rules but enforces none).
6. No `egwg*` link and no managed alias exists in the VM namespace.
7. The expected peer state is written down from the vault config alone: the interface public key
   (`wg pubkey`, the private key on stdin), the peer key, the pinned IPv4 endpoint and port, and
   the keepalive. A key that cannot be derived, or equals the peer's, stops here.
8. The root underlay table is installed. Then the link is created with an alias
   `egresslab-managed:<namespace>:<link>`, moved into the lab and renamed `wg0`. Its name, alias
   and kind (`wireguard`) are read back.
9. After the fwmark and private key are set, and before any peer exists, the lab firewall, the
   underlay table and the fwmark are read back again, and the kernel must report the expected
   interface public key and no peer.
10. The peer, addresses, MTU and default route are configured. The link, firewall and underlay
    are checked once more, and so is the peer (see "Peer verification").

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
- `VerifyConfigured` re-reads the link, firewall, underlay and peer; a failure faults the
  tunnel, and a later correct readback does not clear the fault.

**Peer verification.** Each property is read on its own with `wg show wg0 <property>`, never with
`showconf` or `dump`, which print the private and preshared keys, and compared exactly with the
expected state; nothing is learned from the kernel. A value read is never put in an error.

| Property | Must be |
|---|---|
| `public-key` | the key derived from the vault's private key |
| `peers` | exactly one: the staged peer key |
| `endpoints` | the staged IPv4 address and UDP port |
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

Known gaps:

- One tunnel per helper (see "Signed tunnel lifecycle"); more need a tunnel registry that the
  recovery gate understands.
- A failed underlay install leaves the tunnel uncertain even when nft refused the script before
  changing anything: the lab cannot be deleted, `CreateLab` stays `LAB_BUSY` for the rest of the
  process, and shutdown leaves the namespace (and perhaps the table) for manual recovery.
- If `ip link del` removes the link but reports an error (a timeout), or the inventory after it
  fails, later `Disconnect` calls find no link and stay uncertain: the table is kept until the
  operator recovers by hand.
- Addresses, MTU and routes are not read back (Step 27C.2), hostname endpoints are not
  supported (Step 27C.3), and nothing monitors the tunnel continuously; drift is found only by
  `VerifyLab`.

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

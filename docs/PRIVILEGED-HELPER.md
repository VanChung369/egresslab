# Privileged helper and authorization protocol

Status: **Step 27A — managed WireGuard vault and profile binding.** A controller CLI signs
`CreateLab` and drives the helper's sealed lab lifecycle in the Linux runtime, and the helper can
hold encrypted WireGuard configs per profile. Windows (WSL2) and Linux are verified end to end;
macOS (Lima, Keychain) is implemented but has not been run. Tunnels and probes through the helper
are still not implemented; the sections from "Typed operations only" on are partly design.

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
  `stage-info`. `create-lab` reads the capability from stdin only, never from argv. It refuses to
  run as root.
- The managed WireGuard vault and `StageInfo` (see "Managed WireGuard vault").
- Controller side (see "Controller and runtimes"):
  - an Ed25519 signer that can mint only `CreateLab`, checked against both golden vectors;
  - signing-key storage per platform;
  - runtime providers that reach the helper from each host OS;
  - `egresslab-controller-lab`, which needs `-approve` for every mutation;
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
- Open from earlier steps: firewall readback compared with the intended policy (today it is
  compared with the state read right after sealing); egress-IP leases across runtimes; a
  kill-switch independent of the controller; refusing to delete a profile that still has
  runtime resources.
- Using a staged config: `ConnectTunnel` and `Disconnect` (Step 27B), hostname endpoints and IP
  pinning (Step 27C).
- A controller approval workflow for individual operations.
- Live key rotation and automatic key distribution.
- `ConnectTunnel`, `PermitProbe` and `RecoverClean` through IPC.
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
- A request named `ConnectTunnel` or `PermitProbe` gets `operation not enabled`, even with a valid
  capability and with the lab lifecycle enabled, and the capability stays unused.
- A sealed lab is a namespace with a verified default-deny firewall and only `lo`. It is not a
  connected VPN and not a verified egress IP.
- Every IPC response sets `network_ready=false`, and the client rejects a response that does not.
- `HelperInfo` returns only public metadata. It is not authenticated to the client, so the
  controller compares the fingerprint with its own public key, and never starts trusting a key
  because the helper reports it.
- The controller signs nothing for a profile that lost its unique-IP or kill-switch policy, or
  for a helper reporting another key. It never retries a `CreateLab`; after an error, `ListLabs`
  shows whether the lab exists.
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
  a terminal on the VM. The only exception is the helper's sealed lab lifecycle, and only when
  the helper was started with `-enable-lab-lifecycle` and a public key.
- The helper socket accepts only the configured agent UID. It answers `Ping`, `RecoverScan`,
  `HelperInfo`, the `AuthorizeCheck` dry-run and, with the lifecycle flag, `ListLabs`,
  `CreateLab`, `VerifyLab` and `DeleteLab`, plus `StageInfo` with `-enable-vault`
  (`TestPeerRejection`, `TestPeerIdentityAndReadOnlyOperations`,
  `TestMutationWithValidCapabilityIsRefused`, `TestLabLifecycleIPCRefusals`, `TestListLabsRefusals`,
  `TestStageInfoIPC`).

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

`CreateLab` (creates and seals), `ConnectTunnel{profile_id, stage_id}`, `PermitProbe{ipv4}`,
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

- The helper holds only the public key: a root-owned file of 64 hex characters, in a root-owned
  directory, neither writable by group or others. It is provisioned out of band.
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
4. The controller checks the new fingerprint against its own trust record, then mints new
   capabilities.

The controller must not trust a new key only because the helper reports a new fingerprint. Live
rotation, automatic key distribution and production private-key management are not implemented.

## Sealed lab lifecycle

| `-auth-public-key-file` | `-enable-lab-lifecycle` | Helper mode |
|---|---|---|
| no | no | read-only |
| yes | no | read-only + `AuthorizeCheck` dry-run |
| no | yes | refuses to start |
| yes | yes | signed sealed lab lifecycle |

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
| `OPERATION_DISABLED` | not enabled on this helper (no key, no lifecycle flag, tunnel operations) |
| `RUNTIME_UNAVAILABLE` | helper unreachable, shutting down, or not served by root |
| `INVALID_REQUEST` | malformed frame, version, fields or arguments |
| `LAB_BUSY` | another lab operation is running |
| `LAB_NOT_FOUND` / `LAB_EXISTS` / `LAB_LIMIT` | no lab for the profile / one already / 8 reached |
| `OWNERSHIP_MISMATCH` | the profile's lab is another namespace |
| `FIREWALL_DRIFT` / `LAB_FAULTED` | the lab no longer matches (firewall / topology, or already faulted); delete it |
| `RECOVERY_REQUIRED` | leftover lab resources block creation |
| `KERNEL_INCOMPATIBLE` | new namespaces would get extra devices |
| `STATE_UNCERTAIN` | a create or rollback may have left kernel state behind; check recovery, restart the helper |
| `STAGE_NOT_FOUND` | the profile has no WireGuard config in the managed vault |
| `INTERNAL` | anything else; details are in the helper log |

The controller adds `RUNTIME_UNTRUSTED`, and reports a `CreateLab` that failed without a definite
refusal as `STATE_UNCERTAIN`.

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
  `create-lab` needs, or whether a guest shell re-parses arguments. The transport therefore
  passes only plain tokens.
- **Clocks:** the Windows controller mints with the Windows clock, and the helper checks with
  the WSL clock. With no skew allowance, a WSL clock behind Windows across a second boundary
  refuses a fresh capability.

### Trusted runtimes and profile bindings

The helper reports a **runtime ID**: `runtime_` plus 128 bits of HMAC-SHA256 keyed with
`/etc/machine-id`, so the raw machine ID is never disclosed. It names the Linux installation: it
is stable across helper restarts and differs between installations that hold the same public
key. Images cloned from one installation share it. One installation reached two ways (WSL and
native) reports the same ID. A missing machine ID means no runtime ID, and no trust.

The controller lab CLI keeps `runtimes.json` next to `state.json`:

- **`trust-runtime`** (with `-approve`) pins the reported runtime ID to the provider and target it
  was reached through. It requires a named WSL distribution, because the default can change, and a
  helper that holds this controller's key. Lab commands refuse an untrusted target, or one that now
  answers with another ID, with `RUNTIME_UNTRUSTED`.
- **A profile is bound to one runtime for good**, from its first `create-lab`. The binding is saved
  before the kernel changes, so an uncertain result can only be a lab on that runtime.
- **The lab record** (namespace and helper epoch) is valid only while that helper process runs. A
  record from an earlier epoch is stale: a normal stop deleted that lab, and the recovery gate
  covers a crash. So a restart never strands a profile.
- **`verify-lab` and `delete-lab`** never depend on the controller's record: without a current
  one (or without any binding, for example after `untrust-runtime`), the helper's registry decides,
  and `verify-lab` writes the record back.
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
- `ConnectTunnel` and `PermitProbe` stay disabled, and `network_ready` stays false.

Nothing stops the legacy `egresslab-wg-vault-lab` from opening these paths without the lock: do
not point it at the managed vault. The vault protects configs at rest, not against root in the
runtime.

## Invariants the helper keeps

- Before any opening operation, it reads back the firewall (`LabFirewall.Verify`). Drift blocks the
  operation until an explicit reconcile.
- The underlay policy is installed before the tunnel link exists. It is removed only after the
  link is gone (`VPNEgressLab.Disconnect`).
- Sticky IP: an active profile observed on a different IP is cut off, and the active lease is kept.
- `network_ready` stays `false` until a real egress check passes for the exact profile.
- Every request and its result is appended to an audit log (`0600`). The log never contains secrets.

## Not covered yet

- Remote (non-loopback) controllers. Supporting them needs mutual authentication between the
  controller and the agent.
- Live rotation of the controller signing key (only offline replacement exists, see "Key
  replacement"), and rotation of the vault key.

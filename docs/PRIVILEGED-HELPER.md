# Privileged helper and authorization protocol

Status: **Step 23 — signed authorization dry-run implemented.** Network changes through the
helper are still not implemented; the sections from "Typed operations only" on are partly design.

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
- A process-local replay cache with atomic nonce consumption, capped at 4096 live nonces.
- `AuthorizeCheck`, a dry-run IPC operation.
- Optional root-owned public-key loading in the helper (`-auth-public-key-file`, `-helper-id`).
- Unit tests for signatures, expiry, binding, concurrency, replay, the signing-message golden
  vector and the key loader.

## Not implemented

- Production controller signing-key storage and lifecycle. The controller is a separate Go module
  and cannot import `internal/helperauth`; it needs its own implementation of the format below,
  checked against `TestSigningMessageGolden`.
- A controller approval workflow for individual operations.
- Restart-safe replay protection and helper epoch rotation. The replay cache lives in memory, so
  after a helper restart an unexpired capability that was already used is accepted again.
- Network-changing operations through IPC (`CreateLab`, `ConnectTunnel`, `PermitProbe`,
  `RecoverClean`, ...).
- Per-operation kernel and policy authorization.
- A `CAP_NET_ADMIN`-only helper runtime and systemd hardening.
- A persistent audit log and signing-key rotation.
- Production route readiness and proxy activation.
- The agent does not call the helper yet.

## Safety boundary

- `AuthorizeCheck` never runs `ip`, `wg`, `nft` or any other network mutation.
- A successful dry-run consumes its nonce. It does not authorize a later operation with the same
  capability.
- A request named `ConnectTunnel` or `PermitProbe` gets `operation not enabled`, even with a valid
  capability, and the capability stays unused.
- Every IPC response sets `network_ready=false`, and the client rejects a response that does not.
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
- Privileged changes run only from the `egresslab-*-lab` CLIs. An operator starts those with `sudo`
  in a terminal on the VM.
- The helper socket accepts only the configured agent UID. It answers only `Ping`, `RecoverScan`
  and the `AuthorizeCheck` dry-run (`TestPeerRejection`, `TestPeerIdentityAndReadOnlyOperations`,
  `TestMutationWithValidCapabilityIsRefused`).

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

`CreateLab`, `SealLab`, `ConnectTunnel{profile_id, stage_id}`, `PermitProbe{ipv4}`,
`VerifyLab`, `Disconnect`, `DeleteLab`, `RecoverScan`, `RecoverClean`.

Every argument is validated with the existing patterns: `egresslab-lab-<16 hex>`,
`profile_<16 hex>`, `wgstage_<32 hex>`, and IPv4 literals. Keys never travel over the socket.
`ConnectTunnel` names a stage, and the helper reads that stage from the sealed vault itself.

## Authorization

Each operation that opens traffic (`ConnectTunnel`, `PermitProbe`) needs a capability that the
controller mints. Implemented format, version 1:

```text
claims = {"version":1,
          "intent":{"operation":..., "profile_id":"profile_<16 hex>",
                    "namespace":"egresslab-lab-<16 hex>",
                    "stage_id":"wgstage_<32 hex>"          (ConnectTunnel only)
                    "probe_ipv4":"<dotted IPv4>"},          (PermitProbe only)
          "helper_id":"helper_<32 hex>", "nonce":"<32 hex>",
          "issued_at":<unix s>, "not_after":<unix s, at most issued_at + 30>}

message   = "egresslab/helper-capability/v1" || 0x00 || compact JSON of claims, in the field order above
signature = base64url(Ed25519-sign(controller_key, message)), no padding
```

`TestSigningMessageGolden` pins the exact message and signature for a fixed seed. OpenSSL 3
(`openssl pkeyutl -sign -rawin`) produces the same signature, so a non-Go controller can implement
the format.

- The helper holds only the public key: a root-owned file of 64 hex characters, in a root-owned
  directory, neither writable by group or others. It is provisioned out of band.
- The request carries the intent separately. The helper accepts the capability only when the
  signed intent equals it exactly and `helper_id` matches its own.
- The helper keeps a replay cache of nonces until `not_after`. A capability is single-use.
  Checks that fail before the replay check leave the nonce unused.
- The helper's answer is only `authorization denied`. It does not say which check failed.
- Validity is checked to the second (`issued_at <= now < not_after`) with no clock-skew allowance.
  The controller runs on Windows and the helper in WSL, so their clocks must agree to well under a
  second, or tolerance must be added before the controller mints.
- The controller mints a capability only after the desktop user confirms the action, and only
  when the profile passes its invariants (unique IP, kill-switch). (Not implemented.)

Operations that only close or remove traffic (`Disconnect`, `DeleteLab`) need just the peer UID
check. This keeps cleanup possible even when the controller is down.

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
- Key rotation for the controller signing key and for the vault key.

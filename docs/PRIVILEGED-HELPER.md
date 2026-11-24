# Privileged helper and authorization protocol

Status: **IPC bootstrap implemented in Step 22.** The rest of this document is still design.

Implemented:

- `egresslab-helper` listens on the Linux Unix-domain socket `/run/egresslab/helper.sock`.
- Length-prefixed JSON protocol (`internal/helperipc`), version 1, maximum 64 KiB per frame.
  Unknown fields and trailing content are rejected.
- `SO_PEERCRED` UID check before anything is read. Other UIDs, root included, are closed without
  a reply.
- Two read-only operations: `Ping` and `RecoverScan` (the existing `LabRecovery.Scan`). Every other
  operation name gets `operation not enabled`. `network_ready` is always `false`.
- `egresslab-helperctl ping|recover-scan`, a client for the agent user.
- Unit tests for framing, peer rejection, refused mutations, hidden scanner errors and oversized
  responses (`internal/helperipc`).

Not implemented:

- Network-changing operations through IPC (`CreateLab`, `ConnectTunnel`, `PermitProbe`, `RecoverClean`, ...)
- Ed25519 authorization capabilities
- Replay protection and authorization expiry
- `CAP_NET_ADMIN`-only runtime and systemd hardening
- Desktop/controller-driven helper operations; the agent does not call the helper yet
- Persistent audit log

The sections below on typed operations, authorization and invariants describe that future work.
Until it exists, any `ip`, `wg` or `nft` change still needs a lab CLI run by hand with `sudo`.

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
- The helper socket accepts only the configured agent UID and answers only `Ping` and `RecoverScan`
  (`TestPeerRejection`, `TestPeerIdentityAndReadOnlyOperations`).

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
controller mints:

```text
capability = Ed25519-sign(controller_key, {
  op, profile_id, lab, stage_id?, nonce (128-bit), not_after (<= 30 s), helper_id
})
```

- The helper holds only the public key, which is provisioned out of band.
- The helper keeps a replay cache of nonces until `not_after`.
- A capability is single-use and bound to one operation, one profile and one lab.
- The controller mints a capability only after the desktop user confirms the action, and only
  when the profile passes its invariants (unique IP, kill-switch).

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

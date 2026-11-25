# EgressLab Architecture — iteration 0.1

## Scope

The project is a desktop workstation for configuring and observing network routing resources.
It uses the v1.1.1 Claude Design prototype as UX reference only; no HTML prototype runtime is reused.

### Components

1. **Desktop UI** — SvelteKit SPA rendered inside a Tauri 2 window. It calls the local Go API.
2. **Go Control Plane** — persists routing profiles and proxy endpoint *definitions*; exposes read-only status and CRUD endpoints. It does not handle network traffic.
3. **Linux Network Agent** (`services/network-agent`) has two parts:
   - **Read-only HTTP API**: GET-only discovery (system info, capabilities, links, namespaces) behind a bearer token. It must run unprivileged.
   - **Lab code, CLI only, run with `sudo`**: owned lab namespaces with ownership markers and crash recovery; a sealed nftables table with kernel readback and drift blocking; a per-tunnel VM-side underlay policy (fwmark plus an endpoint-only table); egress probing with sticky active-IP leases; and an encrypted, opt-in WireGuard config store.

   No HTTP handler can trigger lab code. The boundary required before that changes is in `docs/PRIVILEGED-HELPER.md`.
4. **Proxy Data Plane (planned)** — SOCKS5/HTTP CONNECT listeners restricted to verified, isolated routes. Not present in v0.1.

### Invariants

- No profile is considered active merely because it exists.
- No proxy listener is started before its route has passed verification.
- Unique public egress IP across isolated profiles is mandatory; no manual override.
- Mandatory kill-switch and no direct fallback when tunnel becomes unavailable.
- No statement of verification without performing a real egress check.
- No credentials or VPN private keys are stored in current control-plane state.
- Local-only control API is *not* sufficient authorization for privileged network actions. The API must move to authenticated IPC or a mutually authenticated transport before privileged control is added.

### Data model (v0.1)

- `RoutingProfile`: `id`, `name`, `status=unconfigured`, `unique_ip_required=true`, `kill_switch_required=true`.
- `ProxyEndpoint`: `id`, `name`, `protocol`, `listen_host=127.0.0.1`, `port`, `profile_id`, `status=draft`.

JSON persistence lives in the user's OS config directory by default, configurable through `EGRESSLAB_DATA_DIR`.
Write operations are serialized; persistence is atomic to a temporary file and rename on the current filesystem.

### Network API

`GET /api/v1/health`, `GET /api/v1/overview`, `GET /api/v1/profiles`,
`POST /api/v1/profiles`, `DELETE /api/v1/profiles/{id}`,
`GET /api/v1/endpoints`, `POST /api/v1/endpoints`, `DELETE /api/v1/endpoints/{id}`,
`POST /api/v1/endpoints/{id}/start` (always `409 ROUTE_NOT_VERIFIED` in v0.1),
`GET /api/v1/tunnels` (WireGuard interfaces discovered by the agent, all `managed=false`),
`GET /api/v1/agents` (agent health plus sanitized read-only discovery; empty without `EGRESSLAB_AGENT_TOKEN`).

On startup, the controller re-validates every invariant of the persisted state and refuses to start if any fails. The checks cover ID formats, unique names, ports and IDs, endpoint-to-profile references, statuses, the loopback listener, and enabled policy flags.

This API is intentionally *not* a remote management API and listens on loopback only.
CORS is restricted to local development and Tauri origins. This is not full process authentication.

### Shared egress reservation authority (Step 31B)

The unique-IP invariant needs one authority across runtimes: two Linux runtimes, each with its own helper, can see the same exit address and both produce a local candidate (`docs/PRIVILEGED-HELPER.md`, "Egress candidates"). The controller holds that authority's core, an in-process registry in `internal/control`:

- A reservation owner is one managed tunnel's lifetime: profile, runtime, helper epoch, namespace and tunnel generation.
- A candidate is admitted only when the helper's receipt agrees with the trusted runtime and its pinned key, the strict profile and its configured lab, the original V2 probe (generation, nonce, observation time and the unanimously verified address) and both capabilities this controller issued, whose signatures are checked against the pinned public key. The admission deadline never extends the helper's evidence: it is the earlier of 60 s after the probe was sent and the helper's deadline minus 5 s.
- Four indexes (owner, public IPv4, profile and reservation ID) change together; validation, the collision checks and publication run under one mutex, so requests through one registry instance never hold the same address twice, and an existing hold is never overwritten or evicted.
- Expiry ends eligibility for activation, not the hold: an address is released only once a later lifecycle confirms its owner can no longer use it, and no release exists yet.

The registry alone is in memory and coordinates one process; Step 31C puts it behind a durable journal shared by controller processes. It is not wired into the CLI or the HTTP API. Signed reservation and lease activation (Step 31D) and collision and recovery tests (Step 31E) come later; no application traffic is allowed.

### Durable reservation authority (Step 31C)

The controller keeps exclusive IPv4 ownership in an append-only journal, `egress-reservations.journal` in a data directory its caller names (`internal/control/reservation_journal.go`; there is no production caller yet). Every participating controller process must use the same journal on a trusted local filesystem (NTFS, APFS, ext4), not on OneDrive, a network share or a filesystem whose locking and flush semantics are unverified.

- An exclusive OS lock on the journal itself serializes processes: `LockFileEx` on Windows, `flock` on Linux and macOS. A held lock fails at once as busy, with no retry. Other platforms have no authority and no mutex-only fallback. `flock` is advisory: it binds controllers that follow the protocol, not an administrator or a process that edits or replaces the file outside it. Renaming the journal during a transaction can split the authority on Linux and macOS; Windows refuses the rename while the journal is open.
- One transaction holds the lock while it loads and validates the whole journal, rebuilds the four ownership indexes, admits the candidate and checks collisions (Step 31B), appends one record and flushes it. No registry is cached between operations, and inspection takes the same lock.
- A record is a length prefix, canonical JSON (at most 8 KiB, exactly the writer's bytes) and a SHA-256 digest chained to the previous record, starting from the header's digest. A damaged or partial frame, a non-canonical payload, an invalid record or duplicate ownership invalidates the whole journal: allocation and inspection fail, and no partial list is returned.
- Normal operation never creates a missing journal, truncates or repairs a damaged one, or drops a hold; an empty file is corrupt. Provisioning is a separate, explicit step (tests only for now), because a missing journal is no proof that nothing was ever reserved.
- A reservation is returned only after its record and, on Linux and macOS, the journal's directory entry are flushed. If eligibility ends during the flush, the hold stays and no grant is returned. A failure after the write began is uncertain: the caller must inspect durable state, not retry with a new capability. Every transaction, inspection included, flushes the journal before reading it, so a complete record left by a writer that died before its own flush is made durable instead of being reported from the cache.
- Holds survive the process: an exit releases the lock, not the ownership. A record read back is a recovered hold; its timestamps lost the monotonic reading, so it keeps its address but is never eligible for activation. Expiry does not release an address either.

The checksum chain detects corruption, not deliberate rewriting or a rollback to an earlier complete prefix. The authority does not coordinate separate data directories or hosts, and Windows has no directory flush. Locking and recovery are tested with real child processes on Windows and Linux; macOS is compile-checked here and runs the same tests in CI. Safe release, the production command and lifecycle integration (Step 31D) remain pending; no application traffic is allowed.

### Windows / macOS / Linux

The Go control plane can run natively on Windows and macOS.
The Linux network agent will later run in WSL2, a VM or on a Linux host. A running WSL2 process is not yet wired to the desktop shell.

### UX source

Prototype v1.1.1: palette #0B1018 / #101722 / #151E2B, Geist-like typography,
248px sidebar, resource tables and profile cards. UI is implemented afresh, and will evolve during development.

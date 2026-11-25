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

The registry is in memory, is not wired into the CLI or the HTTP API, and coordinates one process only. Cross-process coordination and durable reservations (Step 31C), signed reservation and lease activation (Step 31D) and collision and recovery tests (Step 31E) come later; no application traffic is allowed.

### Windows / macOS / Linux

The Go control plane can run natively on Windows and macOS.
The Linux network agent will later run in WSL2, a VM or on a Linux host. A running WSL2 process is not yet wired to the desktop shell.

### UX source

Prototype v1.1.1: palette #0B1018 / #101722 / #151E2B, Geist-like typography,
248px sidebar, resource tables and profile cards. UI is implemented afresh, and will evolve during development.

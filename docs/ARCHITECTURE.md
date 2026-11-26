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

The registry alone is in memory and coordinates one process; Step 31C puts it behind a durable journal shared by controller processes. The signed reservation workflow (Step 31D.1) and the provisioned authority with its CLI commands (Step 31D.2) build on it; the HTTP API does not reach it. Lease preparation (Steps 31D.3a and 31D.3b) and the helper's generation-bound revocation (Step 31D.3c) build on it too; the controller's revocation and release (Step 31D.3d) and collision and recovery tests (Step 31E) come later; no application traffic is allowed.

### Durable reservation authority (Step 31C)

The controller keeps exclusive IPv4 ownership in an append-only journal, `egress-reservations.journal` (`internal/control/reservation_journal.go`), which production code reaches only through the provisioned authority (Step 31D.2). Every participating controller process must use the same journal on a trusted local filesystem (NTFS, APFS, ext4), not on OneDrive, a network share or a filesystem whose locking and flush semantics are unverified.

- An exclusive OS lock on the journal itself serializes processes: `LockFileEx` on Windows, `flock` on Linux and macOS. A held lock fails at once as busy, with no retry. Other platforms have no authority and no mutex-only fallback. `flock` is advisory: it binds controllers that follow the protocol, not an administrator or a process that edits or replaces the file outside it. Renaming the journal during a transaction can split the authority on Linux and macOS; Windows refuses the rename while the journal is open.
- One transaction holds the lock while it loads and validates the whole journal, rebuilds the four ownership indexes, admits the candidate and checks collisions (Step 31B), appends one record and flushes it. No registry is cached between operations, and inspection takes the same lock.
- A record is a length prefix, canonical JSON (at most 8 KiB, exactly the writer's bytes) and a SHA-256 digest chained to the previous record, starting from the header's digest. A damaged or partial frame, a non-canonical payload, an invalid record or duplicate ownership invalidates the whole journal: allocation and inspection fail, and no partial list is returned.
- Normal operation never creates a missing journal, truncates or repairs a damaged one, or drops a hold; an empty file is corrupt. Provisioning is a separate, explicit step (`init-reservations`, Step 31D.2), because a missing journal is no proof that nothing was ever reserved.
- A reservation is returned only after its record and, on Linux and macOS, the journal's directory entry are flushed. If eligibility ends during the flush, the hold stays and no grant is returned. A failure after the write began is uncertain: the caller must inspect durable state, not retry with a new capability. Every transaction, inspection included, flushes the journal before reading it, so a complete record left by a writer that died before its own flush is made durable instead of being reported from the cache.
- Holds survive the process: an exit releases the lock, not the ownership. A record read back is a recovered hold; its timestamps lost the monotonic reading, so it keeps its address but is never eligible for activation. Expiry does not release an address either.

The checksum chain detects corruption, not deliberate rewriting or a rollback to an earlier complete prefix. The authority does not coordinate separate data directories or hosts, and Windows has no directory flush. Locking and recovery are tested with real child processes on Windows and Linux; macOS runs the same tests in CI. Revocation and safe release (Steps 31D.3c and 31D.3d) remain pending; no application traffic is allowed.

### Signed reservation orchestration (Step 31D.1)

`ReserveVerifiedEgress` (`internal/control/egress_reservation_flow.go`) runs one complete reservation attempt through the trusted runtime transport, from a context the caller assembles from trusted controller state and the runtime in use, never from a request body. The transport must belong to the same provider target as that trusted runtime, as the CLI's `currentRuntime` ensures; the workflow cannot check it, because the receipt carries no helper signature.

1. Preflight: the journal must exist and be healthy, the profile must hold no reservation and the registry must have room. This only rejects early, before any runtime call or signature; the lock is released again, and the durable transaction decides uniqueness.
2. It discovers the current tunnel generation, signs one `PermitMultiProbeV2` capability and validates the returned observation.
3. It signs one `ReserveEgressCandidateV1` capability for exactly that attempt; the signer needs the original probe capability and the validated observation, not just a generation. Each capability is checked again right before it is submitted, since the key store (DPAPI, Keychain) can be slow, and a candidate request that is no longer fresh for the evidence is not submitted.
4. The candidate receipt is checked against both controller-issued capabilities and the original verified public IPv4. The internal admission is built from this operation's own observations only, and the durable authority reloads its journal under the exclusive OS lock for the final admission and uniqueness checks.

No journal lock is held during network operations, and a failed phase stops every later one. A failed global reservation does not restore consumed helper evidence, and a lost candidate response is an uncertain outcome. Nothing is retried, falls back, activates or releases. A cancellation up to the journal append leaves nothing durable; after the commit, cancellation or expiry keeps the hold and returns no grant. Collisions do not disconnect the tunnel: cleanup needs the right owner and generation and belongs to the lease lifecycle. A durable reservation remains an exclusive address hold, not an active lease. Step 31D.2 makes it a method of the provisioned authority and runs it from the CLI; the workflow is tested with synthetic observations, real signatures and real journals.

### Reservation authority provisioning (Step 31D.2)

The reservation authority lives in a fixed per-user configuration directory, `os.UserConfigDir()` + `EgressLab` (`%APPDATA%\EgressLab` on Windows, `~/Library/Application Support/EgressLab` on macOS, `$XDG_CONFIG_HOME/EgressLab` or `~/.config/EgressLab` on Linux), independent of the `EGRESSLAB_DATA_DIR` override, the runtime and the profile; there is no flag for it. Another data directory (`EGRESSLAB_DATA_DIR`) never selects another authority, and one whose signing key differs from the authority's is refused; changing `APPDATA`, `HOME` or `XDG_CONFIG_HOME` does select another root, which is outside the supported setup.

- It is provisioned explicitly, once (`-approve init-reservations`). The immutable marker `reservation-authority.json` holds the authority's random ID, its canonical directory (symlinks resolved, later compared by directory identity rather than spelling) and the controller key fingerprint. It is written to a private temporary file, flushed and hard-linked into place exclusively, and the journal is then published the same way, so neither name ever shows an empty or partial file that a concurrent reader could lock and strand. The V2 journal header binds the journal to the marker with the SHA-256 digest of its canonical form.
- An existing marker or journal, even a broken symlink or the leftover of an interrupted initialization, prevents another initialization. Missing, mismatched, non-canonical or corrupted authority files block allocation and listing; nothing recreates, repairs or migrates them, and V1 journals are not migrated. A marker left by an interrupted initialization blocks the authority until a trusted recovery exists.
- Every operation re-reads the marker and keeps it locked together with the journal for its whole duration, compares it with the identity it opened, and requires the journal header, the controller key and every stored hold's key to agree. There is no key rotation and no migration.
- `init-reservations` and `list-reservations` are local and never reach a runtime. `-approve reserve-egress PROFILE_ID NAMESPACE` opens the authority first, then checks the trusted runtime, the profile's binding and the helper's configured lab, and runs one signed verification, candidate consumption and durable commit (Step 31D.1), followed since Step 31D.3b by the signed lease preparation; it takes no address, path or override arguments. Errors map to stable controller codes (`RESERVATION_AUTHORITY_UNAVAILABLE`, `RESERVATION_BUSY`, `EGRESS_IP_COLLISION`, `EGRESS_RESERVATION_HELD` and others); an uncertain or committed-expired outcome, or a receipt that could not be written after the commit, stays `STATE_UNCERTAIN`.
- A reservation does not activate a lease, a proxy endpoint or application networking, and changes no profile, endpoint or binding; its output says `activation_allowed: false` and `network_ready: false`.

The authority covers cooperating controller processes of one OS user that share the configuration root on a supported local filesystem; the deletion or rollback of all authority files is outside the guarantee boundary. No hold is released yet: a real `reserve-egress` keeps its address for good until Step 31D.3d adds safe release. Key rotation and authority migration remain pending.

### Prepared egress leases (Step 31D.3a)

A durable reservation is exclusive address ownership at the controller. A prepared lease is a helper-owned authorization record that binds that reservation to one verified tunnel generation: `PrepareEgressLeaseV1` names the authority and reservation IDs, and the helper requires everything else (profile, runtime, namespace, generation, pin, address, evidence and candidate nonces) to equal its own candidate, which it consumes once.

- Neither state authorizes application networking. An active lease also needs continuous monitoring, the kill-switch and data-plane enforcement (later steps).
- The prepared lease is single-use and keeps the original evidence deadline; it never refreshes itself, changes the address or moves to another generation.
- The helper cannot read the controller's journal, so the controller must sign a preparation only after its durable commit (Step 31D.3b), within the same approved operation; a reservation read back from disk is not fresh evidence.
- The controller must never release durable ownership because a prepared lease expired or disappeared from helper memory. The helper's revocation (Step 31D.3c) retires the generation, so stale signed operations cannot recreate authorization; release (Step 31D.3d) must rely on it.

### Controller lease preparation (Step 31D.3b)

`ReservationAuthority.ReserveAndPrepareEgress` completes verification, candidate consumption, the durable reservation and the signed lease preparation (`PrepareEgressLeaseV1`) in one approved operation; `reserve-egress` uses it and answers `"state": "prepared"` only after a matching receipt.

- The signing gate requires both the fresh in-process hold this operation committed and its matching record in the authority's journal. A reservation recovered from storage never authorizes a preparation, and nothing signs one for a reservation ID from the CLI or an API.
- The preparation is signed and sent only with at least 5 s of eligibility left, on top of the clock-skew margin, so the helper's tunnel verification cannot run into the evidence deadline and fault the lab.
- The helper's receipt must match the signed capability and the durable hold, the original evidence timestamps and the key fingerprint included, which the signed intent does not carry.
- Any failure after the durable commit, whether signing, expiry, a refusal, a lost response or a mismatched receipt, keeps the address held and returns `EGRESS_PREPARATION_UNCONFIRMED`. That does not prove the helper made no prepared lease. Nothing is retried, released or activated.

Application networking stays disabled. With no release yet, a cooperating controller cannot free the hold between the journal check and the submission; release must also revoke outstanding preparations (Step 31D.3d, with the helper's revocation of Step 31D.3c).

### Generation retirement (Step 31D.3c)

Durable address ownership must outlive the invalidation of local authorization and an uncertain cleanup.

- A reservation may be released only through a future authority transaction (Step 31D.3d) backed by a confirmed retirement of its exact managed tunnel generation: the helper's `RevokeEgressLeaseV1` receipt, checked against the authority, reservation, runtime, helper epoch and the signed revocation attempt, never a receipt a user supplies.
- Expiry, a missing prepared lease and a controller process exit are not release proofs.
- The retirement records live in one helper epoch and do not authorize a release after an unverified runtime recovery.

### Windows / macOS / Linux

The Go control plane can run natively on Windows and macOS.
The Linux network agent will later run in WSL2, a VM or on a Linux host. A running WSL2 process is not yet wired to the desktop shell.

### UX source

Prototype v1.1.1: palette #0B1018 / #101722 / #151E2B, Geist-like typography,
248px sidebar, resource tables and profile cards. UI is implemented afresh, and will evolve during development.

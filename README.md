# EgressLab — real implementation starter (v0.1.0)

**Network Routing & Proxy Studio**. Desktop application with Tauri 2 + SvelteKit + TypeScript and a Go controller.
This is **new source code**, using the EgressLab design v1.1.1 only as a UI/UX reference.

## Implemented today

- Real local HTTP API (not a mocked API)
- CRUD for routing profile definitions and local proxy endpoint definitions
- Persistent state in the OS user config directory
- Duplicate port/name validation, policy enforcement flags on all profiles
- SvelteKit frontend with overview, endpoint table, routing profiles, status pages and creation forms
- Tauri 2 desktop wrapper source (not built in this environment)
- **Safe default:** no VPN tunnel, proxy listener, external routing, or egress verification is claimed to work yet

An endpoint in `draft` state **does not accept connections**. The `start` API deliberately returns `409 ROUTE_NOT_VERIFIED`.
This is the *first vertical slice*, not a working VPN-to-Proxy tool.

## Run on Windows 11 (PowerShell; two terminals)

Install Go 1.23+, Node.js 22+, and Yarn or npm. For the desktop shell, also install Rust + the Tauri prerequisites (C++ build tools and WebView2 as applicable).

**Terminal 1: Go API**

```powershell
cd services/controller
go test ./...
go run ./cmd/egresslab-controller
```

The API listens only on `http://127.0.0.1:8787`.

**Terminal 2: SvelteKit UI**

```powershell
cd apps/desktop
yarn install
yarn dev
```

Open `http://127.0.0.1:5173` to test the UI in Edge or Chrome.

To open the **Tauri desktop** window (Rust/Tauri prerequisites required), stop `yarn dev` if it is already running, then run:

```powershell
yarn tauri dev
```

Tauri starts its own Vite dev server. The Go API must still be running in Terminal 1; automatic sidecar startup is **not implemented**.

To use npm instead of Yarn, replace `yarn install`, `yarn dev`, `yarn tauri dev` with `npm install`, `npm run dev`, `npm run tauri -- dev`.

### macOS / Linux

Use the same commands in Terminal. Install Rust and the platform prerequisites before `yarn tauri dev`.

### Manual API smoke test

PowerShell:

```powershell
Invoke-RestMethod http://127.0.0.1:8787/api/v1/health
Invoke-RestMethod http://127.0.0.1:8787/api/v1/overview
```

Create a routing profile first, then create a proxy endpoint from the UI. Reload: both resources remain saved.

## Structure

```
apps/desktop/                   SvelteKit + Tauri 2 desktop UI
  src/routes/+page.svelte       Real API-connected screens
  src/lib/api.ts                Typed HTTP client
  src-tauri/                   Rust desktop shell
services/controller/            Go HTTP controller
  cmd/egresslab-controller/     Entrypoint
  internal/control/             Store + REST handlers + tests
docs/ARCHITECTURE.md            Boundaries and invariants
docs/NEXT_MILESTONES.md         Implementation sequence
```

## Security boundary and limitations

The Go API is a loopback development control API with origin checks, not authenticated IPC.
It must not be exposed to the LAN, the public internet or privileged network functions in its current state.
The desktop and API currently run as separate processes. SvelteKit builds and Rust/Tauri desktop builds have **not been executed in the artifact environment** because npm registry access and Rust toolchain were unavailable. Go tests **have** been executed successfully.

## Design source

EgressLab-v1.1.1.zip was treated as a layout and UX reference. No React prototype runtime or font binaries were copied into this project.

## Next

Connect a trusted Linux network agent, verify dedicated per-profile routes, and only then implement real proxy activation.

## License

Distributed under the [MIT License](LICENSE). Copyright (c) 2026 VanChung369.

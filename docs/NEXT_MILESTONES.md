# Implementation milestones

## 0.1 — Control plane vertical slice (this download)

- [x] SvelteKit desktop-first app shell
- [x] Basic Tauri 2 wrapper source
- [x] Go loopback control API
- [x] JSON persistence for profiles and proxy endpoint definitions
- [x] Validation, port collision detection, profile in-use protection
- [x] Fail-closed status and blocked activation
- [x] Go unit/integration tests
- [ ] Build/check desktop frontend on a network-connected development machine
- [ ] Build/check native Tauri bundle with Rust installed

## 0.2 — Linux agent foundation

- Pair local controller with a Linux network agent (authenticated transport)
- Discover supported VPN interfaces and routing capabilities
- Manage lifecycle of network namespace and veth bridge
- Provide agent health and diagnostics
- Do not expose network listeners outside loopback by default

## 0.3 — Verified route and proxy runtime

- Add WireGuard profile import without exposing private keys to UI
- Enforce kill-switch using Linux firewall rules
- Verify public egress IP and check uniqueness across profiles
- Implement SOCKS5 data plane that runs only inside verified isolated routes
- Exercise tunnel loss, DNS/IPv6 leak and IP collision scenarios

## 0.4 — Desktop integration

- Package controller securely as sidecar or IPC service
- Handle app/window lifecycle and system tray
- Add diagnostic workflow and runtime metrics
- Implement accessibility and keyboard shortcuts

## 0.5 — UX coverage

- Expand VPN Tunnels, Network Topology, IP Intelligence, Traffic Monitor, Activity & Logs
- Improve based on v1.1.1 design prototype and actual workflow testing
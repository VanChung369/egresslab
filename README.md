# EgressLab

Verified network isolation and proxy routing engine.

EgressLab manages isolated WireGuard routes and exposes authenticated local SOCKS5 endpoints backed by verified public IPv4 reservations.

## Features

- Linux network namespace isolation.
- Managed WireGuard tunnels.
- Kernel-enforced, default-deny firewall.
- Continuous multi-source public IP verification.
- Durable and exclusive IP reservation authority.
- Generation-bound authorization and recovery.
- Multi-runtime and multi-stream SOCKS5 proxy routing.
- Isolated DNS-over-HTTPS hostname resolution.
- Cross-platform controller for Windows, macOS and Linux.
- Encrypted WireGuard configuration storage.

## Release status

Network Engine MVP — Alpha.

The network engine has been exercised on macOS with Lima and Windows with WSL2.

The desktop interface manages configuration definitions. Privileged network activation requires explicitly approved CLI operations.

## Architecture

```text
SOCKS5 Client
    |
Host Controller
    |
Authenticated Runtime Transport
    |
Privileged Linux Helper
    |
Kernel Firewall + WireGuard
    |
VPN Egress
```

## Supported environments

- Windows with WSL2.
- macOS with Lima.
- Native Linux builds are available but have not completed equivalent end-to-end validation.

## Getting started

See [docs/DEV-LINUX-VM.md](docs/DEV-LINUX-VM.md) for runtime provisioning, trusted controller setup, WireGuard staging, reservation management and proxy activation. To verify and install the release archives, start with its section "Installing a release".

## Security boundaries

EgressLab does not allow automatic direct-network fallback.

Reservations remain held until confirmed retirement or authorized reboot-bound recovery.

Public IP verification is periodic. It cannot guarantee instantaneous detection of VPN provider address changes.

IP uniqueness is coordinated within one shared reservation authority, not across independent installations.

SOCKS5 supports IPv4 TCP and hostname resolution. UDP and IPv6 routing are not supported.

## License

MIT. See [LICENSE](LICENSE).

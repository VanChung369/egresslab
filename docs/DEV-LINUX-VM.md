# EgressLab — Docker-Free Linux Development Environment

## Overview

This document describes how to run the EgressLab Linux Network Agent on macOS using a lightweight Ubuntu virtual machine powered by Lima.

Docker is not required.

### Architecture

```text
macOS Host
├── EgressLab Desktop
├── Go Controller
│   └── 127.0.0.1:8787
└── Lima
    └── Ubuntu Linux VM
        └── Network Agent
            └── 127.0.0.1:8788
```

The Controller manages EgressLab configuration, while the Linux Network Agent discovers and eventually manages Linux networking resources.

## Prerequisites

- macOS (Apple Silicon or Intel)
- Homebrew
- Go 1.23 or later
- Lima
- Ubuntu 24.04 LTS

## Install Lima

```bash
brew install lima
limactl --version
```

## Create the Ubuntu VM

```bash
limactl start \
  --name=egresslab \
  --containerd=none \
  --mount-none \
  --cpus=2 \
  --memory=2 \
  --disk=16 \
  template:ubuntu-24.04
```

Enter the VM:

```bash
limactl shell egresslab
```

Verify the operating system:

```bash
uname -s
uname -m
cat /etc/os-release
```

## Install Linux Networking Tools

Inside the Ubuntu VM:

```bash
sudo apt-get update
sudo apt-get install -y \
  iproute2 \
  wireguard-tools \
  nftables \
  curl
```

Verify the installations:

```bash
ip -Version
wg --version
nft --version
```

## Cross-Compile the Network Agent

Run on the macOS host from `services/network-agent`:

```bash
go test ./...

GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
  go build -trimpath \
  -o /tmp/egresslab-agent-linux \
  ./cmd/egresslab-agent
```

The `GOARCH=arm64` configuration matches the tested ARM64 VM. Use `amd64` when targeting an x86-64 Linux VM.

## Transfer the Executable

On macOS:

```bash
limactl copy \
  --backend=scp \
  /tmp/egresslab-agent-linux \
  egresslab:/tmp/egresslab-agent-linux
```

Inside Ubuntu:

```bash
install -m 755 \
  /tmp/egresslab-agent-linux \
  "$HOME/egresslab-agent"
```

## Environment Configuration

The Agent requires:

```dotenv
EGRESSLAB_AGENT_TOKEN=
```

Generate a cryptographically random 32-byte token, encoded as 64 hexadecimal characters.

Never commit real tokens, private keys, or credentials.

Development secrets are stored in `.env` files ignored by Git. When running inside a VM, securely transfer only the required Agent secret and restrict its file permissions to the owning user.

## Run the Agent

Inside Ubuntu, load the Agent environment configuration and execute:

```bash
"$HOME/egresslab-agent"
```

The Agent listens on:

```text
127.0.0.1:8788
```

It must not be exposed directly to an untrusted network.

## Verify the Agent

Use an authenticated request:

```bash
curl -sS \
  -H "Authorization: Bearer $EGRESSLAB_AGENT_TOKEN" \
  http://127.0.0.1:8788/health
```

Other available read-only endpoints:

```text
GET /system/info
GET /capabilities
GET /network/interfaces
GET /network/links
GET /network/namespaces
```

## Verified Development Environment

Tested configuration:

- Host: macOS
- Guest: Ubuntu Linux (Lima)
- Guest architecture: ARM64
- Go executable version: 1.25.1
- Container runtime: Not required

Observed results:

| Component | Result |
|---|---|
| Agent Health | Running |
| System Discovery | Linux ARM64 |
| iproute2 | Detected |
| WireGuard Tools | Detected |
| nftables | Detected |
| Network Namespace Handle | Detected |
| CAP_NET_ADMIN | Missing |
| Named Namespace Discovery | Working; empty list |

## Current Limitations

The Network Agent's HTTP API is read-only: every route is `GET`, and the controller treats the agent as healthy only when it reports `mode=read-only` and `network_ready=false`. The agent refuses to start as root or with `CAP_NET_ADMIN`, `CAP_NET_RAW` or `CAP_SYS_ADMIN`.

Privileged networking exists only as **lab CLIs**. You run them by hand with `sudo` on the VM, and nothing triggers them over HTTP:

| Command | What it exercises |
|---|---|
| `egresslab-netns-lab` | Create and delete an owned lab namespace |
| `egresslab-veth-lab` | Veth pair between two lab namespaces |
| `egresslab-firewall-lab` | Sealed nftables table (policy drop, explicit IPv6/DNS drop) with kernel readback |
| `egresslab-wireguard-lab` | WireGuard between two lab namespaces |
| `egresslab-vpn-lab -file vpn.conf` | Real VPN egress through a sealed namespace (details below) |
| `egresslab-wg-inspect`, `egresslab-wg-vault-lab` | Config import summary; in-memory or opt-in encrypted staging |
| `egresslab-lab-recover [-delete]` | Report (default) leftovers of a crashed session; `-delete` removes only orphan namespaces holding nothing but `lo`/lab veth (never one with WireGuard) and stale markers. Underlay tables are never removed automatically |

`egresslab-vpn-lab` runs these steps:

1. Seal the namespace.
2. Install a VM-side underlay table for the tunnel's fwmark.
3. Bring up `wg0`.
4. Verify the underlay policy and the firewall by reading them back.
5. Probe the egress IP and pin it as an active lease.
6. Simulate tunnel loss to prove there is no fallback route.

Still not implemented:

- A privileged helper and authorization protocol, so that no HTTP path can trigger lab operations. The design is in `docs/PRIVILEGED-HELPER.md`.
- DNS through the tunnel. DNS (port 53) and IPv6 are explicitly dropped inside lab namespaces.
- Multi-peer configs, and hostname endpoints in the VPN lab. The importer reports `vpn_lab_compatible=false` for these.
- SOCKS5 runtime activation.

`network_ready` must remain `false` until the required route verification and network enforcement mechanisms are implemented.

### Running the lab code on the VM

The lab code's unit tests use fake command runners. Only a run on the VM exercises the real kernel paths:

```bash
cd services/network-agent
go test ./...
go build -o /tmp/egresslab-vpn-lab ./cmd/egresslab-vpn-lab
go build -o /tmp/egresslab-lab-recover ./cmd/egresslab-lab-recover
sudo /tmp/egresslab-vpn-lab -file /path/to/vpn.conf   # IPv4 endpoint, AllowedIPs 0.0.0.0/0
sudo /tmp/egresslab-lab-recover                         # should report nothing after a clean exit
```

The firewall readback tests use a synthetic `nft -j` sample. To replace it with a real capture, run the command below from a second terminal while a lab is sealed, and save the output as `internal/agent/testdata/nft-lab-sealed.json`:

```bash
sudo ip netns exec <egresslab-lab-...> nft -j list ruleset
```

## Security Notes

- Never commit `.env` files containing secrets.
- Never include Bearer Tokens in documentation or logs.
- Run the Agent as your normal user. It refuses to start as root or with networking capabilities.
- Persisting WireGuard configs is opt-in (`egresslab-wg-vault-lab -store ... -key ...`). Configs are encrypted with AES-256-GCM, and the key file must be `0600` and live in a different directory than the data file. This protects backups and copies, not a root user on the VM.
- Do not expose the Agent's HTTP API publicly.
- Authenticated communication between the macOS Controller and the Linux VM must be secured before privileged networking operations are introduced.

## Next Milestone

Implement safe Network Namespace lifecycle management after establishing appropriate authorization and privilege boundaries.
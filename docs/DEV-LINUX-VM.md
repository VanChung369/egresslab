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

The Network Agent currently operates in read-only mode.

The following functionality has not yet been implemented:

- Network Namespace creation and deletion
- Veth pair management
- WireGuard tunnel lifecycle
- nftables kill-switch enforcement
- Public egress IP verification
- SOCKS5 runtime activation

`network_ready` must remain `false` until the required route verification and network enforcement mechanisms are implemented.

## Security Notes

- Never commit `.env` files containing secrets.
- Never include Bearer Tokens in documentation or logs.
- Avoid running the Agent as root unless specifically required.
- Do not expose the Agent's HTTP API publicly.
- Authenticated communication between the macOS Controller and the Linux VM must be secured before privileged networking operations are introduced.

## Next Milestone

Implement safe Network Namespace lifecycle management after establishing appropriate authorization and privilege boundaries.
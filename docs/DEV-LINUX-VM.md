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

Privileged networking exists as **lab CLIs** that you run by hand with `sudo` on the VM, plus the helper's opt-in sealed lab lifecycle. Nothing triggers either over HTTP:

| Command | What it exercises |
|---|---|
| `egresslab-netns-lab` | Create and delete an owned lab namespace |
| `egresslab-veth-lab` | Veth pair between two lab namespaces |
| `egresslab-firewall-lab` | Sealed nftables table (policy drop, explicit IPv6/DNS drop) with kernel readback |
| `egresslab-wireguard-lab` | WireGuard between two lab namespaces |
| `egresslab-vpn-lab -file vpn.conf` | Real VPN egress through a sealed namespace (details below) |
| `egresslab-wg-inspect`, `egresslab-wg-vault-lab` | Config import summary; in-memory or opt-in encrypted staging (never against the helper's managed vault) |
| `egresslab-lab-recover [-delete]` | Report (default) leftovers of a crashed session; `-delete` removes only orphan namespaces holding nothing but `lo`/lab veth (never one with WireGuard) and stale markers. Underlay tables are never removed automatically |
| `egresslab-helper -uid <UID> -gid <GID>`, `egresslab-helperctl ping\|recover-scan\|helper-info\|list-labs\|stage-info\|create-lab\|verify-lab\|delete-lab\|connect-tunnel\|disconnect` | Helper IPC: Unix socket with `SO_PEERCRED`, read-only `Ping`/`RecoverScan`/`HelperInfo`, optional `AuthorizeCheck` dry-run, sealed lab lifecycle, managed WireGuard vault and signed tunnel lifecycle (details below) |

`egresslab-vpn-lab` runs these steps:

1. Seal the namespace.
2. Install a VM-side underlay table for the tunnel's fwmark.
3. Bring up `wg0`.
4. Verify the underlay policy and the firewall by reading them back.
5. Probe the egress IP and pin it as an active lease.
6. Simulate tunnel loss to prove there is no fallback route.

Still not implemented:

- Tunnels and probes through the privileged helper. The helper can already create, verify and delete sealed, loopback-only lab namespaces when started with `-enable-lab-lifecycle`, and `egresslab-controller-lab` drives them from the host. The design is in `docs/PRIVILEGED-HELPER.md`.
- DNS through the tunnel. DNS (port 53) and IPv6 are explicitly dropped inside lab namespaces.
- Multi-peer configs, and hostname endpoints in the VPN lab. The importer reports `vpn_lab_compatible=false` for these.
- SOCKS5 runtime activation.

`network_ready` must remain `false` until the required route verification and network enforcement mechanisms are implemented.

### Running the lab code on the VM

The lab code's unit tests use fake command runners. Only a run on the VM exercises the real kernel paths:

```bash
cd services/network-agent
go test ./...
go build -o ~/.local/bin/egresslab-vpn-lab ./cmd/egresslab-vpn-lab
go build -o ~/.local/bin/egresslab-lab-recover ./cmd/egresslab-lab-recover
sudo ~/.local/bin/egresslab-vpn-lab -file ~/.config/egresslab/private/vpn.conf   # IPv4 endpoint, AllowedIPs 0.0.0.0/0
sudo ~/.local/bin/egresslab-lab-recover                                          # should report nothing after a clean exit
```

On WSL, avoid `/tmp` for these binaries: WSL empties it at every distro boot, and it stops the distro when idle. Keep `vpn.conf` on the Linux filesystem, not under `/mnt/<drive>`: files there always show mode 777, so the config is rejected.

The firewall readback tests use real `nft -j` captures from nft 1.0.2 (Ubuntu 22.04 on WSL2). These are `testdata/nft-lab-sealed.json`, taken right after Seal, and `testdata/nft-lab-probe-permitted.json`, taken after PermitEgressProbe. To refresh them for another nft version, run this from a second terminal while a lab is sealed:

```bash
sudo ip netns exec <egresslab-lab-...> nft -j list ruleset
```

### Helper IPC (Steps 22–25)

The helper runs as root in this lab step. The production design keeps only `CAP_NET_ADMIN`. Install the binaries as root-owned files:

```bash
go build -o /tmp/egresslab-helper ./cmd/egresslab-helper
go build -o /tmp/egresslab-helperctl ./cmd/egresslab-helperctl
sudo install -o root -g root -m 0755 /tmp/egresslab-helper /tmp/egresslab-helperctl /usr/local/bin/

# Terminal 1: allow only your normal user
sudo /usr/local/bin/egresslab-helper -uid "$(id -u)" -gid "$(id -g)"

# Terminal 2: as the same normal user, without sudo
egresslab-helperctl ping           # {"ok": true, "network_ready": false, ...}
egresslab-helperctl recover-scan   # same classification as egresslab-lab-recover, never changes anything
egresslab-helperctl helper-info    # {"helper_info": {"authorization_configured": false}} without a key
```

Other UIDs get no reply. `egresslab-helperctl` refuses to run as root, and also refuses a production socket that is not served by root. Users outside your primary group cannot reach the socket at all.

Ctrl+C, `SIGTERM` or closing the terminal removes the socket. After a `SIGKILL`, the helper refuses to start while `/run/egresslab/helper.sock` exists. Check that `pidof egresslab-helper` prints nothing, then remove the socket with `sudo rm`. (Do not use `pgrep -x egresslab-helper`: Linux truncates process names to 15 characters, so it never matches.)

Started without `-auth-public-key-file`, the helper answers `AuthorizeCheck` with `authorization unavailable`. To enable the dry-run, give it the public key file:

```bash
sudo /usr/local/bin/egresslab-helper -uid "$(id -u)" -gid "$(id -g)" \
  -auth-public-key-file /etc/egresslab/helper-auth.pub
```

The public key file holds the controller's Ed25519 public key as 64 hex characters. The path must be absolute. The file and every directory up to `/` must be owned by root, not writable by group or others, and not symlinks, so a key under `/tmp` is refused. A refused configuration exits before touching `/run/egresslab`. The helper never loads a private key.

At every start, the helper generates a new random helper ID (epoch) and logs it with the key's SHA-256 fingerprint. `egresslab-helperctl helper-info` returns both. Capabilities minted for an earlier start are refused, so after a restart the controller must read the new ID first. The Step 23 `-helper-id` flag no longer exists, and the helper refuses to start with it. To replace the key, stop the helper, write the new public key file and start it again: the fingerprint changes.

If the WSL clock steps backwards between two checks, the helper refuses all capabilities with `authorization denied` until you restart it. Nothing is logged when this happens.

`egresslab-helperctl` cannot send `AuthorizeCheck`. The controller mints capabilities (see "Controller lab CLI" below); the agent does not forward them yet.

Add `-enable-lab-lifecycle` (it requires `-auth-public-key-file`) to let the helper create, verify and delete sealed lab namespaces, at most 8, one per profile. The helper refuses the flag if the kernel would add fallback tunnel devices to new namespaces, and refuses `create-lab` while any lab resource it does not own exists (run `egresslab-lab-recover`). `egresslab-helperctl list-labs`, `verify-lab` and `delete-lab` work directly; `create-lab` reads a signed capability from stdin, which the controller produces. On Ctrl+C the helper deletes its labs. After a `SIGKILL`, `sudo egresslab-lab-recover` reports them as orphans and `-delete` removes them.

Run the socket tests in `internal/helperipc` as a non-root user. Under root, the tests that need a non-root socket client skip. The key-loader and vault tests in `cmd/egresslab-helper` run under both.

### Controller lab CLI (Step 26)

`egresslab-controller-lab` runs on the host (Windows, macOS or Linux) and signs with the controller key. Provision once:

```bash
egresslab-controller-lab init-key            # never replaces an existing key
egresslab-controller-lab public-key          # 64 hex characters: copy them to the helper's key file
```

Then start the helper with `-auth-public-key-file <that file> -enable-lab-lifecycle`, trust the runtime once, and run:

```bash
egresslab-controller-lab runtime-status
egresslab-controller-lab -wsl-distro Ubuntu-22.04 -approve trust-runtime   # Windows; on macOS/Linux omit -wsl-distro
egresslab-controller-lab -approve create-lab <profile ID from the desktop>
egresslab-controller-lab list-labs
egresslab-controller-lab verify-lab <profile ID> <namespace>
egresslab-controller-lab -approve delete-lab <profile ID> <namespace>
egresslab-controller-lab stage-info <profile ID>                              # needs -enable-vault
egresslab-controller-lab -approve connect-tunnel <profile ID> <namespace> <stage ID>   # needs -enable-tunnel
egresslab-controller-lab -approve disconnect <profile ID> <namespace>
```

`-runtime auto` uses WSL on Windows (`-wsl-distro`; trust and lab commands need it named), Lima on macOS (`-lima-instance`, default `egresslab`) and the host itself on Linux. A profile stays bound to the runtime it was first used on (`unbind-profile` and `untrust-runtime` release it). Every failure carries a code such as `RECOVERY_REQUIRED` or `RUNTIME_UNTRUSTED`. Install `egresslab-helper` and `egresslab-helperctl` in `/usr/local/bin` inside the runtime (see above). The Lima and Keychain paths are written from the docs but have not been run on a Mac; see `docs/PRIVILEGED-HELPER.md`. If `create-lab` reports an uncertain result, run `list-labs` before retrying.

### Managed WireGuard vault (Step 27A)

Set it up once, with the helper stopped:

```bash
sudo install -d -o root -g root -m 0700 /etc/egresslab/vault /var/lib/egresslab/vault
sudo /usr/local/bin/egresslab-helper vault-init
sudo install -o root -g root -m 0600 ~/.config/egresslab/private/vpn.conf /var/lib/egresslab/vault/import.conf
sudo /usr/local/bin/egresslab-helper vault-stage <profile ID>   # prints the stage ID; consumes import.conf
```

Then add `-enable-vault` to the helper (with `-enable-lab-lifecycle` and the public key) and read the stage with `egresslab-helperctl stage-info <profile ID>`. `vault-stage`, `vault-revoke` and `vault-init` are refused while the helper runs. Your original `vpn.conf` is not touched.

### Managed tunnel (Step 27B.2)

Add `-enable-tunnel` as well (it needs `-enable-vault`). On a sealed lab, `egresslab-helperctl connect-tunnel <profile ID> <namespace> <stage ID> < capability.json` brings the staged config up as `wg0` (`tunnel_configured`: configured only, no handshake or egress checked, no traffic permitted), and `egresslab-helperctl disconnect <profile ID> <namespace>` removes it again. `egresslab-controller-lab -approve connect-tunnel` signs the capability for you (see "Controller lab CLI"). One tunnel per helper: while it exists, `create-lab` gets `LAB_BUSY`. Stop the helper normally (`Ctrl+C`, `SIGTERM`) so it removes the tunnel before the namespace; after a crash, the underlay table must be removed by hand.

## Security Notes

- Never commit `.env` files containing secrets.
- Never include Bearer Tokens in documentation or logs.
- Run the Agent as your normal user. It refuses to start as root or with networking capabilities.
- Persisting WireGuard configs is opt-in: the helper's managed vault (`vault-init`/`vault-stage`, root-only paths under `/etc/egresslab/vault` and `/var/lib/egresslab/vault`), or the lab CLI `egresslab-wg-vault-lab -store ... -key ...` with your own paths, never the managed ones. Configs are encrypted with AES-256-GCM, and the key file must be `0600` and live in a different directory than the data file. This protects backups and copies, not a root user on the VM.
- Do not expose the Agent's HTTP API publicly.
- Authenticated communication between the macOS Controller and the Linux VM must be secured before privileged networking operations are introduced.

## Next Milestone

Run the Lima and macOS Keychain paths on a Mac, then move tunnel operations behind the helper: the controller now signs `ConnectTunnel` (Step 27B.3, see `docs/PRIVILEGED-HELPER.md`); next come a smoke test with a real VPN provider, then hostname endpoints and IP pinning (Step 27C).
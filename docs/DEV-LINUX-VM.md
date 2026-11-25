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
  procps \
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
| `egresslab-firewall-lab` | Sealed nftables table (policy drop; IPv6, DNS and DoT/DoQ drops ahead of loopback) with kernel readback |
| `egresslab-wireguard-lab` | WireGuard between two lab namespaces |
| `egresslab-vpn-lab -file vpn.conf` | Real VPN egress through a sealed namespace (details below) |
| `egresslab-wg-inspect`, `egresslab-wg-vault-lab` | Config import summary; in-memory or opt-in encrypted staging (never against the helper's managed vault) |
| `egresslab-lab-recover [-delete]` | Report (default) leftovers of a crashed session; `-delete` removes only orphan namespaces holding nothing but `lo`/lab veth (never one with WireGuard) and stale markers. Underlay tables are never removed automatically |
| `egresslab-helper -uid <UID> -gid <GID>`, `egresslab-helperctl ping\|recover-scan\|helper-info\|list-labs\|stage-info\|create-lab\|verify-lab\|delete-lab\|connect-tunnel\|disconnect\|probe-egress` | Helper IPC: Unix socket with `SO_PEERCRED`, read-only `Ping`/`RecoverScan`/`HelperInfo`, optional `AuthorizeCheck` dry-run, sealed lab lifecycle, managed WireGuard vault, signed tunnel lifecycle and signed diagnostic probe (details below) |

`egresslab-vpn-lab` runs these steps:

1. Seal the namespace.
2. Install a VM-side underlay table for the tunnel's fwmark.
3. Bring up `wg0`.
4. Verify the underlay policy and the firewall by reading them back.
5. Probe the egress IP and pin it as an active lease.
6. Simulate tunnel loss to prove there is no fallback route.

Still not implemented:

- Tunnels and probes through the privileged helper. The helper can already create, verify and delete sealed, loopback-only lab namespaces when started with `-enable-lab-lifecycle`, and `egresslab-controller-lab` drives them from the host. The design is in `docs/PRIVILEGED-HELPER.md`.
- DNS through the tunnel. DNS (ports 53 and 853, TCP and UDP) and IPv6 are explicitly dropped inside lab namespaces, ahead of loopback (Step 28B); the helper's labs also disable IPv6 on every interface (`sysctl`, Step 28A).
- Multi-peer configs, and hostname endpoints in the legacy VPN lab (`egresslab-vpn-lab`). The importer reports `vpn_lab_compatible=false` for these; the managed tunnel accepts hostnames (`managed_vpn_compatible`, Step 27C.3).
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

The firewall readback tests use real `nft -j` captures. `testdata/nft-lab-sealed-v2.json` is the current seal (Step 28B) from nft 1.0.9 (Ubuntu 24.04 on Lima). `testdata/nft-lab-sealed.json`, taken right after the earlier seal, and `testdata/nft-lab-probe-permitted.json`, taken after PermitEgressProbe, come from nft 1.0.2 (Ubuntu 22.04 on WSL2); the intended policy now refuses the former. To refresh them for another nft version, run this from a second terminal while a lab is sealed:

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
egresslab-controller-lab -approve probe-egress <profile ID> <namespace>                # needs -enable-probe
```

`-runtime auto` uses WSL on Windows (`-wsl-distro`; trust and lab commands need it named), Lima on macOS (`-lima-instance`, default `egresslab`) and the host itself on Linux. A profile stays bound to the runtime it was first used on (`unbind-profile` and `untrust-runtime` release it). Every failure carries a code such as `RECOVERY_REQUIRED` or `RUNTIME_UNTRUSTED`. Install `egresslab-helper` and `egresslab-helperctl` in `/usr/local/bin` inside the runtime (see above). On macOS, the Lima and Keychain paths are verified end to end (macOS 15.3.2, Lima 2.3.0, Ubuntu 24.04 guest with nft 1.0.9); copy the public key into the VM as shown below. If `create-lab` reports an uncertain result, run `list-labs` before retrying.

On macOS, the key lives in the login Keychain. Copy the public key (not secret) into the Lima VM, then install it inside the VM:

```bash
# macOS
egresslab-controller-lab public-key > /tmp/helper-auth.pub
limactl copy /tmp/helper-auth.pub egresslab:/tmp/helper-auth.pub

# Inside the VM
sudo install -d -o root -g root -m 0755 /etc/egresslab
sudo install -o root -g root -m 0644 /tmp/helper-auth.pub /etc/egresslab/helper-auth.pub
```

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

Add `-enable-tunnel` as well (it needs `-enable-vault`). On a sealed lab, `egresslab-helperctl connect-tunnel <profile ID> <namespace> <stage ID> < capability.json` brings the staged config up as `wg0` (`tunnel_configured`: configured only, no handshake or egress checked, no traffic permitted), and `egresslab-helperctl disconnect <profile ID> <namespace>` removes it again. `egresslab-controller-lab -approve connect-tunnel` signs the capability for you (see "Controller lab CLI"). A hostname endpoint is resolved once by `connect-tunnel` and pinned (Step 27C.3); `egresslab-helperctl stage-info` never resolves. `verify-lab` re-checks the IPv6 switches (Step 28A), the peer and the IPv4 addresses, MTU, rules and routes (Step 27C.2); any drift faults the lab and removes the tunnel. One tunnel per helper: while it exists, `create-lab` gets `LAB_BUSY`. Stop the helper normally (`Ctrl+C`, `SIGTERM`) so it removes the tunnel before the namespace; after a crash, the underlay table must be removed by hand.

### Managed probe worker (Step 29B.1)

The diagnostic probe runs `egresslab-probe` as its own system user, through `setpriv` (util-linux, installed on Ubuntu by default). Install it once, root-owned, and create the user:

```bash
# On the macOS host, from services/network-agent
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o /tmp/egresslab-probe ./cmd/egresslab-probe
limactl copy --backend=scp /tmp/egresslab-probe egresslab:/tmp/egresslab-probe

# Inside the VM
sudo install -o root -g root -m 0755 /tmp/egresslab-probe /usr/local/bin/egresslab-probe
id egresslab-probe >/dev/null 2>&1 || sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin egresslab-probe
sudo /usr/local/bin/egresslab-probe   # must print: probe must not run as root
```

Do not reuse the agent's UID: the worker needs neither the helper socket nor the vault. To enable the signed probe (Step 29B.2a), add to the helper started with `-enable-tunnel`:

```bash
-enable-probe -probe-uid "$(id -u egresslab-probe)" -probe-gid "$(id -g egresslab-probe)"
```

The log then reads `signed sealed lab, managed tunnel and diagnostic probe enabled; proxy disabled`. `egresslab-helperctl probe-egress PROFILE_ID NAMESPACE < capability.json` runs one probe of the lab's tunnel; `egresslab-controller-lab -approve probe-egress PROFILE_ID NAMESPACE` signs the capability and prints the observation (Step 29B.2b).

### Managed multi-source worker (Step 29C.3)

The worker now has two modes: with no arguments it is the single-source Cloudflare probe above; with `--source SOURCE_ID IPV4` it makes one request to a built-in source (`cloudflare_trace` or `ident_me`) pinned to that numeric address. Only the helper uses the second mode, inside that source's own timed firewall window; running the worker by hand produces no managed evidence. It still refuses root, supplementary groups, any capability and a missing no_new_privs before any request, and it checks its arguments before that:

```bash
egresslab-probe --source unknown 9.9.9.9        # unknown probe source, exit 1
egresslab-probe --url https://example.com/      # invalid probe arguments, exit 1
egresslab-probe --source ident_me 2001:db8::1   # invalid probe destination, exit 1
```

Build and test it on Linux before installing it. End-to-end multi-source testing over the VPN needs the signed IPC and controller integration of Step 29C.4; do not open the lab firewall by hand to try it.

## Security Notes

- Never commit `.env` files containing secrets.
- Never include Bearer Tokens in documentation or logs.
- Run the Agent as your normal user. It refuses to start as root or with networking capabilities.
- Persisting WireGuard configs is opt-in: the helper's managed vault (`vault-init`/`vault-stage`, root-only paths under `/etc/egresslab/vault` and `/var/lib/egresslab/vault`), or the lab CLI `egresslab-wg-vault-lab -store ... -key ...` with your own paths, never the managed ones. Configs are encrypted with AES-256-GCM, and the key file must be `0600` and live in a different directory than the data file. This protects backups and copies, not a root user on the VM.
- Do not expose the Agent's HTTP API publicly.
- Authenticated communication between the macOS Controller and the Linux VM must be secured before privileged networking operations are introduced.

## Multi-source HTTPS endpoint provisioning

The ident.me destination (Step 29C.2) is provisioned through trusted configuration, outside the lab namespace. Check a candidate address over HTTPS with explicit address pinning and normal certificate verification, and look up who announces it:

```bash
dig +short A 4.ident.me
whois -h whois.cymru.com " -v <candidate IPv4>"      # must not be Cloudflare (AS13335)
curl -q --noproxy '*' --ipv4 --proto '=https' --connect-timeout 5 --max-time 10 \
  --resolve "4.ident.me:443:<candidate IPv4>" -H 'Accept-Encoding: identity' -fsS https://4.ident.me/
```

If DNS returns several addresses, do not take the first one blindly. The provider does not promise a stable address. DNS at probe time, automatic replacement of the address and skipping certificate verification (`curl -k`) are not allowed. A host-side check reveals the host's own public IP to the provider; it is not a managed observation and never activates an egress lease. No helper configuration takes the pin yet: `NewManagedMultiProbeTunnelBackend` accepts it (Step 29C.3), but the helper exposes no flag for it until Step 29C.4.

## Next Milestone

Multi-source public IP verification: signed IPC and controller integration of the multi-source lifecycle (Step 29C.4). The consensus engine (Step 29C.1), the pinned HTTPS sources with destination-aware windows (Step 29C.2) and the managed multi-source lifecycle (Step 29C.3) exist in the network agent, but no helper operation calls them yet. See `docs/PRIVILEGED-HELPER.md`.
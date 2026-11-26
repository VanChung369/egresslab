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

The firewall readback tests use real `nft -j` captures. `testdata/nft-lab-sealed-v2.json` is the current seal (Step 28B) from nft 1.0.9 (Ubuntu 24.04 on Lima). `testdata/nft-lab-sealed.json`, taken right after the earlier seal, and `testdata/nft-lab-probe-permitted.json`, taken after PermitEgressProbe, come from nft 1.0.2 (Ubuntu 22.04 on WSL2); the intended policy now refuses the former. nft 1.0.2 prints the current seal the same way as 1.0.9: the Step 30B.2 run on WSL2 passed on it. To refresh them for another nft version, run this from a second terminal while a lab is sealed:

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
egresslab-controller-lab multi-probe-policy                                           # needs -enable-multi-probe
egresslab-controller-lab multi-probe-target <profile ID> <namespace>                  # needs -enable-multi-probe
egresslab-controller-lab -approve probe-egress-multi <profile ID> <namespace>          # needs -enable-multi-probe
egresslab-controller-lab -approve init-reservations                                     # once per OS user and host
egresslab-controller-lab list-reservations
egresslab-controller-lab -approve reserve-egress <profile ID> <namespace>              # holds the address durably
egresslab-controller-lab -approve release-egress <reservation ID>                       # revokes the generation, then releases
```

`disconnect` and `delete-lab` never release a durable reservation; only `release-egress` does, through the runtime and helper process that hold it. Do not copy an authority between hosts or run `init-reservations` again to work around a mismatch.

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

On Windows, build it with `GOOS=linux GOARCH=amd64` (or `arm64`, as `uname -m` in the distribution says) and install it from its `/mnt/c/...` path the same way.

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

Build and test it on Linux before installing it. End-to-end multi-source testing over the VPN goes through the controller (Step 29C.4c, see "Multi-source verification from the controller"); do not open the lab firewall by hand to try it.

### Multi-source helper (Step 29C.4b)

Choose the ident.me pin outside the lab namespace (see "Multi-source HTTPS endpoint provisioning"): resolve `4.ident.me` (`getent ahostsv4 4.ident.me` in the VM, `dig +short A 4.ident.me` on the host), do not take the first answer blindly, and verify the chosen address with pinned HTTPS and normal certificate checks. Then install it as root, atomically:

```bash
# Inside the VM, with the new egresslab-helper installed; PIN is the address verified in this
# session. The subshell stops at the first failure, and the working pin is replaced only after the
# helper's own startup rules accepted the staged file.
(
  set -eu
  : "${PIN:?set PIN to the verified address}"
  sudo install -d -o root -g root -m 0755 /etc/egresslab
  stage=$(sudo mktemp -d /etc/egresslab/.multi-probe-pin.XXXXXX)   # unique, root-only, same filesystem
  printf '%s\n' "$PIN" | sudo tee "$stage/multi-probe-pin" > /dev/null
  sudo chmod 0600 "$stage/multi-probe-pin"
  sudo /usr/local/bin/egresslab-helper check-multi-probe-pin "$stage/multi-probe-pin"
  sudo mv -T "$stage/multi-probe-pin" /etc/egresslab/multi-probe-pin
  sudo rmdir "$stage"
  sudo stat -c 'owner=%U group=%G mode=%a type=%F' /etc/egresslab/multi-probe-pin   # owner=root group=root mode=600 type=regular file
)
```

Upgrading from single-source mode also needs the Step 29C.3 worker: rebuild and reinstall `egresslab-probe` with the helper (see "Managed probe worker"). An older worker passes the helper's ownership checks but refuses `--source`, so the first signed attempt would fail and fault the lab. Check it before starting the helper: `/usr/local/bin/egresslab-probe --source unknown 9.9.9.9` must print `unknown probe source` (an older worker prints `probe accepts no arguments`).

The file holds one canonical public IPv4 address other than `1.1.1.1` and at most one trailing LF: no `IDENT_PIN=`, URL, host name or port. `check-multi-probe-pin` applies exactly the rules the helper applies at startup (ownership, directories, size, address policy) to an absolute, canonical path (no `..`, `//` or trailing `/`, so the file checked is the file renamed) and prints the pin; if it refuses, the working pin is untouched and the root-only staging directory `/etc/egresslab/.multi-probe-pin.*` is left for you to inspect and remove. Start the helper with `-enable-multi-probe` instead of `-enable-probe` (never both):

```bash
sudo /usr/local/bin/egresslab-helper -uid "$(id -u)" -gid "$(id -g)" \
  -auth-public-key-file /etc/egresslab/helper-auth.pub \
  -enable-lab-lifecycle -enable-vault -enable-tunnel \
  -enable-multi-probe -probe-uid "$(id -u egresslab-probe)" -probe-gid "$(id -g egresslab-probe)"
```

A missing or unsafe pin file stops the start before the socket exists. `egresslab-helperctl multi-probe-policy` prints the policy version, the pin and the helper epoch, runtime ID and public-key fingerprint; compare the last three with `egresslab-helperctl helper-info`. The policy is metadata, not authorization. `egresslab-helperctl probe-egress-multi PROFILE_ID NAMESPACE < capability.json` takes the signed capability on stdin and no destination argument. Do not hand-craft capabilities or open the managed firewall by hand; the controller signs `PermitMultiProbeV2` (`PermitMultiProbeV1` before Step 30B.2). Changing the pin needs the same provisioning and a helper restart (a new epoch).

### Multi-source verification from the controller (Step 29C.4c)

Start the helper with `-enable-multi-probe` and the pin of Step 29C.4b, with the controller's public key in `/etc/egresslab/helper-auth.pub`. From the host:

```bash
egresslab-controller-lab runtime-status
egresslab-controller-lab helper-info
egresslab-controller-lab multi-probe-policy          # same helper_id, runtime_id and public_key_sha256 as helper-info
egresslab-controller-lab -approve probe-egress-multi <profile ID> <namespace>   # trusted runtime, configured tunnel
```

The answer holds the agreed public IPv4 address, the start and finish times, the earliest observation time (the Cloudflare source), the handshake time and each source's evidence, with `network_ready: false`; both sources must report the same address. Afterwards the tunnel stays configured and its firewall sealed: `verify-lab` says `tunnel_configured`, and read-only checks in the VM (`sudo ip netns pids <ns>`, `sudo ip netns exec <ns> wg show wg0 latest-handshakes`, `sudo ip netns exec <ns> nft list ruleset`) show no process and no `egresslab_probe4` set or permit. Do not retry an uncertain or faulted attempt automatically, and do not fall back to `probe-egress`: inspect `list-labs`, `recover-scan` and the helper log, then delete a faulted lab. Disconnect and delete the lab after a smoke test. The operation allocates no lease, activates no profile and permits no application traffic.

### Sticky IP smoke test (Step 30A)

With one configured tunnel, run two separately approved `-approve probe-egress-multi` attempts without disconnecting in between. The first successful attempt pins the tunnel generation's expected address in the helper; the second must return the same address. A different consensus address faults the tunnel even when both sources agree on it, and a failed attempt returns no evidence and never replaces the pin. The generation and the pin are not printed (no IPC exposes them before Step 30B); the unit tests check them directly. Do not provoke an address change by editing the managed firewall, routes or WireGuard configuration. A `LAB_FAULTED` answer is not necessarily a sticky violation (an HTTPS, consensus or handshake failure looks the same): read the helper log, `list-labs` and `recover-scan`, delete the faulted lab and do not retry on it. Only the helper changed in this step; `egresslab-helperctl`, `egresslab-probe` and the controller stay at Step 29C.4.

Keep the clocks synchronized: the helper checks a capability's `issued_at` with no allowance, so a VM clock behind the host's by more than the request's transit time refuses a fresh capability (`AUTHORIZATION_DENIED`); the 5 s allowance applies only to the evidence the controller checks afterwards. Fix time synchronization rather than the tolerance.

### Generation-bound multi-source verification (Step 30B.2)

Upgrade `egresslab-helper`, `egresslab-helperctl` and the controller together (rebuild `egresslab-probe` from the same revision too). The existing `-enable-multi-probe` flag now enables `PermitMultiProbeV2` only; the start log names `PermitMultiProbeV2`. The provisioned ident.me pin and the controller key stay as they are. Mixed versions refuse each other (no negotiation or fallback): an older controller rejects the V2 policy, and a newer controller gets a usage error from an older helperctl.

```bash
egresslab-controller-lab multi-probe-policy                                   # policy: PermitMultiProbeV2
egresslab-controller-lab multi-probe-target <profile ID> <namespace>          # the configured tunnel's generation
egresslab-controller-lab -approve probe-egress-multi <profile ID> <namespace>
```

`multi-probe-target` is read-only and needs a configured tunnel (a sealed lab answers `INVALID_REQUEST`). The verification result adds `tunnel_generation` and `attempt_nonce` to the evidence of Step 29C.4c, still with `network_ready: false`. Two successful attempts without reconnecting report the same generation and address with different nonces; after a confirmed `disconnect` and `connect-tunnel`, `multi-probe-target` reports a different generation, and capabilities or evidence of the old generation are not accepted for the new tunnel (the unit tests cover the stale capability; do not mint one by hand). The generation, the pin and the nonce never appear in helperctl arguments. Never fall back to a legacy operation. The controller also refuses evidence 60 s or older at receipt, by the host clock against the runtime's `observed_at` with no skew allowance, which is one more reason to keep the clocks synchronized. The output is diagnostic evidence only: no egress lease or application networking is enabled.

### Candidate reservation testing (Step 31A)

`ReserveEgressCandidateV1` is tested with the helper's fake managed tunnel backend, real signatures and real Unix sockets. In Step 31A no client sent it yet; since Step 31D.2 `reserve-egress` does, and Step 31D.3e ran it against the real tunnel on Lima (see "Reservation lifecycle smoke test"). Development stays in the Windows repository; the Linux-only tests run against the same mounted repository through `wsl.exe`, as a normal user (never root). From PowerShell, in `services\network-agent`:

```powershell
go test -count=1 -run 'TestCandidate' ./internal/helperauth ./internal/helperipc
go test -count=100 -run '^TestCandidateConcurrentConsumption$' ./internal/helperipc
wsl -d Ubuntu-22.04 -- bash -lc 'cd /mnt/d/project/egresslab/services/network-agent && go test -race -count=100 -run "^TestCandidateConcurrentConsumption$" ./internal/helperipc && go test -race -count=1 ./...'
```

`-race` needs cgo and a C compiler, which a plain Windows Go install lacks; run it in WSL. Use `bash -lc` there: `wsl --exec go` does not find a Go installed with snap, because `/snap/bin` is set only by a login shell. Do not hand-craft reservation capabilities or open application networking.

### Reservation lifecycle smoke test (Step 31D.3e)

Environment:
- Host OS: macOS 15.3.2 (arm64), Go 1.25.1, controller key in the login Keychain, default data directory (`~/Library/Application Support/EgressLab`, which is also the authority root).
- Lima version: 2.3.0 (`vz`, instance `egresslab`).
- Guest OS and architecture: Ubuntu 24.04.5 LTS, Linux 6.8.0-147-generic, aarch64; iproute2 6.1.0, nftables 1.0.9, wireguard-tools 1.0.20210914.
- Tested commit: `70c7a6e`, controller and the four Linux binaries built from it (hashes compared after install); VM clock within 0.13 s of the host.

The Mac had no controller key and no authority, so `init-key` and `-approve init-reservations` provisioned them; a profile was created through the controller API, the runtime was trusted, and the WireGuard config was staged through `/dev/shm` and shredded. The helper ran with `-enable-multi-probe` (`PermitMultiProbeV2`, the provisioned ident.me pin) for the whole test and was stopped only once `list-reservations` showed no active hold: the append-only journal keeps every hold and release, and a hold whose helper stopped could not be released.

Results:
- Initial reservation and preparation: `-approve reserve-egress` succeeded on its first attempt in 3.8 s (no first-probe worker failure this time): state `prepared`, the reservation on generation A, the prepared lease bound to the same reservation and authority, public IPv4 195.242.214.134, `activation_allowed: false`, `network_ready: false`.
- Duplicate reservation refusal: a second `reserve-egress` answered `EGRESS_RESERVATION_HELD` in the preflight, before anything was signed; the generation and the lab were unchanged, and the helper logged nothing.
- Durable ownership inspection: a new CLI process listed exactly that hold (journal 897 bytes).
- Generation retirement and release: after waiting 65 s (the candidate had expired 47 s earlier), `-approve release-egress` released it in 0.5 s; the receipt named generation A and the original helper epoch, with `generation_retired: true`, `state: released`, `network_ready: false`.
- Kernel cleanup verification: before the release the namespace had no process, `wg0`, a 27 s old handshake, no `egresslab_probe4` set or permit, the sealed output chain and the underlay table; afterwards `verify-lab` said `sealed`, the namespace held only `lo`, the underlay table was gone (only `ip nat` remained in the root namespace), and `list-reservations` was empty (journal 1771 bytes).
- Reconnection with a new generation: `connect-tunnel` with the same profile, namespace and stage got generation B, different from A.
- Reservation after release: `reserve-egress` succeeded in 3.4 s with a new reservation ID, the same profile, runtime, helper epoch and namespace, and generation B.
- Same-address reuse: yes, the provider returned 195.242.214.134 again and it was reserved again.
- Stale release refusal: `release-egress` of the first reservation answered `EGRESS_RESERVATION_NOT_FOUND` before any helper call; reservation B and generation B stayed.
- Final recovery scan: after releasing B (journal 3450 bytes: two holds, two releases) and `delete-lab`, `egresslab-lab-recover` found no EgressLab resources.

Afterwards the helper was stopped with SIGTERM and the vault stage revoked. The controller key, the authority marker and journal, `state.json`, `runtimes.json` and `/etc/egresslab/helper-auth.pub` were kept: the journal keeps the history, and the authority has no key rotation. Not run on WSL2 or native Linux, and with one runtime only.

Application networking remained disabled.

### Multi-runtime collision smoke test (Step 31E.1)

Environment:
- Host OS: macOS 15.3.2 (arm64), Go 1.25.1; the controller key, the authority (`authority_547be0819a5b0e116fa546a726da465b`) and the default data directory of Step 31D.3e, reused as they were.
- Tested commit: `f866a75`; the four Linux binaries were built once from it and installed in both VMs (SHA-256 compared). The controller lab CLI, built from the same commit, ran on the Mac and selected each VM with `-lima-instance`, so both runtimes used the one Keychain key and journal.
- Lima instances: Lima 2.3.0, `vz`; `egresslab` (runtime A) and `egresslab-b` (runtime B), each with its own helper, vault and socket, and the same `/etc/egresslab/helper-auth.pub` and ident.me pin; both clocks within 0.1 s of the host.
- Guest OS and architecture: Ubuntu 24.04.5 LTS, Linux 6.8.0-147-generic, aarch64 in both VMs (iproute2 6.1.0, nftables 1.0.9, wireguard-tools 1.0.20210914).

Two Proton VPN Free WireGuard configs with different client keys were available, but they exit through different servers, so two live tunnels could not show the same address. The collision was therefore run with the first config on both runtimes, one after the other: runtime A reserved and then disconnected its tunnel while its hold stayed durable, and runtime B brought the same config up under a third profile (C). The two client identities ran at the same time only in the last phase. Before the helpers started, the first config was staged for profile A on VM A, and both configs for profiles B and C on VM B, through `/dev/shm` and shredded; VM B's vault kept both stages. Both labs on VM B were created before any tunnel there (`create-lab` is refused while the helper has one), and commands that change `runtimes.json` ran one after the other.

Results:
- Distinct runtime identities: `runtime_3932195e…` with `helper_331ebe34…` (A) and `runtime_a9643767…` with `helper_6b62907e…` (B), both with `authorization_configured: true` and `PermitMultiProbeV2`; after `-approve trust-runtime` on B, `runtimes` listed both.
- Shared controller signing key: both helpers reported `d54e6b1e…`, the Mac key.
- Shared reservation authority: every reservation and release of both runtimes went to the one journal in the Mac default data directory.
- Runtime A reservation: `reserve-egress` succeeded in 3.7 s: `prepared`, 195.242.214.134, `activation_allowed: false`, `network_ready: false`. `disconnect` then answered `sealed` (the namespace kept only `lo`), and `list-reservations` still listed the hold.
- Runtime B observed address: with the same config under profile C, `probe-egress-multi` on runtime B saw 195.242.214.134 from both sources.
- Collision refusal: `reserve-egress` on runtime B exited 1 after 3.2 s with `EGRESS_IP_COLLISION: commit durable reservation: public IPv4 already reserved` and printed no reservation or lease.
- Durable ownership after refusal: the journal was byte for byte unchanged (4257 bytes, same SHA-256), and `list-reservations` listed only A's hold.
- Runtime A retirement and release: after B disconnected its candidate-bearing generation, `release-egress` of A succeeded in 0.3 s, the first real release of a hold whose tunnel was already gone (and before its `eligible_until`): the receipt named A's generation and original helper epoch, with `generation_retired: true`; no hold remained (journal 5131 bytes).
- Runtime B reservation after release: B reconnected profile C (a new generation), and `reserve-egress` succeeded in 3.1 s with a new reservation ID owned by runtime B and its helper epoch.
- Same-address reuse across runtimes: yes, the provider returned 195.242.214.134 again and runtime B held it; it was released in turn (journal 6811 bytes).
- Two client identities at once: with A on the first config and B on the second, both tunnels stayed up together. Each probe kept working after the other runtime connected, and again 150 s later, after both had renewed their handshakes; `reserve-egress` then held 195.242.214.134 (A) and 91.207.174.6 (B) at the same time, two independent owners, both released afterwards. The Free plan did not disconnect either tunnel during the 3 minutes they ran together.
- First-probe failure: the first `probe-egress-multi` on the second config, started right after `connect-tunnel` while A was up, failed (`source cloudflare_trace: managed egress probe failed`) and faulted the lab; after `delete-lab` and `create-lab` it worked alone, and then with A up as well. It matches the open first-probe failure (see "Next Milestone"); the provider's connection limit does not explain it, since both tunnels later ran together.
- Final recovery scans: after every hold was released (journal 10164 bytes; this run added four holds and four releases) and the three labs were deleted, `egresslab-lab-recover` found no EgressLab resources in either VM.

Afterwards both helpers were stopped with SIGTERM, once `list-reservations` was empty, and all three vault stages were revoked. The trust record of runtime B and the profile bindings were kept, like the controller key, the authority and its journal. Not run on WSL2 or native Linux. The collision was between two runtimes using the same client key one after the other, not two live tunnels sharing one address.

Application networking remained disabled.

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

Ubuntu 22.04 (the WSL2 distribution) has no `whois` by default; Team Cymru serves the same data over DNS: `dig +short TXT <reversed IPv4>.origin.asn.cymru.com`, whose first field is the ASN.

If DNS returns several addresses, do not take the first one blindly. The provider does not promise a stable address. DNS at probe time, automatic replacement of the address and skipping certificate verification (`curl -k`) are not allowed. A host-side check reveals the host's own public IP to the provider; it is not a managed observation and never activates an egress lease. The helper reads the approved pin from `/etc/egresslab/multi-probe-pin` at startup (Step 29C.4b, see "Multi-source helper").

## Next Milestone

Step 31E: the remaining concurrent and recovery tests across runtimes, on top of the collision refused across two Lima runtimes (Step 31E.1), the reservation lifecycle verified on Lima against the real tunnel (Step 31D.3e), the controller's release command (Step 31D.3d.2), the durable release journal (Step 31D.3d.1), the helper's generation-bound revocation (Step 31D.3c), the controller's lease preparation (Step 31D.3b), the helper's prepared lease (Step 31D.3a), the provisioned reservation authority and its CLI commands (Step 31D.2), the signed reservation orchestration (Step 31D.1), the controller's durable reservation authority (Step 31C), its in-process registry (Step 31B), the helper's local egress candidate (Step 31A), the generation-scoped pin (Step 30A), the signed generation binding (Step 30B.1) and the V2 cutover (Step 30B.2). Open: the first signed attempt of a session sometimes fails because a probe worker exits with an error the helper does not record (Steps 29B.1, 29B.2b, 29C.4c, 30A and 30B.2 on Lima, and the single-source probe on WSL2; in the last four it was the first probe of the session, and a fresh lab then succeeded; in Step 31E.1 it was the first probe right after `connect-tunnel` on runtime B's second config, and a fresh lab then succeeded too); a coded worker failure reason in the helper log would explain it. WSL2 ran the single-source and multi-source paths on 2026-11-25; native Linux has not. See `docs/PRIVILEGED-HELPER.md`.
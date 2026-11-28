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

## Installing a release

Since v0.3.0-alpha.1, release archives hold prebuilt binaries. With them, this guide's build steps are not needed.

**1. Verify every archive** in the folder that holds `SHA256SUMS`.

Windows (PowerShell):

```powershell
Get-Content SHA256SUMS -ErrorAction Stop | ForEach-Object {
    $expected, $file = $_ -split '\s+', 2
    $actual = (Get-FileHash -Path $file -Algorithm SHA256 -ErrorAction Stop).Hash
    if ($actual.ToLower() -ne $expected.ToLower()) { throw "Checksum mismatch: $file" }
    Write-Host "OK: $file"
}
```

macOS: `shasum -a 256 -c SHA256SUMS`. Linux: `sha256sum -c SHA256SUMS`.

**2. Install the controller** on the host. Extract `egresslab-controller-<os>-<arch>` anywhere, and run `egresslab-controller-lab` and `egresslab-controller` from there.

**3. Install the runtime** in the Linux guest (WSL2 or Lima). Take the archive whose architecture matches `uname -m`: `x86_64` is amd64, `aarch64` is arm64. Upgrade only after every related reservation is released and the old helper has stopped.

The subshell starts from an empty folder and stops at the first failure with a non-zero status, so it never installs stale or partial binaries:

```bash
(
    set -e
    rm -rf runtime-release
    mkdir runtime-release
    tar -xzf egresslab-runtime-linux-amd64.tar.gz -C runtime-release
    cd runtime-release
    for binary in egresslab-agent egresslab-helper egresslab-helperctl egresslab-probe egresslab-proxy-dial egresslab-lab-recover; do
        sudo install -o root -g root -m 0755 "$binary" "/usr/local/bin/$binary"
    done
)
```

**4. Provision only what is new.** An environment that is already provisioned keeps its signing key, vault, trust record and reservation authority; never create them again. A new environment follows the sections below: the helper, `trust-runtime`, the vault stage and `init-reservations`.

**Controllers.** Since Step 37 the HTTP controller and the desktop app's controller take a writer lock on their data directory. Stop a controller from an earlier release before starting a new one: the old one takes no lock.

**Versions.** `RELEASE-INFO.txt` names the release version and commit. The version that `egresslab-controller` reports (0.1.0, in its startup log and health response) is its control API version, which a release does not change.

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
egresslab-controller-lab -approve recover-egress <reservation ID>                       # only after a helper crash and a guest reboot
egresslab-controller-lab -approve serve-socks <reservation ID> 1080                    # SOCKS5 on 127.0.0.1:1080, foreground
egresslab-controller-lab -approve serve-endpoint <endpoint ID>                          # a stored SOCKS5 endpoint, foreground
egresslab-controller-lab -approve -recover [-recover-ip same|any] [-recover-attempts N] serve-endpoint <endpoint ID>   # replaces a faulted route
```

`disconnect` and `delete-lab` never release a durable reservation; only `release-egress` does, through the runtime and helper process that hold it, or `recover-egress` after that helper crashed and the guest rebooted (Step 31E.3). Do not copy an authority between hosts or run `init-reservations` again to work around a mismatch.

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
- Initial reservation and preparation: `-approve reserve-egress` succeeded on its first attempt in 3.8 s (no first-probe worker failure this time): state `prepared`, the reservation on generation A, the prepared lease bound to the same reservation and authority, public IPv4 egress A, `activation_allowed: false`, `network_ready: false`.
- Duplicate reservation refusal: a second `reserve-egress` answered `EGRESS_RESERVATION_HELD` in the preflight, before anything was signed; the generation and the lab were unchanged, and the helper logged nothing.
- Durable ownership inspection: a new CLI process listed exactly that hold (journal 897 bytes).
- Generation retirement and release: after waiting 65 s (the candidate had expired 47 s earlier), `-approve release-egress` released it in 0.5 s; the receipt named generation A and the original helper epoch, with `generation_retired: true`, `state: released`, `network_ready: false`.
- Kernel cleanup verification: before the release the namespace had no process, `wg0`, a 27 s old handshake, no `egresslab_probe4` set or permit, the sealed output chain and the underlay table; afterwards `verify-lab` said `sealed`, the namespace held only `lo`, the underlay table was gone (only `ip nat` remained in the root namespace), and `list-reservations` was empty (journal 1771 bytes).
- Reconnection with a new generation: `connect-tunnel` with the same profile, namespace and stage got generation B, different from A.
- Reservation after release: `reserve-egress` succeeded in 3.4 s with a new reservation ID, the same profile, runtime, helper epoch and namespace, and generation B.
- Same-address reuse: yes, the provider returned egress A again and it was reserved again.
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
- Runtime A reservation: `reserve-egress` succeeded in 3.7 s: `prepared`, egress A, `activation_allowed: false`, `network_ready: false`. `disconnect` then answered `sealed` (the namespace kept only `lo`), and `list-reservations` still listed the hold.
- Runtime B observed address: with the same config under profile C, `probe-egress-multi` on runtime B saw egress A from both sources.
- Collision refusal: `reserve-egress` on runtime B exited 1 after 3.2 s with `EGRESS_IP_COLLISION: commit durable reservation: public IPv4 already reserved` and printed no reservation or lease.
- Durable ownership after refusal: the journal was byte for byte unchanged (4257 bytes, same SHA-256), and `list-reservations` listed only A's hold.
- Runtime A retirement and release: after B disconnected its candidate-bearing generation, `release-egress` of A succeeded in 0.3 s, the first real release of a hold whose tunnel was already gone (and before its `eligible_until`): the receipt named A's generation and original helper epoch, with `generation_retired: true`; no hold remained (journal 5131 bytes).
- Runtime B reservation after release: B reconnected profile C (a new generation), and `reserve-egress` succeeded in 3.1 s with a new reservation ID owned by runtime B and its helper epoch.
- Same-address reuse across runtimes: yes, the provider returned egress A again and runtime B held it; it was released in turn (journal 6811 bytes).
- Two client identities at once: with A on the first config and B on the second, both tunnels stayed up together. Each probe kept working after the other runtime connected, and again 150 s later, after both had renewed their handshakes; `reserve-egress` then held egress A (runtime A) and egress B (runtime B) at the same time, two independent owners, both released afterwards. The Free plan did not disconnect either tunnel during the 3 minutes they ran together.
- First-probe failure: the first `probe-egress-multi` on the second config, started right after `connect-tunnel` while A was up, failed (`source cloudflare_trace: managed egress probe failed`) and faulted the lab; after `delete-lab` and `create-lab` it worked alone, and then with A up as well. It matches the open first-probe failure (see "Next Milestone"); the provider's connection limit does not explain it, since both tunnels later ran together.
- Final recovery scans: after every hold was released (journal 10164 bytes; this run added four holds and four releases) and the three labs were deleted, `egresslab-lab-recover` found no EgressLab resources in either VM.

Afterwards both helpers were stopped with SIGTERM, once `list-reservations` was empty, and all three vault stages were revoked. The trust record of runtime B and the profile bindings were kept, like the controller key, the authority and its journal. Not run on WSL2 or native Linux. The collision was between two runtimes using the same client key one after the other, not two live tunnels sharing one address.

Application networking remained disabled.

### Concurrent reservation testing (Step 31E.2)

Environment:
- Host OS: macOS 15.3.2 (arm64), Go 1.25.1; the controller key, authority and default data directory of Steps 31D.3e and 31E.1.
- Tested commit: `9c4672b` with this step's test files; no production code changed, and the controller and network agent sources are unchanged since `f866a75`, so its binaries were reused.
- Lima instances: `egresslab` (runtime A, the first config) and `egresslab-b` (runtime B, the second config) as in Step 31E.1, both already trusted; the helpers were restarted with new epochs, and both clocks were within 0.1 s of the host.

Results:
- V2 concurrent reservation: two processes reserving 8.8.4.4 for different owners: exactly one hold every time, owned by the winner.
- Concurrent release and reserve: the release of the hold against a new owner's reservation of the same address: never two owners, the original hold kept whenever the release lost. A sequential run transferred the address: the new owner's reservation process opened the authority and built its admission before another process committed the release, and was granted once let through; the stale release then answered `ErrReservationNotFound` without touching the new owner.
- Concurrent duplicate release: two processes releasing one hold: exactly one release record, no active hold, the reservation ID and owner kept in the history.
- Stress test repetitions: `-count=50` of the three race tests (150 races) passed on macOS. In every race the loser got `busy`: between two reservations the first child won 22 times and the second 28; between a release and a reservation the release won 29 times, and 21 times the reservation won the lock and answered `collision` while the release got `busy`; between two releases the first child released 23 times and the second 27. With the final test code, all five `TestAuthority*` tests (the three races, the sequential case and the fail-fast lock below) passed 50 times each on macOS and on Linux (Lima VM, arm64). With the `flock` call removed, the reservation and duplicate-release races failed 20 runs out of 20 (duplicate grants, two releases, a corrupt journal), and the release and reserve race did not fail in 20 runs.
- Fail-fast lock: with a child process holding the authority marker and the journal, only the marker, or only the journal, a reservation, a release and a listing answered `ErrReservationBusy` at once, and the release succeeded after the child exited. With a blocking `flock`, this test failed 3 runs out of 3 while every race test still passed; with the V2 journal opened without its lock, the journal-only case failed 3 runs out of 3, and with the marker opened without its lock, the marker-only case did too.
- Race detector: `-race -count=5` passed with no data race; `go test -race ./...` and `go build ./...` passed, `go vet` passed for darwin, linux (arm64, 386) and windows, and staticcheck reported only its two earlier unused-function warnings.
- Real concurrent reservations: two `-approve reserve-egress` processes started within 1 ms of each other. B prepared egress B in 2.8 s; A answered `RESERVATION_BUSY` after 62 ms, when the CLI opened the authority, before any runtime call or signature (its lab stayed `tunnel_configured` on the same generation, and its helper logged nothing). A separate approved `reserve-egress` then prepared egress A for A in 3.5 s on that generation; `activation_allowed` and `network_ready` stayed `false`.
- Real concurrent releases: two `-approve release-egress` processes started together. A was released in 0.4 s with `generation_retired: true`; B answered `RESERVATION_BUSY` after 60 ms, again when the CLI opened the authority, so its helper was not called, its tunnel stayed configured and its hold listed. No `EGRESS_RELEASE_UNCONFIRMED` occurred. A separate approved `release-egress` released B in 0.3 s.
- Final durable ownership: no active hold; this run added two holds and two releases (journal 10164 to 13520 bytes).
- Final recovery scans: after `delete-lab` of both labs, `egresslab-lab-recover` found no EgressLab resources in either VM; the helpers were then stopped and both vault stages revoked.
- First-probe failure: the first `probe-egress-multi` of both new helpers, about a second after `connect-tunnel` (the handshake had already completed), failed on `cloudflare_trace` and faulted both labs. After `delete-lab`, `create-lab` and `connect-tunnel`, both probes succeeded 10 s after connecting; no reservation was attempted on a faulted lab.

Limitations:
- Simultaneous same-address live tunnels: not tested. The two configs exit through different servers, and one client key on two live tunnels would make them take over each other's WireGuard session; the same address is covered only by the synthetic admissions of the subprocess tests.
- Helper restart recovery: not tested. A hold whose helper restarted still cannot be released, so the helpers were restarted and stopped only with no active hold.
- Contention: the CLI opens the authority under the same non-blocking lock, so commands started together often lose immediately with `RESERVATION_BUSY`; the operator runs them again, nothing retries. In both real rounds the loser stopped there, so two real operations never overlapped in their probe or commit phase; only the subprocess tests reach the commit boundary together. Since Step 35 opening the authority is a shared read, so such commands no longer lose at the open; they meet at the exclusive commit instead, as the subprocess tests do.

Application networking remained disabled.

### Helper epoch witness (Step 31E.3a)

Environment:
- Host OS: macOS 15.3.2 (arm64), Go 1.25.1; tested commit `1f4e895` with this step's changes.
- Lima instance: `egresslab` (runtime A of Steps 31E.1 and 31E.2; Ubuntu 24.04.5, kernel 6.8.0-147-generic, arm64). Only its helper was replaced, built with `-trimpath` and `CGO_ENABLED=0`; the controller, helperctl and the IPC protocol are unchanged, and `egresslab-b` was not touched.

Unit tests:
- On Linux (the cross-compiled test binary, run as the normal user without sudo): `TestKernelBootIDParsing`, `TestReadActualKernelBootID`, `TestEpochWitnessRegistersKernelBoot`, `TestEpochWitnessPersistence`, `TestEpochWitnessBootHistory`, `TestEpochWitnessRejectsDuplicate`, `TestEpochWitnessCorruption`, `TestEpochWitnessRejectsUnsafePermissions`, `TestEpochWitnessRejectsSymlink`, `TestEpochWitnessHistoryLimit`, `TestEpochWitnessRejectsNoncanonical` and `TestEpochWitnessDetectsChangedValue` passed; `-count=50` of `^TestEpochWitness` passed, and so did the whole helper test binary. The race detector did not run (no cgo in the cross-compiled binary).
- The upper-case boot ID case first used an all-digit ID, which upper-casing leaves unchanged, so it failed by accepting a valid ID; it now uses an ID with letters.
- On macOS (the new files are Linux-only): `go vet ./...`, `go test ./...` and `go build ./...` passed, and `GOOS=linux go vet` passed for arm64 and amd64.

Real witness persistence (one boot, no hold, no lab), with the final build:
- Before: `list-reservations` showed no hold, no helper ran in either VM, and `egresslab-lab-recover` found nothing. A first build without the checksum had already passed the start, restart and `0644` runs below; the final build refused its three-entry ledger (`invalid or noncanonical epoch witness ledger`, exit status 1, no socket, file unchanged), and that ledger was then removed, since no hold depended on it.
- Leftover socket: with a file at `/run/egresslab/helper.sock`, the helper exited with status 1 (`... already exists`) and created no ledger; the file was then removed.
- First start: the helper logged `Persistent boot-bound helper epoch witness committed` before listening. `helper-epochs.json` was `root root 600` with one link and held one entry whose helper ID, runtime ID and key fingerprint matched `egresslab-helperctl helper-info`, and whose boot ID matched `/proc/sys/kernel/random/boot_id`; its SHA-256, recomputed independently with Python, matched.
- Restart without reboot (SIGTERM, then the same command): a second entry with a new helper ID and the same runtime ID, boot ID and fingerprint; the first entry was unchanged, the checksum matched, and no temporary file was left in the vault directory.
- Fail closed: with the ledger made `0644`, the helper exited with status 1 (`persistent helper epoch registration: read existing helper epochs: vault file must be root-owned, regular, mode 0600, without hard links`) and created no `/run/egresslab/helper.sock`; the ledger's SHA-256 did not change. Back at `0600`, a third start committed its witness and listened: three entries, one boot ID, one runtime ID.
- After: the helper stopped, its socket removed, no reservation, and `egresslab-lab-recover` found nothing; the VM's temporary test directory was removed.

Limitations:
- No guest reboot and no helper crash with a durable hold were tested; that is Step 31E.3d.
- A hold made before this step whose helper is gone stays unreleasable.

Application networking remained disabled.

### Crash and reboot recovery smoke test (Step 31E.3)

Environment:
- Host OS: macOS 15.3.2 (arm64), Go 1.25.1; tested commit `e958131` with this step's changes; the Keychain key, authority and journal of the earlier steps.
- Lima instance: `egresslab` (runtime A; Ubuntu 24.04.5, kernel 6.8.0-147-generic, arm64) with the first config staged for `profile_98e0aaeb5ef3564c`; `egresslab-b` was not touched. The controller CLI, helper, helperctl, probe worker and `egresslab-lab-recover` were built from this tree with `-trimpath` (the Linux ones with `CGO_ENABLED=0`) and installed in `/usr/local/bin`.

Tests:
- macOS: for the controller, `go vet` (darwin, linux, windows), `go test ./...`, `go test -race ./...` and `go build ./...` passed; for the network agent, `go vet` (darwin, linux), `go test ./...` and `go build ./...`. The recovery golden vector (`slPnw8KU…`) matches in both modules.
- Linux (the cross-compiled test binaries of the helper, `helperipc` and `helperauth`, run as the normal user): all passed, including `TestEpochWitnessRecovery` (valid; same boot; missing original or current witness; current epoch not the latest; wrong runtime, key or kernel boot; same epoch) and `TestRecoveredGenerationIPC` (a real socket and real signatures with a synthetic witness proof: success, replay, same boot, the original epoch itself).
- With the controller's distinct-boot check removed, the same-boot recovery flow and the transport test failed.

Real crash and reboot:
- Rehearsal without a hold: `systemctl reboot` restarted the guest (Lima kept it `Running`), changed the boot ID and kept the runtime ID; the guest clock was within 0.03 s of the host.
- The new controller read the real journal (13520 bytes, no hold) before writing anything.
- Hold: `reserve-egress`, 10 s after `connect-tunnel`, prepared egress A as `reservation_15dc65fa…` in 3.7 s, owned by helper epoch `helper_146017d7…`, whose witness named the current boot `6deaa2d7…`; it was the only hold.
- Crash: `kill -KILL` of that helper's PID. Its log had no `EgressLab helper stopped`, `helper.sock` stayed, the hold stayed listed, and `egresslab-lab-recover` reported the orphan namespace (`owner pid 1335 is gone`) and its kept underlay table; neither was removed.
- Same boot (added to the planned run): after the stale socket was removed as the helper's message instructs, a new epoch started (and logged that `CreateLab` is refused until the leftovers are recovered). `release-egress` answered `INVALID_EGRESS_RELEASE` (the original epoch is required) before signing; `recover-egress` answered `EGRESS_REVOCATION_UNCONFIRMED` with the helper's `AUTHORIZATION_DENIED`, and the helper logged `epoch witness: kernel reboot not established`. The hold stayed.
- Reboot: boot `6deaa2d7…` became `d39d0bd8…`; the namespace, underlay table and socket were gone, and `egresslab-lab-recover` found nothing.
- Recovery: a third epoch `helper_d5d0f8c0…` started; `release-egress` still answered `INVALID_EGRESS_RELEASE`, and `-approve recover-egress` released the hold in 0.3 s with a `RecoverRetiredGenerationV1` receipt naming the crashed epoch as `original_helper_id`, the new one as `helper_id`, both boot IDs and `generation_retired: true`; `state` was `released`, and `activation_allowed` and `network_ready` were `false`. The journal grew from 14326 to 15385 bytes and listed no hold; a second `recover-egress` answered `EGRESS_RESERVATION_NOT_FOUND`.
- Lifecycle afterwards: a new lab and tunnel; `reserve-egress`, 10 s after connecting, held the same address for the new epoch, and `release-egress` released it with a normal `RevokeEgressLeaseV1` receipt (no boot IDs). Journal: 17066 bytes.
- No downgrade: a controller built from `e958131` answered `RESERVATION_JOURNAL_CORRUPT` at byte 14326, the recovery's release frame, on `list-reservations`, while the new build listed the journal normally.
- After: `delete-lab`, no labs, `egresslab-lab-recover` found nothing, the helper stopped and the vault stage revoked; the ledger held 7 witnesses over 3 boots and one runtime, with a valid checksum.

Limitations:
- Recovery trusts the guest: a cloned VM, a restored snapshot or root in the runtime is outside the guarantee.
- A helper restarted without a reboot, a hold whose generation the backend contradicted and a hold made before Step 31E.3a stay unreleasable.
- Only Lima ran it; WSL2 and native Linux did not.

Application networking remained disabled.

### Continuous egress monitoring smoke test (Step 32)

Environment:
- Host OS: macOS 15.3.2 (arm64), Go 1.25.1; tested commit `195919a` with this step's changes.
- Lima instance: `egresslab` (runtime A; Ubuntu 24.04.5, kernel 6.8.0-147-generic, arm64) with the first config staged for `profile_98e0aaeb5ef3564c`. Only the helper was replaced (sha256 `f7a25348…`, `-trimpath`, `CGO_ENABLED=0`); the controller CLI, helperctl and probe worker are the Step 31E.3 builds.

Tests:
- macOS: `go vet` (darwin, linux), `go test -race ./...`, `go test -race -count=50 -run '^TestEgressMonitor'` and `go build` (darwin, linux) passed.
- Linux (the cross-compiled test binaries of `internal/agent` with its test data and sources, `internal/helperipc` and the helper, run as the normal user): passed, and `-count=50` of `^TestEgressMonitor` passed.
- The monitor tests cover a renewal that leaves the original evidence, receipt and reservable state untouched; a busy lifecycle (no probe, no renewal); a changed address, a source disagreement, a failed probe, a wrong or drifted generation, a changed policy and expired health, each faulting the lab and dropping the prepared lease, with the generation retired (and `release-egress` confirmable) only after a confirmed, uncontradicted cleanup; an old monitor leaving a new generation alone; and a stalled log sink. Drift is covered only by the fake backend.

Real run:
- Before: no hold, no helper, and the stage revoked in Step 31E.3, so the config was staged again.
- The helper started at 14:16:49 (guest time). `reserve-egress`, 10 s after `connect-tunnel`, prepared egress A as `reservation_94ec6ade…` on `tunnelgen_bf491829…` (14:17:17 to 14:17:21); the original evidence was observed at 14:17:19 and the prepared lease expired at 14:18:18.
- Monitor: `Egress monitor healthy` at 14:17:44, 14:18:07, 14:18:31, 14:18:54, 14:19:18, 14:19:41 and 14:20:04, every 23 to 24 s, all with the same reservation, generation and address; four of them after the original evidence had expired. No monitor fault occurred.
- At 14:19:41, right after a healthy line: `verify-lab` answered `tunnel_configured`, `list-reservations` showed the same reservation, address, generation and helper epoch, `multi-probe-target` the same generation, and `network_ready` stayed `false`.
- At 14:20:04, right after a healthy line, `-approve release-egress` released it with a normal `RevokeEgressLeaseV1` receipt (`generation_retired: true`); no `LAB_BUSY` occurred. Journal: 17066 to 18747 bytes.
- After: `delete-lab`, no labs, `egresslab-lab-recover` found nothing; no healthy line followed the release through 14:21:04 (more than two intervals); the helper then stopped cleanly and the vault stage was revoked.

Limitations:
- The monitor loop and its start and stop wiring are covered only by this run; drift only by the fake backend.
- No probe failed, so the new worker reason codes were not observed.
- While a monitor probe runs, release and disconnect answer `LAB_BUSY` and must be approved again; teardown has no priority.

Application networking remained disabled.

### Kernel traffic gate test (Step 33)

Environment:
- Host OS: macOS 15.3.2 (arm64), Go 1.25.1; tested commit `7356812` with this step's changes.
- Lima instance: `egresslab` (Ubuntu 24.04.5, kernel 6.8.0-147-generic, arm64, nft 1.0.9). No VPN, reservation or managed lab was used, and no managed namespace's firewall was touched; the helper was not reinstalled. The dedicated user `egresslab-proxy` (UID 997) was created with `useradd --system --user-group --no-create-home --shell /usr/sbin/nologin`.

Tests:
- macOS: `go vet` (darwin, linux), `go test -race ./...`, `-race -count=20` of the gate and window tests, and `go build` (darwin, linux) passed.
- Linux (the cross-compiled test binaries of `internal/agent` with its test data and sources, `internal/helperipc` and the helper, run as the normal user): passed, including `TestManagedTrafficGateRealCapture` and `TestTunnelBackendOffersTrafficWindow` (the helper's backend wrapper exposes the gate to the lifecycle).

Real kernel run (two throwaway namespaces joined by a veth pair, the client side named `wg0`, 192.0.2.1 and 192.0.2.2, no default route, so no Internet): the client namespace got exactly `sealLabRules` and the script of `managedTrafficRules(997)`, both written out by the code; a TCP and UDP echo server ran in the peer namespace, and the clients ran through `setpriv` with no supplementary groups.

| Test | Result |
|---|---|
| Gate not open, proxy UID, TCP | blocked (timeout) |
| Gate active, proxy UID, TCP | allowed (echo) |
| Gate active, another UID (999), TCP | blocked |
| Gate active, root, TCP | blocked |
| Gate active, IPv6 TCP | blocked |
| Gate active, UDP | blocked (`EPERM`) |
| Gate active, TCP 53 and 853 | blocked |
| New connection 10.4 s after opening | blocked |
| Connection established while active | after expiry, data the server pushed never arrived, and data the client sent never reached the server |
| Stale flow: UID 999 connected through a temporary unmarked permit (like a probe window), removed before the gate opened | data the server pushed while the gate was open never arrived |
| Gate removed by its handles | no gate object left; the ruleset was byte-identical to the sealed one before the gate; still blocked |

- Review found that the first input permit (any established TCP on `wg0`) also admitted flows opened before the gate. With that permit, the stale-flow row failed: the push **arrived**. The permits now mark admitted connections (`ct mark set`) and accept only marked replies; with them, every row above passed. The first permit passed every other row in two earlier runs.
- The readbacks of the final run while active, after expiry and after removal are the test data `nft-lab-traffic-active.json`, `nft-lab-traffic-expired.json` and `nft-lab-traffic-closed.json`; nft 1.0.9 printed the permits exactly in the expected canonical form (the UID and the mark as numbers, the mark statement as `mangle`), and the expired set had no `elem`. The temporary permits of the stale-flow test used handles 13 and 14, so the gate's are 15 and 16.
- After: both namespaces deleted, and `egresslab-lab-recover` found nothing.

Limitations:
- The gate ran with the code's scripts but not through `WithTrafficWindow` on a live managed tunnel: no caller exists yet, and its open, verify and close sequence is covered by the fake kernel with the real captures.
- No helper crash or hang was simulated while a gate was open; the expiry itself is the kernel's and was observed.

Application networking remained disabled.

### SOCKS5 proxy smoke test (Step 34)

Environment:
- Host OS: macOS 15.3.2 (arm64), Go 1.25.1; tested commit `145f06b` with this step's changes.
- Lima instance: `egresslab` (Ubuntu 24.04.5, kernel 6.8.0-147-generic, arm64, nft 1.0.9), with the first config staged for `profile_98e0aaeb5ef3564c`. The helper, helperctl and `egresslab-proxy-dial` (in `/usr/local/bin`) and the controller CLI were built from this tree; the helper ran with `-enable-proxy -proxy-uid 997 -proxy-gid 987` (`egresslab-proxy`).

Socket handoff in the kernel (two throwaway namespaces as in Step 33, with public-format addresses 11.0.0.1 and 11.0.0.2 and no default route; a scratch test, run as root, called `dialInNamespace` with the installed worker, the code's gate scripts and its verifier):
- With the gate closed the worker could not connect. With it open, the socket was handed over in 0.01 s and `ip netns pids` was empty afterwards.
- A gate for UID 999 did not pass the UID 997 socket: `meta skuid` still matches the creator after `SCM_RIGHTS`. A probe window for another destination did not pass it either.
- Cadence, with a server that pushes every 200 ms while the client stays silent: with 6 s open and 17 s closed (the Step 33 cadence), **no data arrived in four windows** after the first close; with 8 s/4 s, 6 s/6 s and 6 s/10 s, data resumed in every window (after about 2.6 s, 0.6 s and 3.3 s). A client writing every 500 ms recovered within 0.32 s even at 6 s/17 s. Windows therefore chain to the monitor's renewal deadline now (the user's choice), so the gate closes only while the monitor probes.

`limactl shell` as a stream transport: 1 MiB of random bytes went through unchanged, and closing stdin reached the guest as EOF. A killed `limactl` left the guest process running with no EOF (still there 12 s later), and closing stdout, even with stderr, in the guest did not reach the host while the process lived; hence the framing in both directions.

Tests: on macOS `go vet` (darwin, linux, windows for the controller), `go test -race ./...` and `go build` passed for both modules, including the SOCKS5 protocol tests (wrong password, no authentication, fragmented greeting, BIND, UDP ASSOCIATE, domain names, IPv6, port 0, a refused destination, a failed dial, shutdown, a stream ended in the runtime, an idle client after the destination's FIN), the transport (binary data over several frames, FIN, END, refusal, an invalid ack, cancellation) and helperctl's stream mode (an upload after the destination's FIN). On Lima the cross-compiled test binaries of `internal/agent`, `internal/helperipc`, `internal/helperauth`, the helper and helperctl passed, and three runs of the helper's stream tests (an echo across windows, a replay, an expired health, a forged destination, a failed dial, a disabled proxy, a release closing the stream, a replaced stream, an abandoned request, a wait out a busy lifecycle).

Real run (the egress address is compared, never printed):
- `serve-socks` listened on `127.0.0.1:1080` only, with `network_ready: false`.
- Through `curl -4 --socks5` (local name resolution, certificate verification on), `https://api.ipify.org` returned the reserved address (egress A) every time; the first request of a new stream took 2.3 to 11.1 s, later back-to-back requests about 2 s each.
- Refused as expected: a wrong password (RFC 1929 failure); `1.1.1.1`, TCP port 53 and `192.168.1.1` (reply 2, not allowed); a domain name through `--socks5-hostname` (reply 8).
- A download of `https://proof.ovh.net/files/100Mb.dat` limited to 150 KB/s ran 400 s (curl's own limit) and received 61.6 MB at a steady rate across 18 monitor checks, with one stall of about 24 s (t=61 to 83 s) that began well before a check; no monitor fault. `speed.cloudflare.com` answered 403 to the VPN address.
- `kill -KILL` of `serve-socks` during a download: curl got a partial file, the orphaned `limactl` forwarded the controller's closed stdin as EOF, so helperctl exited at once; a restarted `serve-socks` served a new request in 5.5 s.
- `-approve release-egress` during a download: released in 0.5 s (the stream was preempted), with a normal `RevokeEgressLeaseV1` receipt and no hold left; the lab went back to sealed. curl then drained about 3.3 MB already buffered between the helper and its rate-limited reader and ended with a partial file; a new CONNECT answered a general failure (`reservation is not held`).
- Found and fixed during the run: the first CONNECT answered `LAB_BUSY` while the monitor probed (an authorized request now waits up to 5 s for the lock), and back-to-back clients were reset while the previous stream still closed through the tunnel (a client now waits up to 10 s for the slot; closing a stream no longer blocks it).
- After: `serve-socks` stopped on SIGINT (exit 0), `delete-lab`, `egresslab-lab-recover` found nothing, the helper stopped and the stage was revoked. The helper logged 32 healthy checks, no fault and no dial error. Journal: 18747 to 22105 bytes (two holds, two releases).

Limitations:
- One stream per runtime, IPv4 only, no domain names; traffic pauses at each monitor check, and a rate-limited reader saw one 24 s stall (most likely zero-window probes backing off while the gate was closed).
- WSL2 and native Linux did not run it; the handoff harness is a scratch test, not part of the tree.
- The last fixes (the lock wait, the client slot wait, the non-blocking close) came after the review.

Application networking as a whole remained disabled.

### Endpoint integration test on two runtimes (Step 35)

Environment:
- Host OS: macOS 15.3.2 (arm64), Go 1.25.1; tested commit `3613cdb` with this step's controller changes. The helpers, helperctl and workers are the Step 34 builds, installed in both instances (the same SHA-256 in each); `egresslab-b` was upgraded to them and got the `egresslab-proxy` user.
- Route A: `egresslab`, the first config, `profile_98e0aaeb5ef3564c`, endpoint on port 1080. Route B: `egresslab-b`, the second config, `profile_3b12e9450758a345`, endpoint on port 1081. One reservation authority for both.

Tests: on macOS `go vet` (darwin, linux, windows), `go test -race ./...` and `go build ./...` passed, including `TestServeEndpointArguments` (approval, arguments, runtime flags refused), `TestEndpointPlanLifecycle` (no hold, resolution, release) and `TestEndpointPlanRefusesOtherEndpoints`.

Real run:
- Both routes reserved, prepared and distinct: egress A (route A) and egress B (route B).
- The two endpoints were created through the HTTP API (`POST /api/v1/endpoints`, as the desktop does); they stayed `draft`, and the API's start answered 409. `serve-endpoint` served each from its stored configuration, with no runtime or reservation given, on `127.0.0.1` only.
- Two listeners started at the same moment: the second answered `RESERVATION_BUSY` at start (the authority's non-blocking lock) and was started again.
- Concurrent requests to `https://api.ipify.org` through both endpoints, six rounds: 11 of 12 matched their own reserved address, and the two addresses always differed. The twelfth (round 1, A) was refused because its per-CONNECT check found the shared journal locked by B's (`egress reservation registry unavailable`); the same happened to one of two downloads started together. No CONNECT ever used the other route's address.
- A rate-limited download through B ran 45 s at the expected rate while a wrong password was refused on A.
- Releasing A during a download through A: released in 0.5 s; B still matched its address; a new CONNECT on A was refused (`reservation is not held`).
- A new tunnel generation and hold for profile A (the same address, a new reservation): the running A listener refused it (`endpoint binding changed; restart it with a new approval`); restarted with a new approval, it served the new reservation, matching, while B kept its own.
- After: both listeners stopped on SIGINT, every hold released, both labs deleted, `egresslab-lab-recover` found nothing in either instance, the helpers stopped and both stages revoked. Journal: 22105 to 27138 bytes. The two endpoint definitions stay in the controller state.

Limitations:
- In this run, concurrent CONNECTs on two listeners collided on the journal's exclusive lock and failed; nothing retries.
- After this run, from the Codex review: journal reads (opening the authority, listing, lookups) take the lock shared, so listeners no longer block each other; only a concurrent write (reserve or release) still makes a CONNECT or a start busy. The per-CONNECT check moved after the helper call and the mint, right before the capability is sent, and the journal is read once instead of twice (the hold through the mint; endpoint, binding and trust from the controller's files). A later hold on the same helper keeps the binding, so it is now refused by the mint (`reservation is not held`) rather than as `endpoint binding changed`. Tests: `TestReservationAuthorityReadersShare`, `TestServeEndpointRevalidatesEachConnect` (the endpoint deleted during the helper call: no capability sent; it fails with the check moved before the call) and the later hold in `TestEndpointPlanLifecycle`. Re-run on Lima in the next test (several streams per runtime).
- The checks resolve names on the host (curl's `--socks5`): they prove the data plane, not DNS isolation.
- Windows was not tested in this run; see "Windows and WSL2 run (Step 35)".

Application networking as a whole remained disabled.

### Several streams per runtime on two runtimes (Step 35)

Environment:
- Host OS: macOS 15.3.2 (arm64), Go 1.25.1; commit `36f2e88`. The helper, helperctl, `egresslab-proxy-dial`, the probe worker and `egresslab-lab-recover` were built from it with `-trimpath` and `CGO_ENABLED=0` and installed in both instances (the same SHA-256 in each; helper `7e4de451…`); the controller CLI was built from it on macOS.
- Routes as in the endpoint test above: A on `egresslab` (first config, endpoint on port 1080), B on `egresslab-b` (second config, port 1081), one reservation authority. Both configs were staged through a private `/dev/shm` directory, removed after the import.

Tests: on macOS `go vet` (darwin, linux, windows), `go test -race ./...` and `go build` passed for both modules; the helper's Linux tests ran in `egresslab` (no `-race`: no cgo in the VM), the proxy tests five times in a row. New: `TestProxyStreamsShareWindows` (two streams across several windows; the last one ends them), `TestProxyStreamLimit` (a ninth stream refused before its capability is consumed, then accepted once one ended), `TestProxyStreamFirstRequestsJoin` (two first requests at once, the keeper's windows longer than the lock wait), `TestProxyStreamClosedByRelease` (three streams; the lab ends `sealed`, not faulted), the hanging dial among the refusals (it gives up before the window's deadline), `TestProxyPlaneQueue` and, in the controller, `TestServeEndpointConcurrentClients` (three CONNECTs reach the transport at once). The fake traffic window now fails, as the real gate does, when its run outlives the window or the window is cancelled. Each of the three fixes from the first review (windows on the helper's own context, the dial deadline, the plane recheck while waiting) was checked by reverting it: the matching test failed.

Real run:
- Phase 1 changes, re-run first: both listeners started at the same moment and both served (the earlier run had answered `RESERVATION_BUSY`); six concurrent rounds through both endpoints: 12 of 12 matched their own reserved address, always distinct, no listener error.
- Ten CONNECTs at once through A: 10 of 10 matched, in 4 s (eight served at once, the rest waited for a slot).
- A download through A limited to 150 KB/s for 45 s, while six batches of three new CONNECTs arrived on the same endpoint: 18 of 18 matched, and the download kept its rate (448 KiB per 3 s sample from its start to curl's 45 s limit, 6.98 MB); no new stream interrupted it.
- Releasing A while three downloads ran through it: released in 0.4 s with `generation_retired: true`, and the lab ended `sealed`, not faulted. The three downloads were cut (partial files); curl went on reading what was already buffered on the host (about 3.8 MB per stream in the ssh channel and the sockets) for another 22 s at its rate limit, though the tunnel was gone. B still matched; a new CONNECT on A was refused (`reservation is not held`).
- A new tunnel generation and hold for A on the same helper (the same address and epoch, a new reservation): the running listener refused it with `reservation is not held`, as the tests predicted; restarted with a new approval, it served the new reservation (4 of 4 matched), while B matched 4 of 4, and both together stayed distinct.
- Helper logs: 8 healthy checks on A and 11 on B, no fault, no dial error.
- After: both listeners stopped on SIGINT, every hold released, both labs deleted, `egresslab-lab-recover` found nothing in either instance, the helpers stopped and both stages revoked. Journal: 27138 to 32173 bytes.

Second review of commit `36f2e88`, fixed after the run above:
- A capability is consumed when the request arrives, not in the window, so a long wait for a window (a monitor check) cannot outlast its 30 s lifetime; nothing retries.
- A stream whose connection to helperctl is gone entirely ends even if the destination neither sends nor reads (the socket's hang-up, polled every 250 ms while the download runs); a half-close alone keeps the download. Before, such a stream kept its slot until the destination closed or 30 minutes passed.
- A cancelled plane admits and dials nothing more; every caller that closes the streams waits until their sockets are closed; a request waiting when a window fails reports that failure, not `AUTHORIZATION_DENIED`; the tests' timing overrides are copied into each keeper.
- New tests: `TestProxyStreamPeerHangup`, `TestProxyDialAfterPlaneEnded`, `TestProxyStreamWindowFailure`; reverting the hang-up watch, the dial check or the keeper's failure precedence made the matching test fail.
- Short run on runtime A with that build (helper `b2ca9d92…`): 10 of 10 concurrent CONNECTs matched in 9 s (the first monitor check ran in the middle of it); a 150 KB/s download kept 448 KiB per 3 s while three batches of three CONNECTs matched (9 of 9); after six downloads were killed mid-transfer, eight concurrent CONNECTs all matched (their slots were free); releasing A with two downloads running took 0.4 s, the generation was retired, the lab ended `sealed`, and a new CONNECT was refused (`reservation is not held`). The helper logged 4 healthy checks, no fault and no dial error.

Third review (of those fixes) and a review of the release path, fixed:
- A release waiting for the lock could lose it to a new CONNECT that started a new plane, whose first window outlasts the 5 s wait. Now new requests are refused with `LAB_BUSY` while a release waits, and the release cancels any plane on every poll. `TestProxyStreamRefusedWhileReleaseWaits` (a request during the wait answers at once, and the release gets the lock) answered after 5 s with the old code.
- A wall-clock rollback observed after a request arrived refuses it before its dial (`Verifier.ClockSafe`, tested in `helperauth`).
- The hang-up is watched from the start of the stream, so a client that leaves while its upload is stuck on a destination that no longer reads frees its slot (`TestProxyStreamHangupDuringUpload`, which fails with the watch started after the upload).
- A request waiting for a failed window waits for the keeper's reason until its own deadline, then answers `STATE_UNCERTAIN` (`TestProxyPlaneFailure`).
- Final run on runtime A with the final build (helper `6fe5b715…`, installed in both instances): 10 of 10 concurrent CONNECTs matched in 5 s (again with a monitor check in the middle). With three CONNECTs at a time arriving in a loop and two downloads running, the release took 0.4 s, retired the generation and left the lab `sealed`. The four rounds started earlier matched (12 of 12); the three requests already at the helper when the release came were refused (`LAB_BUSY`), and every later CONNECT was refused by the controller (`reservation is not held`, 168). The helper logged no fault and no dial error.
- Cleaned up the same way after each run (listener stopped, holds released, lab deleted, nothing for `egresslab-lab-recover`, helpers stopped, stage revoked); journal 35535 bytes. Codex did not review this last round; two earlier passes were cut off by the reviewer's content filter or by a commit during the review and were run again.

Limitations:
- Traffic still pauses at each monitor check (the next part of Step 35).
- A window admits new dials only in its first part (while 6 s of it are left), so a stream that arrives later waits for the next window, up to about 4 s (not measured separately).
- After a release, a client may still read data that was already buffered on the host; nothing new crosses the tunnel.
- The checks resolve names on the host: they prove the data plane, not DNS isolation.

Application networking as a whole remained disabled.

### Windows and WSL2 run (Step 35)

Environment:
- Host OS: Windows 11 Pro (10.0.26300), Go 1.26.2; commit `412aa23` with this run's controller fixes. WSL2 Ubuntu 22.04, Linux 6.6.87, nft 1.0.2.
- The helper, helperctl, `egresslab-proxy-dial`, the probe worker and `egresslab-lab-recover` were built from `412aa23` and installed in `/usr/local/bin` (helper `9b74d7d3…`). The controller CLI and the HTTP controller were built on Windows and reached the helper through `wsl.exe`.
- The reservation authority was the real one in `%APPDATA%\EgressLab` (DPAPI key), with the controller's `state.json` and `runtimes.json` next to it.
- One route: the multi-source helper with the proxy enabled, `profile_156714f52695b619`, and one endpoint on port 1080 created through the HTTP API.

Tests:
- On Windows, `go vet` (windows, linux, darwin) and `go test ./...` passed for both modules with Go 1.26.2 and 1.23.2: 478 controller and 1014 network-agent tests and subtests.
- The shared journal lock tests passed 20 times in a row: `TestReservationAuthorityReadersShare`, `TestReservationAuthorityBusy` and the subprocess lock tests.
- Windows has no C compiler here, so `-race` ran in WSL for both modules.
- New: `TestStateFilesReplaceWhileRead`. Four readers load both state files the way each CONNECT does, while the test creates and deletes endpoints and saves the runtimes. It runs 3 s in `%TEMP%` unpaced and 3 s under the user config directory at about 100 saves a second. It allows no failed save or read, and no read that sees an empty state.
  - Before the retries existed, it failed when the reader's delete sharing or the POSIX rename was reverted. With the retries, it no longer catches either.
  - It creates, and then removes, a temporary directory under `%APPDATA%`.
- New: `TestStateFileReplacedWhileOpen`. A reader holds its handle while a save replaces the file; the save must finish within 1 s, and the reader still reads the old content.
- New: `TestStateFileRetriesWhileHeld`. Another handle holds the file without sharing, as a scanner can; a read and a replace succeed once it closes. A file that really is missing is still reported as missing.
- New: `TestStateFileMissingBriefly`. The name appears 50 ms after a read starts, and the read returns the file; the test raises the missing-file budget so that it does not depend on scheduling.
- Mutation checks, one at a time, each caught by exactly one of the three deterministic tests:
  - the reader without delete sharing, and `os.Rename` instead of the POSIX rename: caught by `TestStateFileReplacedWhileOpen`;
  - no read retry, and no replace retry: caught by `TestStateFileRetriesWhileHeld`;
  - no missing-file retry: caught by `TestStateFileMissingBriefly`.
- The four state-file tests passed 20 times in a row.

Real run (the egress address is compared, never printed):
- `wsl.exe` as a stream transport: random binary data went through unchanged, and closing stdin reached the guest as EOF. Unlike `limactl`, killing `wsl.exe` ended the guest process.
- The helper started with the multi-source probe and the proxy, and committed its epoch witness.
- `probe-egress-multi` succeeded at the first attempt (3.4 s); it was the first probe of the session.
- `reserve-egress` held and prepared the address in 4.2 s. The monitor reported healthy throughout: 98 checks, all for this hold. The helper log had no fault or error line.
- The traffic gate (`ct mark`, `meta skuid`) worked on nft 1.0.2. Through `serve-socks` on `127.0.0.1:1080`, requests to `https://api.ipify.org` returned the reserved address: 6 of 6, then 2 of 2.
- Refused as expected: a wrong password (authentication); `1.1.1.1` and TCP port 53 (reply 2); a domain name (reply 8).
- `serve-endpoint` served the same reservation for the API-created endpoint. The first request took 12 s, later ones about 1.3 s.
- API churn: a CONNECT loop ran through `serve-endpoint` while the HTTP API created and deleted endpoints as fast as it answered.
  - With the `412aa23` builds: 9 saves failed (`Access is denied` on the rename), and 3 CONNECTs were refused because `state.json` was being used by another process.
  - With delete-sharing reads and the POSIX rename: no CONNECT failed, but saves under `%APPDATA%` still failed now and then.
  - With the final build: in 60 s, 14414 saves with none failed, and 21 of 21 CONNECTs matched.
- `-approve release-egress` with the helper up: released in 0.5 s with `generation_retired: true`. The list was empty and the monitor stopped.
- After:
  - The endpoint was deleted through the API. `state.json` was identical to before the run; `runtimes.json` differed only in the binding's `updated_at`.
  - `disconnect` (`sealed`), then `delete-lab`; `egresslab-lab-recover` found nothing.
  - No namespace, underlay table, probe or proxy process was left, and the helper stopped.
  - Journal: 1772 bytes (one hold and its release).

Found and fixed during the run:
- State files on Windows (the pending check from the Codex review):
  - Go's `os.ReadFile` opens a file without delete sharing, and `os.Rename` (`MoveFileEx`) refuses to replace a file that another process has open. A save during a CONNECT's read therefore failed with `Access is denied`, and a CONNECT during a save failed with a sharing violation.
  - In a standalone reproduction with four readers, about 90% of saves failed; at a realistic rate, a few did. Delete sharing on the read side alone was not enough.
  - Fix: readers now open with delete sharing. Saves rename through `SetFileInformationByHandle(FileRenameInfoEx)` with `POSIX_SEMANTICS`, which replaces the name even while readers hold the old file. Where that is unsupported, saves fall back to `os.Rename`.
- Under `%APPDATA%`, where the real files live, a filesystem filter still refused some renames:
  - When saves with new content came at about 250 to 300 a second, `SetFileInformationByHandle` answered `Access is denied`, sometimes for several seconds.
  - Both files could still be opened for delete. The Restart Manager named no process holding either, except once `System` (PID 4) on the target. The likely filter is Defender, which runs behavior monitoring.
  - It did not happen in `%TEMP%`, with unchanged content, or at about 130 saves a second or fewer.
  - A read during a replace sometimes found no file at all, which `NewStore` and `LoadRuntimeState` would have taken for an empty state.
  - Fix: a save retries such a refusal for up to 5 s. A read retries a sharing violation or a refusal for 250 ms, and a missing file for 25 ms.
- A destination refused by policy was logged as `destination not allowed` followed by `invalid reservation release evidence`. It now has its own error (`ErrProxyDestinationNotAllowed`) and logs one line.

Limitations:
- The retries bound the filter's refusals; they do not remove them. At the unpaced rate, refusals longer than 5 s were observed: two consecutive saves each refused for their whole 3 s retry loop. A refusal that long still fails the save; the API answers an error and keeps the previous definition.
- `-race` has not run on the Windows-only code (no C compiler on that machine).
- The checks resolve names on the host: they prove the data plane, not DNS isolation.
- Native Linux has not run the proxy or the endpoints.

Application networking as a whole remained disabled.

### Monitor overlay and isolated DNS on Windows and WSL2 (Step 35)

Environment:
- Host and runtime:
  - Windows 11 Pro, Go 1.26.2; commit `f66b4d5` with this step's changes.
  - WSL2 Ubuntu 22.04, Linux 6.6.87, nft 1.0.2.
- Helper binaries:
  - The helper, helperctl, the workers and `egresslab-lab-recover` were built from the working tree and installed in `/usr/local/bin`.
  - The `412aa23` builds are backed up in `/root/egresslab-bin-backup-412aa23`.
  - Runs 1 and 2 used helper `2d07fa63…`. Run 3 used helper `db96d0b3…`, which adds the check timing and the overlay's opening budget.
- The controller CLI was built on Windows. Build `87a19874…` was used from the second half of run 2 on; it has the resolver fixes.
- The reservation authority was the real one in `%APPDATA%\EgressLab`.
- One route: `profile_156714f52695b619`, with an endpoint on port 1080 created through the HTTP API.

Kernel check in throwaway namespaces (nft 1.0.2, root, both namespaces created and deleted by the check):
- The lab side was a veth named `wg0`; an echo server ran in a second namespace.
- With the seal and the gate open, a client of UID 998 got its echoes.
- With the gate closed (3.2 to 5.25 s), nothing came back.
- When the overlay and a probe window opened in one transaction, the marked connection resumed at once. It ran until the overlay's element expired 10 s later.
- During the overlay, new connections of UID 998 and of UID 999 timed out.
- The readbacks (open, overlay expired, closed) are now `testdata/nft-lab-monitor-overlay-*.json`.

Tests:
- New in the agent and helper:
  - `TestMonitorOverlayRules`.
  - `TestMonitorOverlayRealCapture`: the real captures.
  - `TestMonitorOverlayRejectsDrift`: wrong UID, a marking output permit, wrong order, a foreign set, a gate permit beside the overlay, and other drift.
  - `TestMonitorOverlayEligible`.
  - `TestMonitoredProbeWindow`: the composite script, the close by handle, ineligible overlays, the opening deadline, an expired probe window, a foreign UID, an unconfirmed close.
  - `TestManagedMultiProbeWithOverlay`: an overlay in every window, none after the streams end, a changed address stopping at the first source.
  - `TestEgressMonitorTrafficOverlay`: offered only for running streams of the monitored reservation, with the keeper's UID and the old health.
  - `TestEgressMonitorDriftClosesStreams` and `TestEgressMonitorDueWhenWindowsEnd`.
  - `TestTunnelBackendOffersMonitorOverlay`.
- Changed: two sticky-IP tests now expect one window fewer and `ErrManagedStickyIPChanged`.
- New in the controller:
  - `TestIsolatedResolver`: answers, aliases, private and reserved addresses, loops, status and size limits, redirects, certificates, invalid names.
  - `TestIsolatedResolverBuiltInRoots`, `TestIsolatedResolverWaitsForStreamExit`, `TestIsolatedResolverStalledHandshake`, `TestIsolatedResolverStreamEndsDuringQuery`.
  - `TestIsolatedResolversKeepTheirRoutes`: two routes resolving at once, each through its own streams. This is the only coverage of two runtimes here.
  - `TestConnectByDomainName` and `TestDomainRefusals`.
- Mutation checks: each of 15 safety mutations, applied one at a time, failed a test. Among them: an overlay that marks, ignoring liveness or health, no sealed check after the strips, a strip taking any set, no opening deadline, no early stop on a changed address, an overlay without streams or for another reservation, the interval-only check timing, a resolver that keeps its stream, follows redirects or accepts private answers, and DNS ports allowed by name.
- On the final code:
  - on Windows, `go vet` (windows, linux, darwin) and `go test ./...` passed with Go 1.26.2 and 1.23.2: 538 controller and 1058 network-agent tests and subtests;
  - `-race` in WSL passed for both modules. It had caught one data race in a new test (a relay left running past its test), which is fixed.

Real run: three holds, each released. Addresses are compared, never printed.
- Run 1 was faulted by my own capture.
  - `tcpdump` ran inside the lab namespace, and the monitor's process inventory refused it ("lab namespace is busy").
  - The tunnel was removed, and the hold released with `generation_retired: true`.
  - No process may run in a lab namespace. The later captures used `sniff.py`, which opens a packet socket in the namespace and moves its process back to the root namespace. A plain `tcpdump` watched ports 53 and 853 in the root namespace.
- Run 2 (helper `2d07fa63…`):
  - Names resolved by the proxy (curl `socks5h`) all came out at the reserved address:
    - `api4.ipify.org` 3 of 3 and `ipv4.icanhazip.com` 3 of 3, then 8 of 8 concurrent, with no `LAB_BUSY`;
    - after the resolver fixes, `api4.ipify.org` 3 of 3, `ifconfig.co` 3 of 3, and 8 of 8 concurrent.
  - The Windows DNS cache held none of these names, before or after.
  - Captures over the whole run:
    - root namespace: 0 packets on ports 53 or 853;
    - lab namespace: 24579 packets, all on `wg0`, with 0 IPv6 and 0 on ports 53 or 853;
    - 511 packets with `8.8.8.8:443`, of which 33 SYNs, one per proxied name lookup.
  - One kept-alive connection, 300 small requests at 3 a second for 4 minutes:
    - all 300 matched; median 0.64 s, p95 1.87 s, maximum 18.0 s; 31 requests took over 1 s;
    - the long ones began about 7 s before each check. The keeper stops opening windows 14 s before the renewal deadline, but the check came only at the routine interval, about 8 s later. TCP's backoff stretched that gap to 8 to 18 s. During the probes themselves, the overlay carried the connection.
  - A 130 s download at 150 KB/s averaged 118 KiB/s, with stalls of 22 s and 5 s. The transport's buffers hide shorter pauses in this measure.
  - Release during three downloads:
    - released in 0.7 s with `generation_retired: true`; the lab ended `sealed`;
    - the downloads drained about 0.8 MB already buffered, then ended (curl 56);
    - a new name lookup was refused (`reservation is not held`).
- Run 3 (helper `db96d0b3…`, with the check due when the windows end):
  - On one connection, 300 requests all matched: median 0.32 s, p95 0.85 s, maximum 2.8 s; 7 took over 1 s.
  - Checks came about every 17 s.
  - A 130 s download at 150 KB/s averaged 151 KiB/s, with no stall of a second or more across eight checks.
- After:
  - The endpoint was deleted, and `state.json` was identical to before.
  - The `runtimes.json` binding names the last lab's namespace and helper epoch, as `connect-tunnel` leaves it.
  - `disconnect` and `delete-lab` ran, and `egresslab-lab-recover` found nothing.
  - The helper stopped, with no namespace or table left.
  - Journal: 1772 to 6815 bytes (three holds, three releases).
  - Helper log: 60 healthy checks; the only fault was run 1's.

Found and fixed during the step:
- From Codex's review:
  - The resolver used the platform TLS verifier, which may fetch certificates over the host's network. It now uses built-in roots.
  - The DNS stream's slot was still busy when the CONNECT followed. The resolver now waits for the runtime process to exit.
  - An overlay left with milliseconds to open could fault the generation. Eligibility now requires a 2 s opening budget.
  - A dial could race the HTTP client's cancellation. The stream is now opened before the client starts.
  - A failed lookup could miss its reply near the deadline, and an empty name got none. Both are fixed.
  - Reserved answers (CGNAT and others) were taken before a public one. They are now skipped.
  - The alias walk stopped one alias short, and let an early address bypass a bad alias. Both are fixed.
  - Two tests could pass vacuously. Both are fixed.
- From the real run: the gate gap before each check. While streams run, the check is now due as soon as no window may open.
- From Codex's second review, after the real run (unit tests and mutation checks only; no real run used these builds):
  - A check slower than about 16 s would have run again at once, and so on back to back. A check that ended past the windows' end now keeps the routine schedule.
  - No check now starts while an authorized release waits for the lock.
  - An answer listing a probe source (such as `1.1.1.1`) before an allowed address failed the CONNECT. The resolver now skips answers the mint would refuse.
  - A name with an alias also passed with a malformed or IPv6 address record, or with the same CNAME twice. It is now refused.
  - The resolver waited for the stream's process even after a failure. It now waits only after an answer, and only while its caller's context lasts. `serve-socks` passes the listener's context, so a client that leaves does not shorten the wait.
  - Codex's third look found that a release could start waiting between the monitor's check of it and the lock. The monitor now checks again once it holds the lock.
  - Three tests were added:
    - `TestDoHRootsVerifyServedChain`, which checks the chain dns.google served on 2026-11-26, recorded in `testdata`;
    - a dial that completes only after cancellation;
    - a failure reply after the original handshake deadline.
  - Each of these eight fixes, reverted one at a time, failed a test.
- A direct check of the final resolver against the real service resolved `example.com` and `www.github.com`, and `one.one.one.one` to `1.0.0.1` (skipping `1.1.1.1`).

Limitations:
- Short pauses remain:
  - between the last window and the overlay (up to about a second and the check's setup);
  - between the two sources' windows;
  - when a probe outlives the overlay's 10 s element.
- The helper releases a DNS stream's slot asynchronously.
- After a check slower than about 16 s, no window opens until the next check, as before Step 35, so new streams wait.
- A release that arrives during a check still waits for it, up to 5 s.
- The resolver is pinned to Google Trust Services' roots R1, R3 and R4; another CA fails closed.
- Google Public DNS sees the queried names, coming from the VPN's address.
- One runtime only on Windows; two runtimes resolving at once were covered by a unit test here, and ran later on two Lima runtimes (see "Release binaries on macOS and two Lima runtimes (Step 36)"). Native Linux has not run it.
- The captures show no traffic on DNS ports and no host lookup of the tested names. They do not exclude every conceivable leak.

Application networking as a whole remained disabled.

### Release build and release binaries on Windows and WSL2 (Step 36)

Release packages are built by `scripts/build-release.sh VERSION`, and officially by the manual GitHub Actions workflow "Release Build" (`.github/workflows/release.yml`, from `main` only). The workflow tests both modules, builds, verifies `SHA256SUMS` and uploads the archives as an artifact; it publishes no GitHub Release.

How the script works:
- It refuses a version that is not `vMAJOR.MINOR.PATCH[-PRERELEASE]`, a checkout with changes or untracked files, an existing `dist/VERSION`, and a missing tool (`git`, `go`, `tar`, `zip`, `sha256sum` or `shasum`, checked before anything is built).
- It builds with `CGO_ENABLED=0`, `-trimpath` and `-buildvcs=true`. The macOS Keychain store uses `/usr/bin/security`, not cgo, so the cross builds keep it.
- Archive hygiene:
  - tar headers carry uid and gid 0 and explicit modes (binaries 0755, the rest 0644), never the builder's user or a checkout's or Windows mount's modes; zip leaves out uid and gid (`-X`);
  - inherited `TAR_OPTIONS`, `ZIPOPT`, `ZIP` and `GZIP` are cleared, and macOS metadata files are suppressed;
  - every archive is checked against its exact member list, directories included, and for tarballs executable binaries and numeric owner 0, before anything is hashed.
- The output directory is reserved atomically, a symbolic link for `dist` is refused, and a failed build removes its partial output.
- The resolver's three trust roots are embedded by name, so an untracked file in their folder cannot end up in the binary.
- Output:
  - six controller archives (`egresslab-controller` and `egresslab-controller-lab` for Windows, macOS and Linux, amd64 and arm64; zip for Windows, tar.gz otherwise);
  - two Linux runtime archives (the agent, helper, helperctl, probe and proxy-dial workers, and `egresslab-lab-recover`);
  - `SHA256SUMS`.
- Every archive also holds `RELEASE-INFO.txt` (version, commit, role, OS, architecture), `LICENSE`, `README.md` and the three guides in `docs/`.
- `dist/` is ignored by git.

Trial build on 2026-11-26:
- Where and with what:
  - in WSL (Go 1.27.4, Info-ZIP 3.0), from a throwaway clone of `94ff972` with this step's files committed in the clone only;
  - the official build uses the Go that `go.mod` names.
- Refusals checked: an invalid version, an untracked file, and a second run into the same output.
- The build:
  - 24 binaries and 8 archives in 102 s; `sha256sum -c` passed, and so did the PowerShell check under "Installing a release" on Windows;
  - every binary has the right format and architecture (PE32+ x86-64 and Aarch64, Mach-O x86_64 and arm64, ELF x86-64 and aarch64);
  - the Unix binaries are executable;
  - the checkout was still clean afterwards.
- No archive holds a private key, a WireGuard config, a state file, a journal, a key file or a path from the build machine.
- The docs named two real VPN egress addresses from the Lima runs. Since this step they are "egress A" and "egress B".

Release binaries on Windows and WSL2 (the controller from `egresslab-controller-windows-amd64.zip`, the runtime from `egresslab-runtime-linux-amd64.tar.gz`):
- Setup:
  - The runtime archive's checksum was verified, and its six binaries were installed in `/usr/local/bin`, with no helper running and no hold.
  - The existing signing key, vault, trust record and reservation authority were kept; nothing was provisioned again.
  - `list-reservations` read the real authority; `runtime-status` reported the release helper reachable and authorized, and `helper-info` showed the trusted runtime ID.
- Lifecycle, with the user's approval for one hold:
  - `create-lab` and `connect-tunnel`; `probe-egress-multi` passed at the first attempt (3.0 s).
  - `reserve-egress` prepared the hold in 3.6 s.
  - An endpoint was created through the release HTTP controller (still `draft`), and the release `serve-endpoint` served it.
- Hostname requests (`socks5h`) all came out at the reserved address:
  - `api4.ipify.org` 3 of 3 and `ifconfig.co` 3 of 3;
  - `api4.ipify.org` 8 of 8 concurrent;
  - the Windows DNS cache held neither name, before or after.
- Kill switch, with a 50 KB/s download running, after the lab's `wg0` was taken down as root:
  - the lab had no route left;
  - three requests during the outage were all refused, and none was answered by any other path;
  - the lab was `faulted` 2 s later, when the keeper's next window found the tunnel changed;
  - the download ended (curl 56) after the data already buffered on the host;
  - a new request was refused, and the hold stayed in the journal.
- After the fault:
  - `release-egress` released the hold in 0.3 s with `generation_retired: true`;
  - the endpoint was deleted, and `state.json` and `runtimes.json` were unchanged;
  - `delete-lab` removed the faulted lab, and `egresslab-lab-recover` found nothing;
  - the helper stopped, leaving no namespace or table.
  - Journal: 6815 to 8497 bytes.

Official artifact (GitHub Actions "Release Build", `727fc84`), checked on 2026-11-26:
- Provenance and content:
  - all 8 checksums verified on Windows;
  - every binary embeds Go 1.23.12, `vcs.revision=727fc84…`, `vcs.modified=false`, `-trimpath` and `CGO_ENABLED=0`;
  - every archive has its exact members; tarballs carry owner `0/0`, binaries 0755 and the rest 0644, and the zips have no uid or gid;
  - no key, config, state file, build-machine path or real egress address.
- Lifecycle with the official Windows controller and Linux runtime (one more hold, with the user's approval):
  - `probe-egress-multi` passed at the first attempt (3.1 s), and `reserve-egress` prepared the hold in 3.5 s.
  - Hostname requests all came out at the reserved address: `api4.ipify.org` 3 of 3, `ifconfig.co` 3 of 3, and 8 of 8 concurrent. The Windows DNS cache held neither name.
  - Kill switch, with `wg0` taken down:
    - three requests during the outage were all refused, and none was answered by another path;
    - the lab was `faulted` 5 s later, and the hold stayed;
    - the download started for this check had received nothing yet: its first window was still pending.
  - `release-egress` released the hold in 0.3 s with `generation_retired: true`. `state.json` and `runtimes.json` were unchanged, `delete-lab` and `egresslab-lab-recover` left nothing, and the helper stopped.
  - Journal: 8497 to 10180 bytes.

Limitations:
- The lifecycle above, with a download cut mid-stream, ran on the first trial build. The script was hardened after Codex's review: archive modes and owners, member checks, the trust roots embedded by name. Its later trial builds, through GNU tar and through BSD tar (libarchive, as on macOS), passed their checks and checksums, and their Windows controller started, but the lifecycle was not repeated.
- macOS with two Lima runtimes ran later, with a local build of the release commit; see the next section. Native Linux has not run end to end.
- A fault found by the keeper's traffic window was not written to the helper log, unlike a monitor fault; the controller saw `LAB_FAULTED`. Since 2026-11-27 it is logged as `Traffic window fault`.
- `recover-egress` (after a guest reboot) was not repeated with release binaries.

### Release binaries on macOS and two Lima runtimes (Step 36)

Environment:
- Host: macOS 15.3.2 (arm64). The tests ran with Go 1.25.1 at `9aa3c37`, whose code is that of `727fc84`; only this guide changed in between.
- Runtimes: `egresslab` and `egresslab-b`, Lima (vz, aarch64), Ubuntu 24.04.5, Linux 6.8, nft 1.0.9.
- Routes:
  - A on `egresslab`: the first config, `profile_98e0aaeb5ef3564c`, endpoint on port 1080;
  - B on `egresslab-b`: the second config, `profile_3b12e9450758a345`, endpoint on port 1081.
- One reservation authority: the Mac's real one, with its Keychain key.

Tests:
- On macOS, `go vet` (darwin, linux, windows), `go build` and `go test -race ./...` passed for both modules: 220 controller and 467 network-agent top-level tests.
- The test binaries of all 12 packages that have tests, cross-built for linux/arm64, passed in `egresslab`, the overlay tests among them. There was no `-race` in the VM, since it has no cgo.

Kernel check of the monitor overlay on nft 1.0.9. The readback fixtures were captured on nft 1.0.2, so the check was repeated in throwaway namespaces, which it created and deleted:
- The lab side was a veth named `wg0`, sealed with `sealLabRules`. The rules were the agent's own: `managedTrafficRules(998)`, then `managedMonitorTrafficRules(998)` with the probe window for `1.1.1.1`.
- With the gate open, UID 998's connection got its echoes and its new connections succeeded. UID 999's never did.
- With the gate closed (4.0 to 8.1 s), the marked connection got nothing.
- The overlay and the probe window opened in one transaction:
  - the marked connection resumed at its next test, under a second later;
  - it ran until the overlay's element expired, 10 s later;
  - new connections of UID 998 and of UID 999 timed out throughout.
- The helper's parser (`verifyMonitorOverlay`, `verifySealedPolicy`) treated the nft 1.0.9 readbacks as it treats the WSL2 captures:
  - the open pair was accepted, with its handles;
  - the expired overlay was refused as active, accepted after the probe, and could be closed by the same handles;
  - the closed ruleset was sealed;
  - another UID, a plain probe window and a gate reading were refused.
- These captures were not added to `testdata`.

Release build on macOS:
- Built from a clean clone of `727fc84` with `scripts/build-release.sh v0.3.0-alpha.1`:
  - `GOTOOLCHAIN=go1.23.12`, the Go of the official build;
  - BSD tar (bsdtar 3.5.3, libarchive) and Info-ZIP 3.0.
- 8 archives and 24 binaries in 45 s; the clone stayed clean.
- `shasum -a 256 -c SHA256SUMS` passed. Every tar entry has owner `0/0` and mode 0755 (binaries) or 0644. The zips carry no uid or gid.
- Every binary embeds Go 1.23.12, `vcs.revision=727fc84…`, `vcs.modified=false`, `-trimpath` and `CGO_ENABLED=0`. Formats are as expected: Mach-O, ELF and PE32+, for both architectures.
- The macOS arm64 binaries are ad-hoc signed by the Go linker (`adhoc,linker-signed`), as Apple Silicon requires. The amd64 ones are unsigned, and none is notarized.
- No archive holds a private key, a WireGuard config, a state file, a build-machine path or an egress address.
- The official artifact was not downloaded (no `gh` on this Mac), so no checksums were compared with it.

Installation:
- Runtime: installed with no hold and both helpers stopped.
  - The arm64 runtime archive was verified with `sha256sum -c --ignore-missing`. It was installed in both instances with the subshell under "Installing a release", with only the archive name changed to arm64; `uname -m` is `aarch64`.
  - The six installed binaries match the archive (root, 0755). The previous builds are kept in `/root/egresslab-bin-backup-412aa23`.
- Controller: the macOS arm64 controller ran from its extracted folder with the existing Keychain key and authority. Nothing was provisioned again. `list-reservations`, `runtime-status` and `helper-info` worked for both runtimes.

The ident.me pin:
- The first probe on each runtime faulted its lab with `source ident_me: … HTTPS_REQUEST_FAILED`. `4.ident.me` had moved:
  - the pinned address no longer answered;
  - DNS gave one other address, the same on the host and in both instances: AS24940 (Hetzner, not Cloudflare). It answered pinned HTTPS with a valid certificate.
- The new address was installed:
  - Both faulted labs were deleted (no hold existed), and the helpers were stopped.
  - The new address was installed in both instances with the subshell under "Multi-source helper (Step 29C.4b)". The old pin is kept in `/root/multi-probe-pin.before-2026-11-27`.
  - With the new pin, every probe of the run passed at the first attempt.
- ident.me itself was unreliable that day:
  - of 30 pinned requests from each instance's own network, 6 and 9 failed (no connection within 5 s, or no answer within 10 s), and several more took 3 s or longer;
  - the same check against `1.1.1.1` answered in 0.1 s.
  - Any such failure during a monitor check faulted the lab, with no retry. Three of the five holds below ended that way. Since then, a source that gives no answer only renews nothing; see "A source without an answer (Step 36)".

Real run: five holds in three rounds, each released. Addresses are compared, never printed.

Round 1, both routes:
- `probe-egress-multi` took 3.3 s and 5.3 s, and `reserve-egress` 5.5 s and 6.0 s. The two addresses differed.
- The two endpoints were already in the controller state from the Step 35 runs. The release `serve-endpoint` served them.
- Names resolved by the proxy (`socks5h`) all matched their own route:
  - `api4.ipify.org` 3 of 3 and `ifconfig.co` 3 of 3 on each route;
  - then 8 concurrent requests on each route at once: 16 of 16 in 4.5 s;
  - an IPv4 CONNECT matched on both routes.
- An idle route's new request waits for the next monitor check when no window can open before it:
  - the first request on each route took 14 to 15 s, and a later one 17 to 18 s;
  - each of these four ended 1 to 2 s after its route's next healthy check;
  - the others took 1.5 to 3.4 s.
- One kept-alive connection on A, 300 small requests at 3 a second:
  - 300 of 300 matched; median 0.29 s, p95 0.76 s, maximum 1.85 s; 3 took over 1 s;
  - six checks ran during the series, 16 to 23 s apart.
- The same series on B:
  - The first attempt was refused with `LAB_BUSY` at its DNS stream. It was the first stream of a new plane, and a check on B ended about when it was refused, so the check likely held the lifecycle lock longer than the 5 s wait.
  - The second attempt matched 121 of 121 until the monitor faulted B (ident.me). The stream was closed, and the 179 later lookups were refused (`AUTHORIZATION_DENIED`).
  - A's series went on matching. A was faulted the same way 56 s later, after its series ended.
- Both faulted holds were released in 0.3 s each, with `generation_retired: true`. The listeners then refused new requests (`reservation is not held`).

Round 2, a kill switch on B while A's kept-alive series ran:
- 25 s into a 50 KB/s download through B, B's `wg0` was taken down as root (`ip -n NAMESPACE link set wg0 down`). The monitor faulted B 10 s later (`cloudflare_trace … HTTPS_REQUEST_FAILED`).
- After the fault, with `wg0` still down, three name requests and one IPv4 request through B were refused (reply 1), and none was answered by another path. The hold stayed. Requests between the cut and the fault were not tested.
- The download went on delivering data buffered on the host before the cut: about 4.3 MB, at its rate limit, for 83 s. Then it ended (curl 18).
- A's series matched 300 of 300: median 0.29 s, p95 0.76 s, maximum 1.53 s; 4 took over 1 s; six checks ran during it.
- `list-labs` answered `LAB_BUSY: lab registry unavailable` while streams ran on that runtime. It answered once they ended. This is fixed after the release (see "Found and fixed after the run" below); `727fc84` predates the fix.
- The release of A planned for this round found A already faulted, by ident.me 2 s before:
  - its three downloads and new requests had started while A was idle, were still waiting for a window, and were refused at the fault.
  - Both holds were released in 0.3 s with `generation_retired: true`. A's lab stayed `faulted`.

Round 3, a release during downloads on A, with a fresh hold:
- Three 150 KB/s downloads were receiving 4 s after `serve-endpoint` started, and a name request matched.
- `release-egress`, 11 s later, took 4.7 s. The monitor's healthy check was logged in the second the release returned: the release waited for that check.
  - It retired the generation, and the lab ended `sealed`, not faulted.
  - A new request was refused (reply 2).
- The downloads drained the data already buffered on the host, 2.5 to 2.9 MB each over about 20 s, then ended.

DNS captures, as on Windows: `sniff.py` with its packet socket in the lab namespace and its process back in the root namespace, and `tcpdump` on ports 53 and 853 in each instance's root namespace.
- Lab namespaces, rounds 1 and 2:
  - 0 IPv6 packets and 0 on ports 53 or 853;
  - one SYN to `8.8.8.8:443` per proxied name lookup: 15 on each route in round 1, 1 each in round 2.
- Root namespaces, over the whole run: 60 packets in each. The queries among them were 28 for the instance's own host name and 2 for `4.ident.me`, made by hand for the pin. None was for a tested name or for `dns.google`.

After:
- Every hold was released. Journal: 35535 to 43897 bytes (five holds, five releases).
- No lab, namespace or EgressLab table was left, and `egresslab-lab-recover` found nothing in either instance. Both helpers stopped, and both stages were revoked.
- `state.json` and `reservation-authority.json` were unchanged. In `runtimes.json`, only the two profiles' bindings changed (`updated_at`, the last lab), as `connect-tunnel` leaves them; the runtimes' trust records were unchanged.

Found and fixed after the run (`list-labs` while streams run):
- Cause: `ListLabs` took the lifecycle lock with `TryLock`, and since the second part of Step 35 the streams' keeper holds that lock through its chained windows almost all the time.
- A first fix read the registry without the lifecycle lock. Codex's review found that it let callers see an operation that had not settled:
  - a lab being created was not listed yet, so `unbind-profile` could remove the binding of a lab about to exist;
  - `disconnect` published `sealed` before verifying it;
  - a probe's temporary `faulted` turned a concurrent precheck into `LAB_FAULTED`.
- The fix: the registry has its own lock, and `ListLabs` reads it either with the lifecycle lock free or while that lock is held by a holder marked settled. Only the streams' traffic windows and the monitor's check are marked settled, since they change a lab only to fault it. Any other operation still makes `ListLabs` answer `LAB_BUSY`, as before.
- Tests:
  - `TestLabRegistrySnapshot` (macOS `-race`): no unsettled state is seen across 50 creates and deletes; busy during another operation; answers during a settled hold, also while that holder faults the lab; unavailable after `Close`.
  - `TestEgressMonitorHealthy` lists during a check.
  - `TestListLabsLifecycle` lists during a settled hold over the socket.
  - `TestProxyStreamsShareWindows` lists from inside each window while two streams cross windows. Codex's second review found that the first version, which polled every 100 ms, could fail on a lock handoff; it now runs 20 times in a row without a failure.
- Mutation checks: each of these failed a test:
  - the old `TryLock`;
  - reading without regard to the settled mark;
  - no mark in the traffic window, or in the monitor;
  - an unlocked registry write (caught as a data race).
- On Lima, route A, with a helper built from the working tree (the release helper was reinstalled afterwards):
  - during `probe-egress-multi`, `list-labs` answered `LAB_BUSY` 10 times and `tunnel_configured` twice, and never `faulted`;
  - during a 150 KB/s download, 50 of 50 calls, a second apart across three monitor checks, answered `tunnel_configured`, with no fault;
  - the release took 0.43 s, and the lab ended `sealed`.
  - Journal: 43897 to 47247 bytes, from two more holds and releases (one of them for the first fix).
- A call that lands just as the keeper takes or gives back the lock, or while a new stream's first request holds it, still answers `LAB_BUSY`.

Limitations:
- The release was built locally, from the release commit with the official Go version. The official GitHub artifact was not run on macOS.
- The host's own DNS traffic was not captured, since packet capture on macOS needs root, which this run did not have. The isolated resolver sends nothing to the host's resolver by design (Step 35), and the instances' captures saw none of the names.
- ident.me's unreliability faulted three of the five holds: in `727fc84`, any source failure during a check faults the generation. Changed after this run; see "A source without an answer (Step 36)".
- An idle route's first request may wait up to a monitor interval for a window. If it arrives during a check longer than 5 s, it is likely refused with `LAB_BUSY` (seen once).
- In `727fc84`, `list-labs` answered `LAB_BUSY` while a runtime had streams (seen on B); fixed after the run.
- A release that arrives during a check waits for it (4.7 s here).
- Gatekeeper with a browser-downloaded (quarantined) archive was not tried.
- Native Linux has not run end to end.

Application networking as a whole remained disabled.

### Release v0.3.0-alpha.2 on macOS and two Lima runtimes (Step 36)

The official artifact of `063fe7f` (the `list-labs` fix above), built by GitHub Actions and downloaded by the user, checked on 2026-11-27.

Artifact:
- The zip holds the 8 archives and `SHA256SUMS`, and `shasum -a 256 -c SHA256SUMS` passed for all 8.
- Every tar entry has owner `0/0` and mode 0755 (binaries) or 0644, and the zips carry no uid or gid.
- All 24 binaries embed Go 1.23.12, `vcs.revision=063fe7f…`, `vcs.modified=false`, `-trimpath` and `CGO_ENABLED=0`.
- The macOS arm64 binaries are ad-hoc signed by the linker.
- No archive holds a key, a build-machine path or an egress address.
- Reproducible: a build on macOS from a clean clone of `063fe7f`, with `GOTOOLCHAIN=go1.23.12` and BSD tar, gave 24 of 24 binaries byte-identical to the official ones. The docs in the archives are those of the commit.
- Those docs lack the "Limitations:" heading of the macOS section and the start of its first item, removed by mistake in `063fe7f`; restored after the release.

Installation: the arm64 runtime went into both instances with the subshell under "Installing a release" (6 of 6 binaries match the archive, helper `67a41d07`). The alpha.2 macOS controller read the existing authority.

Real run: four holds, all ended by ident.me (in `063fe7f` any source failure faults).
- Both routes probed and held. B's first probe faulted its lab (ident.me) and passed on a new lab.
- All four holds were faulted by the monitor's ident.me check, from 9 s to 8.5 min after they were made.
- Name requests: through B, 8 of 8 concurrent ones matched. Through A, 1 of 8 matched; the other 7 got `LAB_BUSY` at their DNS stream, the first streams of a new plane arriving during a long check.
- Not run, because the holds faulted and my test script hung on the listeners: `list-labs` during streams with this binary (the same code ran on Lima in the previous section), a kept-alive series, a kill switch, and a release during downloads.
- The faulted holds were released in 0.24 to 0.34 s with `generation_retired: true`. Journal: 47247 to 53932 bytes.

### A source without an answer (Step 36)

On 2026-11-27, ident.me failed 3 of 20 pinned requests from each instance's own network. In `063fe7f` each monitor check (about every 20 s) faulted the lab on such a failure, so a route lasted one or two minutes. Since this change, only a source that answered wrongly faults; one that gives no answer renews nothing.

The change:
- The worker reports a source that gave no answer as its own line (`HTTPS_NO_ANSWER`), apart from one that answered and was refused (`HTTPS_REQUEST_FAILED`).
  - No answer: the source sent nothing at all, not a byte at any layer, and the attempt timed out or the connection was refused, reset or closed. Any byte that came back makes it an answer, cut off or not, and so does a server that completed TLS and then went silent.
  - A certificate, a host name, a TLS alert, a reply that is not TLS, a status, an encoding or a body is an answer.
- The agent leaves the tunnel in place only when all of these hold:
  - the error is nothing but the no-answer error;
  - the source's window closed as opened;
  - the worker is gone;
  - the tunnel verifies as staged;
  - the clock checks pass.

  It then returns `ErrManagedProbeSourceUnavailable`, with no evidence and no pin. Anything else on top of it faults as before.
- The monitor, on that result:
  - renews nothing, checks that the generation did not change, and checks again 2 s later;
  - opens no traffic window until a check succeeds, while the overlay keeps carrying established streams during the checks;
  - cuts the tunnel when the health expires, as before (60 s after the last source observation).
- `probe-egress-multi` answers `EVIDENCE_UNAVAILABLE` and leaves the lab configured; a new approval probes again.

Tests:
- `TestManagedProbeNoAnswer`, with real HTTPS servers in the test:
  - no answer: a server that never answers, a closed port, and a connection closed before TLS;
  - an answer: an untrusted certificate, another host name, a reply that is not TLS, and HTTP 503.
- `TestManagedMultiProbeNoAnswer`:
  - no answer from either source keeps the tunnel, its firewall and the next attempt;
  - no answer together with a cleanup failure, a drift, a worker left running, a cancellation or an expired window removes the tunnel.
- `TestManagedProbeWorkerError` and `TestProbeFailure`: the worker's line and its mapping.
- `TestAdaptProbeError`: only the agent's source without an answer reaches the helper as one.
- `TestEgressMonitorSourceNoAnswer`:
  - the health is unchanged, and the check waits for the recheck time;
  - no traffic window opens;
  - a later success renews the health;
  - an expired health faults.
- `TestEgressMonitorSourceNoAnswerGenerationChanged`.
- `TestGenerationProbeSourceNoAnswer`: the lab is restored, the capability is used, a new attempt succeeds, and a changed generation faults.
- On macOS, `go vet` (three systems) and `go test -race` passed for both modules, and the Linux tests passed in `egresslab`.
- Mutation checks: each of these 14 failed a test.
  - the soft path still faulting, or skipping the tunnel check or the idle check;
  - any joined cause counted;
  - every error counted as no answer;
  - no recheck spacing, the recheck gate ignored, or the health extended;
  - no generation check in the monitor or in the on-demand probe;
  - the lab not restored after an on-demand probe;
  - the runner's error untyped, the worker's single line, and the adapter passing the error through.
- A list of certificate errors that the first version excluded was removed: no test could tell it apart, since such errors are never timeouts or connection errors.
- Codex's review, both fixed after the Lima run below (unit tests and mutation checks only):
  - A source that sent a status line and then disconnected counted as no answer. Now only an error before the first byte of the response does (`httptrace`); the test adds that interrupted reply.
  - After a check without an answer, a recheck could wait for the routine interval once the last stream closed, while no window could open. Now the recheck is due at its time, streams or not (`TestEgressMonitorRecheckDueWithoutStreams`).
  - Reverting either fix failed its test.
- Codex's second review, both fixed:
  - The first fix looked only at HTTP data, so a short reply that was not TLS, then a close, still counted as no answer. Now the connection itself records whether the source sent any byte. The test adds that reply, and a server that completes TLS and then sends nothing (now an answer too).
  - The path without an answer skipped the attempt's clock check. It now runs it before keeping the tunnel, and a test steps the clock back 1.5 s during a source without an answer.
  - Reverting either fix, or not recording the bytes, failed a test.
- Codex's third review, both fixed:
  - The attempt's context could expire during the clock check and still keep the tunnel. The context is now checked last, and a test cancels it at that reading.
  - A check without an answer whose generation read ended after the health expired only scheduled a recheck. It now checks the health and the deadline again and faults, as a renewal does (`TestEgressMonitorSourceNoAnswerPastExpiry`).
  - Reverting either fix failed its test. Codex did not review this last round.
- These six fixes came after the Lima run below, which used the first classification. 40 pinned requests from each instance's own network then failed 3 times each, every time before TCP connected.
- Also passed with Go 1.23.12, the release workflow's version: `go vet` (three systems) and `go test` for both modules.

On Lima with the final build (helper `768b64ee`, worker `b2c8b317`; the alpha.2 helper and worker reinstalled afterwards):
- `probe-egress-multi` on A with WireGuard's UDP port dropped: after 11 s, the controller printed `EVIDENCE_UNAVAILABLE: no matching fresh verified egress evidence`, and the lab stayed `tunnel_configured`. Once the drop was removed, the same lab probed at the first attempt and was reserved.
- An 8-minute run on both routes, as below (kept-alive series on A, downloads on B, name requests and `list-labs` every 15 s):
  - no fault on either route;
  - checks: 26 healthy and 5 without an answer on A, 27 and 5 on B, each route twice two in a row; all 10 from ident.me;
  - 17 of 17 name requests matched on each route, and `list-labs` always answered `tunnel_configured`;
  - A's kept-alive requests: 1200 of 1200 matched; median 0.29 s, p95 0.77 s; 23 over 1 s.
  - One A request took 16.6 s. It started at the second check in a row without an answer, with 14 s of health left. That is too little for the overlay (it needs 14 s), so the established connection stopped until the next success, 8 s later, and TCP's backoff stretched the pause.
  - B: five of six downloads kept their rate (about 17 MB in 110 s). The sixth got `LAB_BUSY` at its first stream, which arrived during a 10 s check without an answer, longer than the 5 s a first stream waits.
- Holds released in 0.35 and 0.47 s with `generation_retired: true`, and cleaned up as before. Journal: 60620 to 63964 bytes.

On Lima, with this helper (`a0f00fda`) and worker (`c8c9442a`) and the rest of alpha.2 (the alpha.2 helper and worker were reinstalled afterwards).

An 11-minute run on both routes:
- Route A ran 300-request kept-alive series back to back, with name requests and `list-labs` every 15 s.
  - 31 healthy checks and 5 checks without an answer from ident.me, once two in a row (16 s of health left); no fault.
  - 1500 of 1500 requests matched: median 0.28 s, p95 0.77 s, maximum 8.2 s; 29 took over 1 s and one over 5 s. The slow ones coincide with checks without an answer, when no window opens.
  - 27 of 27 name requests matched, and `list-labs` answered `tunnel_configured` 27 times.
- Route B ran 150 KB/s downloads back to back.
  - 3 checks without an answer, two of them in a row, recovering with about 6 s of health left; the two downloads kept their rate (about 17 MB in 110 s each).
  - At 11:03:41 the monitor faulted B: `invalid egress observation: wall clock went backwards during the attempt`. This is the existing clock check, which fails closed on any backward step during an attempt, and is unrelated to this change. The journal of the instance shows no time adjustment.
- Every on-demand probe of the run passed at the first attempt, so the on-demand path without an answer ran only in tests.

Kill switch:
- Idle route A, `wg0` taken down: faulted 3.6 s later. The next check found `tunnel network configuration drifted: addresses` before any source was asked.
- Route B with a download running, `wg0` taken down: faulted 0.8 s later (the keeper's window), and a new request was refused.
- A silent VPN server on A: WireGuard's UDP port dropped in the instance's root namespace, with the tunnel itself intact.
  - Three checks without an answer followed (27, 14 and 1 s of health left).
  - The monitor faulted the lab with `monitor health expired` 58 s after the last success, 52 s after the drop.
  - A request during the silence was refused. The drop was removed afterwards.

After: every hold released in 0.27 to 0.38 s with `generation_retired: true`, no lab or table left, nothing for `egresslab-lab-recover`, helpers stopped, stages revoked, the alpha.2 runtime reinstalled in both instances (6 of 6 binaries match the archive). Journal: 53932 to 60620 bytes.

Limitations:
- A path that answers nothing is now cut when the health expires, up to 60 s after the last success, instead of at the first failed check (about 20 s). Nothing new crosses it meanwhile, since no window opens. Established streams may flow under the overlay until 14 s before the expiry. An address change is still caught by the first source that answers.
- A check without an answer takes 10 to 13 s (the worker's 10 s limit), so about three in a row reach the expiry. Two in a row were seen twice in 11 minutes, once on each route; three in a row ended a route once in the next run (see the next section).
- Long checks still hold the lifecycle lock: a first stream or a release arriving then may get `LAB_BUSY`, and checks without an answer (about 10 s each) make long checks more frequent; one download was refused that way in the final run.
- Near the end of a streak without answers, the overlay stops being eligible (it needs 14 s of health), so established streams can stall; one request took 16.6 s.
- The clock check faulted B once; on Lima it treats any backward step of the wall clock during an attempt as a failure.
- The released binaries (alpha.1, alpha.2) do not have this change; it needs a new release.

### Release v0.3.0-alpha.2 rebuilt from `9daebee` on macOS and two Lima runtimes (Step 36)

The user rebuilt the release from `9daebee` (this section's change) under the same version, v0.3.0-alpha.2. Two different artifacts now carry that name: the first from `063fe7f`, this one from `9daebee`. `RELEASE-INFO.txt` and the binaries' `vcs.revision` tell them apart, and checksums taken from the first no longer match. A new change should get a new version.

Artifact, checked on 2026-11-27:
- `shasum -a 256 -c SHA256SUMS` passed for all 8 archives. Owners and modes are as before, and no archive holds a key, a build-machine path or an egress address.
- All 24 binaries embed Go 1.23.12, `vcs.revision=9daebee…` and `vcs.modified=false`.
- A build on macOS from a clean clone of `9daebee` (Go 1.23.12, BSD tar) gave 24 of 24 binaries byte-identical to the official ones.
- The docs in the archives are those of `9daebee`; the "Limitations:" heading is back.
- The arm64 runtime went into both instances with the subshell under "Installing a release" (6 of 6 binaries match). The macOS controller read the existing authority.

Real run, with the release binaries only:
- `probe-egress-multi` on A with WireGuard's UDP port dropped: `EVIDENCE_UNAVAILABLE` after 11 s, and the lab stayed `tunnel_configured`. Once the drop was removed, the probe and the reservation passed at the first attempt; so did B's.
- A 9-minute run on both routes (kept-alive series on A, downloads on B, name requests and `list-labs` every 15 s):
  - B: 28 healthy checks and 6 without an answer from ident.me (once two in a row); no fault. Name requests 19 of 19 matched, `list-labs` always answered `tunnel_configured`, and five 110 s downloads kept their rate (about 17 MB each).
  - A: 23 healthy checks and 7 without an answer from ident.me. The last three came in a row at 13:28:43, 13:28:57 and 13:29:10, with 32, 17 and 4 s of health left.
  - The recheck after them ran into the health's expiry, and the lab was faulted at 13:29:14. The log reads `source cloudflare_trace: managed egress probe failed` with `context deadline exceeded`: the check's deadline is the health's expiry. This is the expiry cut, about 56 s after the last success.
  - Until then, on A: 1293 of 1294 kept-alive requests matched (median 0.29 s, p95 0.77 s, maximum 8.0 s), and 18 of 18 name requests matched.
- B with a download running, `wg0` taken down: faulted 2.5 s later, and a new request was refused.
- A new hold on A, released while three downloads ran: 0.74 s, `generation_retired: true`; the lab ended `sealed`, and a new request was refused.
- After: holds released, labs deleted, nothing for `egresslab-lab-recover`, helpers stopped, stages revoked. `state.json` and `reservation-authority.json` unchanged. Journal: 63964 to 68982 bytes. Both instances keep this runtime.

Limitations:
- Three checks in a row without an answer still end a route, since each takes 10 to 13 s and the health lasts 60 s. On that day ident.me's failures (all before TCP connected) came in bursts: three in a row once in 9 minutes on one route.
  - A shorter connection timeout for the probe source would fit more rechecks into the health. So would a second source outside Cloudflare.
  - Both are design decisions for later.
- The expiry cut during a recheck is logged as the probe's context deadline, not as `monitor health expired`.

### A shorter connection timeout for probe sources (Step 36)

The rebuilt alpha.2 run above lost a route after three checks in a row without an answer, each taking 10 to 13 s. Since this change, the worker gives a source 4 s to accept the TCP connection; TLS and the response keep their 10 s limit. A check whose source does not connect takes about 5 s, so about six fit into the 60 s health instead of about three.

Tests: `TestManagedProbeConnectTimeout`, which fails with the timeout back at 10 s. On macOS, `go vet` (three systems) and `go test` passed with Go 1.25.1 (`-race`) and Go 1.23.12; the agent's Linux tests passed in `egresslab`. Codex's review found nothing.

On Lima with the helper (`6119e7c2`) and worker (`3655e5c5`) built from the working tree; the rebuilt alpha.2 helper and worker were reinstalled afterwards.
- `probe-egress-multi` on A with WireGuard's UDP port dropped answered `EVIDENCE_UNAVAILABLE` after 4.7 s; the same probe took 11 s with the 10 s timeout. The lab stayed configured, and both routes then probed and reserved at the first attempt.
- A 9-minute run on both routes (kept-alive series on A, downloads on B, name requests and `list-labs` every 15 s):
  - no fault on either route;
  - A: 30 healthy checks and 6 without an answer; B: 29 and 4; all 10 from ident.me.
  - A single check without an answer was followed by a success 5 to 10 s later.
  - Once on A two came in a row, 14 s apart. That source had connected but not answered TLS, which still waits 10 s. The success followed with 16 s of health left.
  - A's kept-alive requests: 1500 of 1500 matched; median 0.28 s, p95 0.76 s, maximum 7.9 s; 31 took over 1 s.
  - 20 of 20 name requests matched on each route; `list-labs` always answered `tunnel_configured`; five 110 s downloads on B kept their rate.
- Holds released in 0.65 and 0.82 s with `generation_retired: true`, and cleaned up as before. Journal: 68982 to 72326 bytes.

Limitations:
- A source that connects and then stays silent still takes up to 10 s per check.
- The released binaries do not have this change; it needs a new release (a new version, such as v0.3.0-alpha.3).

### Release v0.3.0-alpha.3 on macOS and two Lima runtimes (Step 36)

The official artifact of `272917d` (the 4 s connect timeout), built by GitHub Actions and downloaded by the user, checked on 2026-11-27.

Artifact:
- `shasum -a 256 -c SHA256SUMS` passed for all 8 archives, and owners and modes are as before.
- All 24 binaries embed Go 1.23.12, `vcs.revision=272917d…` and `vcs.modified=false`. The macOS arm64 binaries are ad-hoc signed by the linker.
- No archive holds a key, a build-machine path or an egress address, and the docs are those of `272917d`.
- A build on macOS from a clean clone of `272917d` (Go 1.23.12, BSD tar) gave 24 of 24 binaries byte-identical to the official ones.
- The arm64 runtime went into both instances with the subshell under "Installing a release" (6 of 6 binaries match; helper `4f7faaea`, worker `e25ef9a6`). The macOS controller read the existing authority.

Real run, with the release binaries only:
- `probe-egress-multi` on A with WireGuard's UDP port dropped answered `EVIDENCE_UNAVAILABLE` after 4.5 s, and the lab stayed `tunnel_configured`. Both routes then probed and reserved at the first attempt.
- A 10-minute run on both routes (kept-alive series on A, downloads on B, name requests and `list-labs` every 15 s):
  - A: 30 healthy checks and 3 without an answer from ident.me, each followed by a success 5 to 11 s later; no fault.
    - 1500 of 1500 kept-alive requests matched: median 0.29 s, p95 0.75 s, maximum 7.7 s; 18 took over 1 s.
    - 22 of 22 name requests matched, and `list-labs` always answered `tunnel_configured`.
  - B: 25 healthy checks and 4 without an answer, then a fault at 14:30:12.
    - The reason was `source ident_me: managed egress probe failed: HTTPS_REQUEST_FAILED`: something came back through B's tunnel and was refused, so the check faulted, as designed. The worker reports only its fixed line, so what came back is not known.
    - Until then: 19 of 19 name requests matched, and five 110 s downloads kept their rate.
- ident.me at that time, from each instance's own network:
  - with curl, 10 to 13 of 40 pinned requests failed, mostly before TCP connected, twice after TCP without TLS;
  - the release worker, run 40 times on each instance as the probe user, got no answer 11 and 12 times (about 4 s each) and never reported `HTTPS probe failed`.
- A, released while three downloads ran: 0.43 s, `generation_retired: true`; the lab ended `sealed`, and a new request was refused.
- A new hold on B with a download running, `wg0` taken down: faulted 5.1 s later, and a new request was refused.
- After: every hold released, labs deleted, nothing for `egresslab-lab-recover`, helpers stopped, stages revoked. `state.json` unchanged. Journal: 72326 to 77339 bytes. Both instances keep this runtime.

Limitations:
- A source that sends something wrong still faults the lab at once. Once in 10 minutes, on one route, ident.me's reply through the tunnel did. Telling an HTTP status apart from a TLS reply cut short would need more specific worker reasons; it is left as a decision.
- ident.me was worse than earlier that day (about a quarter of requests failed). The no-answer path kept route A up throughout.

### Desktop supervisor and private IPC on macOS (Step 37)

Environment: macOS 15.3.2 (arm64), Go 1.25.1 and 1.23.12, Rust 1.92.0, Node 24, Tauri CLI 2.12.6, `@tauri-apps/api` 2.12.5. Every run used a scratch `EGRESSLAB_DATA_DIR`; the real `state.json` and `runtimes.json` were unchanged afterwards.

Tests:
- Go: `TestDesktopIPC`, `TestDesktopIPCDelete`, `TestDesktopIPCDeniedRoutes`, `TestDesktopIPCEndsOnMalformedRequest`, `TestControllerWriterLock`.
  - Denied routes: start, a lowercase method, a query string, the `/api/v1` prefix, an empty path, PUT and PATCH, a bad or traversing ID, a trailing slash, the wrong kind of ID, and a request line as the method.
  - Malformed requests: not JSON, an unknown field, trailing data, another version, an oversized line.
  - Every reply is checked to be exactly one line.
  - `go vet` passed for three systems, and `go test -race` (Go 1.25.1) and `go test` (Go 1.23.12) passed for the module.
- Rust (`cargo test`, against the real sidecar and a scratch directory):
  - create, list, restart, read back and delete a profile;
  - `start` refused with 403;
  - a second writer refused;
  - an oversized request refused;
  - no controller left after the session ends.
  - `cargo fmt` and `cargo clippy` are clean.
- Frontend: `svelte-check` reports 0 errors (the two accessibility warnings predate this step), and Prettier is clean.
- Mutation checks:
  - opening the allowlist, accepting unknown fields, or not mapping the busy lock failed a Go test;
  - removing the writer lock from `main.go` failed `refuses_a_second_writer`.

`yarn tauri dev` with a scratch data directory:
- The webview's first requests started the controller (`target/debug/egresslab-controller -desktop`) as the app's child. Its copy matches `binaries/` by hash.
- Nothing listened on 8787, and the controller had no socket.
- A second controller on the same directory, in desktop or HTTP mode, exited with "another EgressLab controller is using this data directory".
- With the app terminated (SIGTERM) or killed (SIGKILL), the controller exited 0.5 s later on EOF. No controller, app or Vite process was left.

Not checked here:
- The UI itself (Overview, creating and deleting profiles and endpoints in the window) and a normal quit (Cmd+Q, the `RunEvent::Exit` path). These need someone at the window.
- Windows (see "Windows checks").

Notes:
- Codex's review found five issues. Four are fixed; the fifth is left as a decision.
  - A list over 1 MiB ended the controller without a reply, so the UI could never load. Now such a reply is a `500 IPC_REPLY_TOO_LARGE` error and the session goes on (`TestDesktopIPCOversizedReply`). Pagination is left for later.
  - The sidecar was built for the host even when Tauri targets another architecture. Now it follows `TAURI_ENV_TARGET_TRIPLE`; an x86_64 build from this arm64 Mac produced an x86_64 Mach-O.
  - Quitting during a slow request waited up to 15 s for the session lock. Now shutdown kills the controller through a handle kept outside that lock (`shutdown_does_not_wait_for_a_request`, which fails with the old shutdown).
  - A rejected `invoke` reached the UI as a string, and the page showed a generic message. It is now an `Error` carrying the supervisor's message.
  - Left as a decision: in `yarn tauri dev`, a process that already holds port 5173 would serve the page that gets the desktop IPC. This is a development-mode risk from the guide's configuration; checking that the port is free before `tauri dev` would narrow it.
- Codex's second review repeated the two open points (port 5173 in development mode, pagination). It also found five more, all fixed:
  - A shutdown that began while a controller was starting could miss it and wait for the request's timeout. The new controller is now registered under the lock shutdown takes, and the shutdown flag is checked again there before any work is sent (`shutdown_during_start_sends_nothing`).
  - The 15 s deadline started only when a request got the session. It now starts when the request is made, and a request whose time ran out while it waited is refused without being sent (`expired_requests_are_not_sent`).
  - A universal macOS build stopped in the sidecar hook. Now both architectures are built and combined with `lipo`, and the result holds x86_64 and arm64.
  - The bundle advertised Tauri's default macOS minimum. The sidecar built with Go 1.25 needs macOS 12.0 (its `LC_BUILD_VERSION`), and that is now the bundle's minimum.
  - The Rust tests picked any sidecar in `binaries/`. They now take the one for the target they are built for; `build.rs` exports the triple.
  - Removing the first two fixes failed their tests. Seven Rust tests now pass.
- Codex's third review repeated the two open points. Two more issues are fixed; two minor ones are left for later. Codex did not review this last round.
  - Fixed: a universal build left only the combined sidecar, while Tauri's per-architecture Rust builds each need their own. Now all three are built (arm64, x86_64, universal).
  - Fixed: the time left was measured before a new controller started, so a request could still be sent after its deadline. It is now measured again after the start (`expired_after_start_is_not_sent`, which fails without it).
  - Left for later: with an agent token and a slow agent, `/agents` and `/tunnels` each make the same upstream calls and now run one after the other, so the second can run out of time.
  - Left for later: when another controller holds the data directory, the desktop sees only a pipe error, not the reason the sidecar logged.
  - Eight Rust tests now pass.
- After the fixes, the app was started again with a scratch directory:
  - the controller was the app's child, nothing listened on 8787, and the controller had no socket;
  - it exited 0.5 s after the app ended, and nothing was left;
  - the real files were unchanged.
- `cargo` created `src-tauri/Cargo.lock` and `src-tauri/gen/` (schemas). `gen/` is now ignored; `Cargo.lock` is for the app and is left to commit.

Follow-up on 2026-11-27, for the open points above:
- **Pagination.** `GET` profiles and endpoints take `?limit=N&offset=M` and answer `next_offset` while more follow; the desktop reads pages of 200. Desktop IPC passes this one query form, and only on those two lists. `TestDesktopIPCListPages` covers pages and an offset past the end; `TestListPageRefusals` covers a zero or too-large limit, a negative offset, a missing, repeated or extra parameter, and a non-number.
- **One discovery request.** `GET /discovery` answers agents and tunnels from one snapshot, and the UI's two lists share that one request, so a slow agent is asked once per refresh.
- **Lock reason in the UI.** A controller refused by the writer lock exits with status 3. The supervisor waits up to 0.5 s for the exit status after a failed request and, on 3, answers "Another EgressLab controller is using this data directory. Stop it, then retry." (`reports_a_controller_already_running`, against the real sidecar; nine Rust tests pass).
- **Dev port.** `yarn tauri:dev` first checks that nothing accepts connections on 127.0.0.1:5173 and stops if something does; Vite runs with `--strictPort`. Checked both ways: with a listener on the port it stopped, and on a free port the app started.
- **CSP.** `http://127.0.0.1:8787` is removed; the window allows only Tauri's IPC origins and the dev server.
- Checks:
  - Go: `go test -race` (Go 1.25.1) and `go test` (Go 1.23.12) passed, and `go vet` passed for three systems.
  - Rust: `cargo fmt --check` and `cargo clippy -- -D warnings` are clean.
  - Frontend: Prettier is clean, and `svelte-check` reports 0 errors and the same two warnings.
- Mutation checks, each failed a test:
  - a `next_offset` on the last page;
  - a page one item too long;
  - accepting a repeated `limit` or one over 500;
  - dropping `/discovery` from the allowlist;
  - allowing a page query on any list;
  - another exit status in the supervisor.
- With a controller holding a scratch directory, `yarn tauri:dev` on that directory started four controllers for the first refresh, and each exited with the lock message. The window itself could not be captured from this terminal (no screen-recording permission), so the banner is for someone at the window to confirm. Afterwards no controller, app or Vite process was left.
- Codex's fourth review (of this follow-up; it changed nothing, the tree hash was the same before and after) found four issues. Three are fixed; Codex did not review the fixes.
  - A malformed query (`%zz`, `&`, a malformed extra pair, `;`) was dropped by Go's parser, so it listed everything or passed as a valid page. The raw query is now parsed strictly and refused with `BAD_PAGE` (added to `TestListPageRefusals`; going back to the lenient parser fails it).
  - With more than 200 items, a delete from the window could land between two pages of a refresh, which then kept the deleted item and dropped a valid one. The window's writes and paged reads now take turns. The real `api.ts` was bundled with a fake IPC of 250 profiles, and a delete was sent between pages. With the fix the read was a whole snapshot from before the delete; with the delete's turn removed, it kept `p0` and dropped `p200`.
  - The pipe worker did not know the deadline, so a request delayed in the hand-off could still be written after it expired. The worker now refuses an expired request and closes the pipe (`worker_does_not_send_an_expired_request`; without the check the controller received the request and the test failed 3 of 3 times). Ten Rust tests pass.
  - Left as a decision: development mode still trusts whatever serves port 5173. The preflight narrows this, but a process can take the port while the sidecar builds, and plain `yarn tauri dev` skips the check. A process of the same user can already write the data directory, so the risk is from another local user. A full fix would tie the page to this launch, or load bundled assets in development.
- Also added after the review, since nothing tested the single snapshot: `TestDiscoveryAPIUsesOneSnapshot` counts the agent's calls. `/discovery` makes as many as one `/agents` (4), and a second snapshot in the handler fails it (8). The real `api.ts`, bundled with a fake IPC, sent one `/discovery` for `getAgents()` and `getTunnels()` together, and two without the shared promise.
- After these fixes, `yarn tauri:dev` ran on a fresh scratch directory:
  - the controller was the app's child and kept its PID for 20 s;
  - nothing listened on 8787, and the controller had no socket;
  - after the app got SIGTERM, the controller was gone within 250 ms, and no app, controller or Vite process was left;
  - the real `state.json` and `runtimes.json` matched their hashes from before the run.
- The sidecar answered the UI's exact requests (`/profiles?limit=200&offset=0`, the same for endpoints, and `/discovery`) with 200.
- The two harness checks of `api.ts` were run once by hand; the desktop app has no frontend test suite to keep them in.

### More and longer proxy streams, and desktop follow-ups (2026-11-27)

The helper admitted at most 8 streams per runtime and cut each after 30 minutes. That was too few for a messaging client's parallel connections, and too short for its long-lived ones (WebSockets).

Changes:
- The helper admits 32 streams, admitted and waiting together, out of 40 connections, so 8 stay free for a release and other operations. A stream lives at most 24 hours.
- `serve-socks` and `serve-endpoint` serve 32 clients at once, and up to 32 more wait 10 s for a slot.
- Desktop:
  - `yarn tauri:dev` embeds the built frontend, so no port serves the window; `yarn tauri:dev:hmr` keeps Vite (see `docs/ARCHITECTURE.md`).
  - A timer refresh is skipped while one runs, and an older refresh never overwrites a newer one.
  - In the browser, each request is bounded at 15 s.
- CI has a macOS job for the Rust supervisor: it builds the sidecar, then runs `cargo fmt --check`, `clippy -D warnings` and `cargo test --locked`.

Tests:
- `TestProxyStreamClosedByRelease` now fills all 32 stream slots and sends the release through the helper's socket. With no connections reserved beyond the streams, the release is refused (connection reset).
- The helper IPC tests passed in `egresslab`, and `go test` passed for both modules with `-race` (Go 1.25.1) and with Go 1.23.12.
- The CI job's steps passed in a copy of the tree holding only tracked and unignored files: no `node_modules` and no frontend build, which the debug build does not need. Without the sidecar, `tauri-build` stops at compile time. The job has not run on GitHub yet.
- Desktop changes, each checked by bundling the real module with a fake IPC or `fetch`, and each check failed with its change removed:
  - the refresh after a delete kept its result while a slower timer refresh ended later, and a tick during a refresh was skipped;
  - a stalled browser request was rejected after 15 s; without the bound, it was still waiting after 20 s.
- `yarn tauri:dev`, started with no frontend build at all:
  - Cargo started only after both Vite builds;
  - the window's requests started the controller, and the controller kept its PID;
  - nothing listened on 5173, 1430 or 8787.

Lima's SSH sessions. Every stream runs one `limactl shell` for its whole life, and all of them share one SSH connection. Ubuntu's `sshd` allows 10 sessions on it (`MaxSessions`). Beyond that, `ssh` opens a connection of its own, and `sshd` drops some of those when many start at once (`MaxStartups 10:30:100`).
- With the default, 20 sessions at once all ran, 10 of them on their own connection; with 40 at once, 8 failed.
- After the drop-in below and a new master connection, 40 of 40 ran on the shared connection.

Applied to `egresslab` only; `egresslab-b` keeps the default:

```bash
limactl shell egresslab bash -c 'printf "MaxSessions 64\n" | sudo tee /etc/ssh/sshd_config.d/70-egresslab-sessions.conf > /dev/null && sudo sshd -t && sudo systemctl reload ssh'
ssh -o ControlPath="$HOME/.lima/egresslab/ssh.sock" -O exit lima-egresslab
```

Real run on `egresslab`, with the helper (`945b143f`) and `helperctl` built from the working tree, the rest of alpha.3, and `serve-endpoint` built from the working tree:
- The pin answered 5 of 5. The vault stage must be made while the helper is stopped; the route then probed and reserved at the first attempt, and a name request matched.
- 24 downloads at once, at 20 KB/s for 90 s each, next to a long download:
  - the lab namespace held 23 established connections after 30 s and 22 after 60 s;
  - 22 of 24 downloads ran at full rate, about 1.85 MB each;
  - a name request during the burst matched.
- The other 2 failed before connecting: their name lookups, each of which opens its own DoH stream, could not be dialed within the window (`DESTINATION_UNREACHABLE` after about 7 s). About 48 dials started at once.
- A first burst against proof.ovh.net does not count: that server answered 20 of 24 with HTTP 429, its own limit per address.
- Long downloads at 5 to 10 KB/s:
  - from Cloudflare, one ran past 30 minutes and was reset after 2162 s (36 minutes);
  - from OVH and Hetzner, two ended cleanly after exactly 1611 s at 5 KB/s, and one at 10 KB/s after 1008 s, so neither the time nor the byte count is fixed.
  - The helper logged nothing at any of these moments, and the monitor stayed healthy throughout: 209 checks, no check without an answer, no fault.
  - What ended these connections is unknown: the helper did not log why a stream ends. Since 2026-11-27 it does (see "Logs" under the proxy in `docs/PRIVILEGED-HELPER.md`).
- Cleanup: the hold released in 0.86 s with `generation_retired: true`; the build with the probe classes below then ran on the same route.

Limitations:
- A burst of new connections can outrun the dial budget of one traffic window, since every name lookup is its own DoH stream. Caching or sharing lookups would reduce this; it is left as a decision.
- On Lima, more than about 10 streams need the `MaxSessions` change above. WSL2 starts one `wsl.exe` per stream and has not run more than eight (see "Windows checks").
- The released binaries keep the old limits; this needs a new release.

Codex reviewed this work once; it changed nothing.
- Fixed: `yarn tauri:dev` started Cargo before the frontend build had finished, so it could embed the previous build. The build hook now waits (`wait: true`); with no build at all beforehand, Cargo started only after both Vite builds.
- Fixed: in the browser, a stalled request could hold a refresh, and with it every timer tick, for good. Each request now ends after 15 s.
- Left as a decision: on a Lima guest with the default `MaxSessions`, a burst of more than about 10 connections opens SSH connections of its own, and some can be dropped. The fix above is a guest setting, not code.

### Probe failure classes (2026-11-27)

A source that answered at all used to fault the lab, even when the answer said nothing about the egress address. The alpha.3 run lost a route to `HTTPS_REQUEST_FAILED` from ident.me, and nobody could tell what came back. The worker now reports one of seven classes:
- Three renew nothing and fault nothing, like a source that never answered: the check runs again 2 s later, and the lab faults only if the health expires (see `docs/PRIVILEGED-HELPER.md`):
  - `HTTPS_NO_ANSWER`;
  - `HTTPS_SOURCE_UNAVAILABLE`: 429 or 5xx after a verified TLS handshake;
  - `HTTPS_REPLY_INCOMPLETE`: a verified reply that timed out or was cut.
- The other four still fault at once: `HTTPS_TLS_FAILED`, `HTTPS_UNEXPECTED_STATUS`, `HTTPS_INVALID_RESPONSE` and `HTTPS_REQUEST_FAILED`.
- Monitor lines now name the reason of a check without an answer.
- `probe-egress-multi` and `reserve-egress` answer `EVIDENCE_UNAVAILABLE` for these three classes and leave the lab configured.
- Since 2026-11-28 (below) `HTTPS_TLS_FAILED` is split three ways, so the list now has nine classes.

### A TLS handshake cut short (2026-11-28)

What happened: ten minutes into the 24-hour soak, the monitor faulted the lab with `source cloudflare_trace: managed egress probe failed: HTTPS_TLS_FAILED`. Automatic recovery replaced the route in about 23 s, at the same address, and used one of its five attempts.
- The timing is consistent with a stalled handshake. The healthy check before ran from about 09:49:29 to 09:49:33. With the download running, the next check was due at about 09:49:45 (16 s after the last start), or at 09:49:53 by the routine 20 s, and the fault came at 09:50:05. So the faulting check took 12 to 20 s, while the healthy one before it took about 4 s. `HTTPS_TLS_FAILED` meant that bytes had arrived but the handshake never finished, so the source probably sent its first bytes and then nothing until the 10 s timeout. The worker's single fixed line cannot say more.
- An alert or a certificate failure would have ended within a second.
- ident.me had answered the pin on every check before. Cloudflare runs first, so ident.me was not asked in that attempt.
- With this change the hold would probably have been kept. The proof would be a `pin confirmed` line in a soak run with the new helper.

The worker now tells three cases apart where it reported one:
- **`HTTPS_TLS_INTERRUPTED`:** the first two bytes began a TLS handshake record. Then, before the handshake was verified, the request timed out or the connection was reset or became unreachable, and the handshake itself reported nothing else.
- **`HTTPS_TLS_ALERT`:** the source sent a TLS alert.
- **`HTTPS_TLS_FAILED`:** everything else unverified:
  - a certificate or a host name, even when the deadline is the error that comes back, as long as the handshake reported the refusal first;
  - a reply that is not TLS, or a single byte;
  - a close. Go reports a TLS `close_notify` as a plain close, so a close might be an alert.

On a pinned generation, an `HTTPS_TLS_INTERRUPTED` no longer faults if every other source answers the pin in its own window of the same attempt. The monitor then logs `probe source unavailable ... (HTTPS_TLS_INTERRUPTED, pin confirmed by 1 other); health not renewed` and checks again 2 s later.
- **Still faults:**
  - a first probe with no pin;
  - a second cut;
  - the other source without an answer, with a clock step, or seeing another address;
  - a clock step at the finish;
  - any window, cleanup or tunnel failure.
- **Still faults at once:** alerts, closes and certificate failures. A cut that keeps recurring faults when the health expires, as a source without an answer does.
- **Budget:** one cut costs about 13 s of the 30 s check, so two in a row fit within the 60 s health.
- **Recovery supervisor:** during a check, `ListLabs` still answers at once (the monitor marks the registry settled), and `HelperInfo` takes no lock, so a longer check is not an unreadable poll.

Tests:
- `TestManagedProbeNoAnswer` (27 cases) adds five rows:
  - a handshake prefix followed by silence and by a reset, both `HTTPS_TLS_INTERRUPTED`;
  - a handshake prefix followed by a close, one handshake byte, and a `close_notify` first, all `HTTPS_TLS_FAILED`.
- The alert row now expects `HTTPS_TLS_ALERT`, and the two bytes that are not TLS still give `HTTPS_TLS_FAILED`.
- `TestProbeTLSPrefix` covers the prefix check.
- `TestProbeHandshakeRefusedAtTheDeadline` checks that a refused handshake still decides when the deadline is what `Do` returns.
- `TestManagedMultiProbeInterrupted` (20 cases) covers:
  - the cut on either source, with the pin confirmed, and the pin confirmed followed by a step at the finish (a fault);
  - no pin; the other source without an answer, with a clock step, or seeing another address; both sources cut;
  - a wrong handshake peer; a window not closed; drift; a worker left running; cancellation; an expired window;
  - drift, a worker left running and cancellation also on the last source;
  - a wrapped failure, `HTTPS_TLS_FAILED` and `HTTPS_TLS_ALERT`.
- Mutations: 17 of 19 caught. The two that survived change nothing that matters:
  - letting a second cut through still faults, because the sample count check catches it;
  - counting a close as a cut still gives `HTTPS_TLS_FAILED`. Go reports the close to the handshake as an error that is no timeout or reset, so the refused-handshake check catches it.
- Passed:
  - the Windows tests;
  - `go vet` for Windows, Linux and macOS;
  - on WSL, as the normal user and with test binaries built on Windows: the probe tests above plus the Linux-only `TestManagedProbeFailureReason`, `TestManagedProbeWorkerError`, `TestManagedProbeReasonsRoundTrip` and `TestProbeFailure`;
  - after the soak (go1.27.4 on WSL, as the normal user): `go vet ./...`, `go test ./...` and `go test -race ./...` for the whole module.
- Installed in WSL `/usr/local/bin` after the soak's teardown, built from `c5b661f` (helper `b2147388`, probe `f973d429`). The `56e03a8` binaries are in `/root/egresslab-bin-backup-56e03a8`. The helper started with the soak's flags and answered `ping` and `list-labs`, and nothing was left after it stopped. No hold has run on it yet.

Codex reviewed it once and found six issues; five were fixed:
- Fixed: a cut plus a clock step at the finish was soft, so a handshake that went stale during the attempt was never checked. It now faults.
- Fixed: Go reports a TLS `close_notify` as a plain close, so an alert record followed by it counted as a cut. Closes no longer count, and only a handshake record (22, 3) is a prefix.
- Fixed: one byte was enough for a prefix. Two are now required.
- Fixed: the request's deadline could hide a certificate refusal. The handshake's own error now decides.
- Fixed in the tests: the reset row now waits for the client hello and checks `SetLinger`.
- Left as before: a runner error that wraps both a hard failure and `ErrManagedProbeSourceUnavailable` or `ErrManagedProbeNoAnswer` would be misread. No worker produces one; this predates the change.

Tests:
- `TestManagedProbeNoAnswer` covers 22 cases against local servers, each with its class and consequence:
  - silence, refusal and a close before TLS;
  - 503 and 429;
  - a reply cut between lines, inside the status line, inside a header line, in the body or in a chunked trailer, and silence after TLS;
  - an untrusted certificate, another host name, a reply that is not TLS, two bytes that are not TLS, and a TLS 1.3 alert after the handshake;
  - 404, an encoded body, an empty body, and a complete malformed status line with or without a close after it.
- A cut is recognized when the connection was closed or reset below TLS while more of the reply was due. A TLS server that closes properly (`close_notify`) in the middle of a line still faults.
- `TestManagedProbeReasonsRoundTrip` maps every worker line back to the same reason and consequence in the helper. A line the helper does not know fails.
- `TestManagedMultiProbeNoAnswer` checks that the reason reaches the error.
- Linux: the agent, worker and helper tests passed in `egresslab-b`; macOS: `go test`, and `go vet` for three systems.
- Mutation checks, each of which failed a test:
  - a byte before a verified handshake counted as no answer;
  - a certificate failure counted as no answer;
  - a 503 or a cut verified reply counted as a failure;
  - a 404 counted as no answer;
  - the reason dropped from the monitor line;
  - an unknown worker line counted as no answer;
  - a close while more was due ignored, or any read counted as a close;
  - a TLS alert after the handshake reported as an invalid response.
- The first run of the certificate mutation was not caught, because the test read the expected consequence from the table it was checking. The soft classes are now listed in the test itself.

Codex's review (it changed nothing) found three gaps, all fixed with the tests above:
- a reply cut inside its status or a header line, which Go reports as a syntax error;
- a chunked reply cut in its trailer;
- a TLS 1.3 alert after the handshake, which was reported as an invalid response.

On Lima, `egresslab` ran this build: the helper `cc5bbfb5`, `helperctl` `5503fbc8` and the probe worker `5be57051`.
- `reserve-egress` probed and reserved at the first attempt.
- 8 minutes with two downloads at 20 KB/s and a name request every 15 s:
  - 23 of 23 name requests matched;
  - both downloads ran the full 480 s, about 9.8 MB each;
  - 24 healthy checks, none without an answer, no fault.
- ident.me answered every check, so no new reason appeared in the log.
- Afterwards:
  - the hold was released with `generation_retired: true` and the lab deleted;
  - the alpha.3 helper (`4f7faaea`), `helperctl` and worker (`e25ef9a6`) were reinstalled and the stage revoked;
  - nothing remained for `egresslab-lab-recover`;
  - `state.json` was unchanged;
  - the journal went from 77339 to 80689 bytes.

Limitations:
- A real 503 or cut reply from ident.me cannot be produced on demand, so the Lima run is a regression check only.
- Whether these classes cover the failures seen so far is unknown until the next one is logged with its reason.
- This needs a new release.

### Tests on Windows and release v0.3.0-alpha.3 on WSL2 (2026-11-27)

Tests of `bb8073f`:
- Windows, Go 1.26.2 and 1.23.2:
  - `gofmt` is clean, and `go vet` passes for all six release targets in both modules;
  - the controller passed: 547 tests and subtests.
- `TestManagedProbeNoAnswer` failed on Windows (fixed below). CI does not test the network agent on Windows.
- WSL, Go 1.27.4: `go test -race` passed for both modules.
- Desktop:
  - in a clean export of the tree (`yarn install --frozen-lockfile`): Prettier passed, and svelte-check reported 0 errors and 2 accessibility warnings;
  - the sidecar built, and `cargo fmt --check` passed;
  - `clippy` and `cargo test` cannot link on this machine (no MSVC `link.exe`); the macOS CI job runs them.
  - In the working tree, svelte-check reported a missing `@tauri-apps/api/core`: that `node_modules` predates the dependency.

Fixed: probe failure classes on Windows.
- Winsock reports its own error codes, and Go's `syscall.Errno.Is` maps none of them to the Unix names. A refused connection, or one aborted before TLS, was therefore classed `HTTPS_REQUEST_FAILED` instead of `HTTPS_NO_ANSWER`.
- The errno lists are now per system:
  - `managed_probe_errno_other.go` keeps exactly the previous values;
  - `managed_probe_errno_windows.go` has `WSAECONNREFUSED`, `WSAEHOSTUNREACH`, `WSAENETUNREACH` and `WSAETIMEDOUT`, which Go does not count as a timeout. A reset is `WSAECONNRESET`, `WSAECONNABORTED` or `ERROR_NETNAME_DELETED`.
- The worker runs only on Linux, so this changes no runtime behavior; the module's tests now pass on Windows as well.
- The "short reply, not TLS" test server wrote two bytes and closed with the client's hello unread. That close sends a reset, and Windows drops unread bytes on a reset, so the client sometimes saw no byte. It now sends FIN, then drains with a deadline.
- The test lists the expected codes for each system itself instead of reading the lists it checks.
- Checks:
  - removing any one of the seven Winsock codes failed the test on Windows;
  - the old test server failed it in 2 of 3 runs, as a race does;
  - the final version passed 20 times in a row on Windows, and the earlier one 10 times under `-race` in WSL. A full `-race` run passed with the final version.
- Codex reviewed it and found four gaps, all fixed: `WSAETIMEDOUT`, `ERROR_NETNAME_DELETED`, the drain without a deadline, and expected values taken from the list under test.
- Not covered on any system, before or after: `receivingConn` marking a reset as a close. Removing that changes no test result, because the reset error itself already counts as a cut.

The artifact (`egresslab-v0.3.0-alpha.3.zip`, the official build of `272917d`), checked again on Windows and in WSL:
- all 8 checksums verified, with exact members, owner `0/0` and modes 0755 and 0644;
- 24 of 24 binaries embed Go 1.23.12, `vcs.revision=272917d…` and `vcs.modified=false`;
- the docs are those of `272917d`, and no archive holds a key, state file, build path or egress address.
- The amd64 runtime went into WSL `/usr/local/bin` (helper `b37d812f`, worker `f32aaefd`). The alpha.1 binaries are in `/root/egresslab-bin-backup-alpha1`.

ident.me's address had changed:
- The helper's pin (from 2026-11-25) was no longer an answer for `4.ident.me`. Pinned HTTPS to it timed out even from the host's own network.
- Four `probe-egress-multi` attempts answered `EVIDENCE_UNAVAILABLE`, and the lab stayed `tunnel_configured`. The first, right after `connect-tunnel`, named Cloudflare as without an answer; the other three named ident.me.
- The pin was replaced as described under "Multi-source helper": the current single answer was verified by pinned HTTPS with certificate checks (3 of 3), staged, checked by `check-multi-probe-pin`, and renamed. The old pin is kept root-only.
- The Lima instances keep their own pins, and those may need the same change.

First hold, with the user's approval:
- `probe-egress-multi` passed at the first attempt (3.7 s); the hold was prepared, and an endpoint was created through the alpha.3 HTTP controller and served by `serve-endpoint`.
- Hostname requests: `api4.ipify.org` 3 of 3, `ifconfig.co` 3 of 3 and 8 of 8 concurrent, all at the reserved address. The Windows DNS cache held neither name.
- 108 s after the hold, after four healthy checks, the monitor faulted the lab: `monitor health expired`, 12 s after the last healthy check.
  - Cause: the WSL VM's clock ran about 4% slow against Windows, and its wall clock was stepped forward every 33 s.
    - The journal logged `Clock change detected` 931 times between the VM's boot the evening before and noon, and 55 more times after 19:00.
    - That the stepper is `systemd-timesyncd` is inferred from the 33 s cadence (its shortest poll interval); its log shows only the first synchronization.
    - The steps measured just after the fault were 1.07 and 1.11 s. Those at 19:27:30 and 19:28:03, during the hold, did not fault, and their size is unknown.
  - The helper refuses to trust health across a wall-clock step of more than 1 s (`evidenceClockStable`). The step at 19:28:37 came a second before the fault. Its refusal is by design, and it failed closed: the streams closed, new requests were refused, and the hold stayed.
- `release-egress` released it in 0.4 s with `generation_retired: true`.
- During the same period, `TestProxyStreamFirstRequestsJoin` failed once under `-race` in WSL; its message was not kept.
  - It then passed 20 times in a row, a full run and three runs of its package. Later it passed 100 of 100 times under `-race` while the clock was again stepping by more than 1 s.
  - Its cause is unknown.

`wsl --shutdown`, with the user's approval:
- The clock still ran 1.5 to 2.3% slow; right after the restart, the steps were 0.73 to 0.76 s every 33 s.
- During the second hold they were 0.79 to 1.00 s (0.999 s at 20:00:53).
- From 20:02, once the hold was over, they were 1.09 to 1.13 s again, so the restart helped for about ten minutes. The cause on the host is unknown.

Second hold, with the user's approval:
- `probe-egress-multi` passed at the first attempt (3.7 s), and `reserve-egress` prepared the hold in 3.6 s.
- Hostname requests: 3 of 3, 3 of 3 and 8 of 8 concurrent, all at the reserved address; the DNS cache held neither name.
  - 9 of these 14 requests took 2.3 to 7.3 s, and 5 took about 13 s. Why those 5 waited was not analyzed.
- Refused as expected: a wrong password, `1.1.1.1`, TCP port 53 and the name `localhost`. A normal request right after them matched.
- 360 requests on one kept-alive connection (3 a second for 2.5 minutes):
  - all matched, with no new connection;
  - median 0.31 s, 95th percentile 0.84 s, maximum 4.7 s;
  - 7 took over 1 s, each at a monitor check.
- The monitor reported 12 healthy checks, 16 to 25 s apart, and no fault until the kill switch.
- Kill switch, with a 50 KB/s download running and the lab's `wg0` taken down as root:
  - the lab had no route left;
  - three requests during the outage were all refused, and none was answered by another path;
  - the lab was `faulted` 5 s later;
  - the download ended (curl 56) after 17 KiB already buffered;
  - a new request was refused, and the hold stayed.
- `release-egress` released it in 0.3 s with `generation_retired: true`.

After:
- the endpoints were deleted through the API, and the labs deleted; `egresslab-lab-recover` found nothing;
- the helper stopped, leaving no namespace, table or process;
- `state.json` is unchanged, and `runtimes.json` differs only in the binding's `updated_at`;
- the journal went from 10180 to 13532 bytes;
- WSL keeps the alpha.3 runtime.

Limitations:
- A WSL VM whose clock runs a few percent slow faults every hold within minutes, once its steps exceed 1 s. On this machine a restart brought them under 1 s only for about ten minutes, and the second hold ran with as little as a millisecond of margin.
  - Before a real run, check `journalctl | grep -c "Clock change detected"`.
  - The helper now tolerates such steps; see the next section.
- Native Linux has still not run end to end.

### Wall-clock steps no longer fault a hold (2026-11-27)

What changed, with the details in `docs/PRIVILEGED-HELPER.md`:
- Between checks: the monitor's health and the verified evidence are timed on the monotonic clock, and bounded by their wall-clock age too (`freshSince`). A step alone no longer ends them, and a wall clock 60 s or more ahead (a paused VM) still does.
- During a check: a step that is the only cause ends the attempt like a source without an answer, with the reason `WALL_CLOCK_STEPPED`. This applies in the worker's attempt, and in the helper around the probe and at the renewal. The check runs again 2 s later and renews nothing meanwhile.
- An on-demand `probe-egress-multi` or `reserve-egress` across a step answers `EVIDENCE_UNAVAILABLE` and leaves the lab configured.
- Still faults, step or not:
  - an invalid observation;
  - a changed pinned address, generation or policy;
  - a failed window cleanup or readback;
  - a busy namespace or a tunnel that no longer verifies.

Tests:
- `TestManagedMultiProbeClockStepped` (agent) covers 11 cases:
  - a step within the 1 s tolerance passes;
  - 1.1 s forward as on WSL, 5 s forward at the finish, 1.5 s back between sources, a swing back, and a 500 ms nudge back each end softly: tunnel, pin and firewall unchanged, and the next attempt runs;
  - a step still removes the tunnel when it comes with a failed cleanup, with drift, with a changed pinned address, with two sources that disagree, or (at the finish) with a handshake from the wrong peer.
- `TestFreshSinceClockSteps`: the monotonic deadline, a reading before the record, 1.1 s ahead (fresh), 10 minutes ahead (not fresh), and a step back past the observation (fresh until the monotonic deadline, never after).
- `TestEgressMonitorClockStepped`:
  - a step around the probe, from its start or from its end to the renewal leaves the health and schedules the recheck, which then renews;
  - with an invalid observation, or one that started 10 s before the check, it faults.
- `TestGenerationProbeClockStepped`:
  - `EVIDENCE_UNAVAILABLE` with the lab configured, then a normal probe;
  - with an observation that started before the capability was issued, or finished in the helper's future, it faults.
- The helper simulates a step through `LabLifecycle.clockStable` (nil in production), because Go offers no way to build a time with a stepped wall clock.
- The earlier clock cases in `TestManagedMultiProbeLifecycle` moved to the new test, and the no-answer test keeps the source's own reason across a step.
- 17 mutations, each caught by a test:
  - in the agent (6): any step made soft even when joined with a failure; no soft path in the loop; a step at the finish faulting; the soft path skipping the tunnel check; no address comparison before the clock; the finish without the handshake peer check;
  - in `freshSince` (3): no wall-clock age bound; a step back ending it; no monotonic deadline;
  - in the monitor (5): a step around the probe or by the renewal faulting; the step checked before the time bounds, or before validity; no check from the probe's end to the renewal;
  - in the on-demand probe (3): no soft step; the step checked before the time bounds; bounds widened beyond the measured step.
- Not caught by a unit test: putting the step check back between checks, which needs a real step.
- Codex reviewed it. Fixed:
  - a step could hide a disagreement between sources, or a malformed handshake from the wrong peer at the finish;
  - the helper made an attempt soft before checking its times, so a step could hide an observation outside the attempt;
  - the monitor did not compare the probe's end with the renewal.
- Codex also flagged a pin set by an attempt that the helper then discards. That is intended: the agent verified that address.
- Paths that still fail on a backward step are listed in `docs/PRIVILEGED-HELPER.md`; they predate this change.
- `go test` passed on Windows (Go 1.26.2), and `go test -race` passed in WSL. `go vet` passed for linux, windows and darwin.

Real run on WSL2, with the user's approval for one hold:
- Setup:
  - the helper (`4446c8d2`) and the probe worker (`f9631f73`) were built from the working tree; the alpha.3 ones are in `/root/egresslab-bin-backup-alpha3`;
  - the rest of the runtime and the Windows controller were alpha.3;
  - `clockstep.py` sampled the VM's clock throughout.
- `probe-egress-multi` passed at the first attempt (3.6 s), and `reserve-egress` prepared the hold in 3.7 s.
- Hostname requests: 3 of 3, 3 of 3 and 8 of 8 concurrent, all at the reserved address. The DNS cache held neither name.
- 16.5 minutes of traffic:
  - 2100 requests on one kept-alive connection (curl reconnected twice), all at the reserved address: median 0.30 s, 95th percentile 0.81 s, maximum 8.8 s (the first request);
  - a 20 KB/s download alongside ended with curl 56 after 323 s (6.2 MB), before any step over 1 s, with nothing in the helper log. As on Lima, what ends such connections is unknown.
- The clock stepped 31 times, from +0.77 to +1.19 s; 15 steps were over 1 s, from 20:53 on.
  - The alpha.3 helper would have faulted the lab at the first of them.
  - The monitor reported 45 healthy checks.
  - Three checks met a step: `source ident_me: probe source unavailable; tunnel unchanged (WALL_CLOCK_STEPPED); health not renewed, 35s left`. Each recheck, 6 s later, was healthy.
- Kill switch, with `wg0` taken down:
  - three requests were refused, and none was answered by another path;
  - the lab was `faulted` 4 s later, and the hold stayed.
- `release-egress` released it in 0.3 s with `generation_retired: true`.
- After:
  - the endpoint and the lab were deleted, `egresslab-lab-recover` found nothing, and the helper stopped;
  - `state.json` is unchanged, and the journal went from 13532 to 15209 bytes;
  - WSL keeps the working-tree helper and worker. To go back to alpha.3, install the two binaries from `/root/egresslab-bin-backup-alpha3` into `/usr/local/bin`.

Limitations:
- The helper compared a capability's `issued_at` with its own clock with no allowance, so a WSL clock behind Windows could refuse a request. Since the next section but one it allows 4 s.
- Steps backwards were not tested on a real helper: at the time, correcting a forward step would have tripped `helperauth`'s rollback check, which then held until a helper restart (see the next sections).
- This needs a new release.

### Stream logs and network agent CI on Windows and macOS (2026-11-27)

- CI: the cross-platform job runs `go vet` and `go test` for the network agent on `windows-latest` and `macos-latest` too, not only on Linux. The Winsock failure above had gone unnoticed for want of it.
- The helper logs why each proxy stream ended and how many bytes it carried, without addresses. It also logs a fault that the keeper's traffic window finds (see "Logs" under the proxy in `docs/PRIVILEGED-HELPER.md`).
- Tests (Linux, under `-race`):
  - `TestProxyStreamEndReason` checks the naming;
  - `TestRelayProxyEndCause`, over real sockets, checks four ends: both sides closed, the destination reset, the client gone, and the context ended from outside. It also checks the byte counts.
- Three mutations each failed it:
  - consequences of our own close recorded as the cause;
  - the hang-up watcher without its cause;
  - the context read after the relay's own cancel.
- Codex reviewed it. Fixed:
  - the hang-up watcher could still write the cause while the relay returned (a data race);
  - a clean close of both sides was named `streams closed`, because the relay's own cancel came first;
  - the reason of a closed plane could be stale or carry a raw backend error, so the stream line no longer quotes it;
  - 32 stream lines could fill the 32-line log queue ahead of the fault line; the queue now holds 128.
- The new fault line prints its error as the monitor's fault line always did.
- Not yet seen on a real helper: the next run's long connections will show their reason.

### Clock rollback and host clock skew in authorization (2026-11-27)

What changed (`helperauth`):
- A rollback no longer disables authorization until a restart. While the wall clock reads earlier than the latest second seen, every capability is refused, and the latest second is never lowered. Once the clock catches up, authorization resumes.
  - Replay stays impossible: nonces are pruned only at recorded times, so a pruned nonce could only look valid again at an earlier time, which is refused.
  - The helper logs one line when authorization pauses, with how far behind the clock is, and one when it resumes. Before, the fault was silent.
  - Before, a rollback left a hold that `release-egress` could no longer release; only `recover-egress` after a guest reboot could.
- `issued_at` may lie up to 4 s ahead of the helper's clock (`MaxIssueSkew`). That is a second under the controller's 5 s allowance for evidence, so the truncation of `issued_at` to the second never lets the helper accept an attempt that the controller refuses.
  - The same allowance applies where the helper and `helperctl` compare an attempt's start with the capability's issue.
  - Expiry has no allowance, so a helper whose clock runs behind can accept a capability for up to 34 s instead of 30.
- A proxy request waiting for a window is refused at admission if its capability has expired meanwhile, or while the clock is behind. The permanent fault used to cover that.

Tests:
- `TestClockRollbackCannotRestoreConsumedNonce` covers four cases:
  - a capability minted at the rolled-back time is refused;
  - so is one a second before the latest time;
  - authorization resumes at the latest second;
  - the consumed capability is never accepted again.
- `TestClockRollbackLogged`: one line on pause, one on resume.
- `TestClockRollbackLiveNonceAndExpiry`: a consumed capability still live after the catch-up stays consumed, and `Unexpired` turns false at `not_after` and while the clock is behind.
- `issued_at` exactly 4 s ahead is accepted, and 5 s is refused, both by the verifier and by the response check.
- 7 mutations each failed a test: the latest time lowered by a rollback, a rollback refusing nothing, no skew, an unbounded skew, the probe start without the skew, no pause line, and `Unexpired` ignoring `not_after`.
- Codex reviewed it. Fixed:
  - a queued proxy request could dial after its capability expired, once the clock had caught up;
  - the log lines were written under the verifier's lock, so a stalled sink could stall authorization; they are now queued without blocking;
  - near the boundary, the helper could accept an attempt that the controller refused (hence 4 s);
  - the docs overstated the 30 s limit.
- `go test -race` passed in WSL, and `go test` and `go vet` (windows, darwin, linux) on Windows.

### Automatic route recovery (2026-11-27)

`serve-endpoint -recover` replaces a faulted route without a new start.
- **Approval.** `-approve -recover` approves, for this process only and only for the endpoint's profile, up to `-recover-attempts` automatic attempts (default 3, at most 20). With `-recover-ip same` (the default) a new route must come back at the faulted hold's address; `any` accepts another one. Without `-recover`, nothing changes: a later hold needs a new, approved start.
- **What triggers it.** A supervisor polls the helper every 5 s. Only a `faulted` state of the served lab, read from the helper epoch, runtime and key that prepared the hold, starts a recovery. Anything else stops the endpoint and touches nothing:
  - a lab that is missing, in another namespace, or `sealed`;
  - another helper epoch;
  - three unreadable polls in a row.
- **During a recovery** every new connection is refused (the kill switch); the helper already closed the streams. A client keeps the route it found when it connected, for its DNS and its CONNECT, so no request mixes two routes.
- **Steps:**
  1. Release the faulted hold. It must confirm `generation_retired`. A busy journal, an unconfirmed release or an unconfirmed revocation is asked again up to 6 times, 1 to 16 s apart. `release-egress` documents that remedy, and the helper reports a fault before it has finished removing the tunnel.
  2. Delete the faulted lab.
  3. For each attempt:
     - check that the endpoint, its runtime and the helper epoch are still those approved;
     - create a lab, connect the tunnel and probe it (four tries while a source gives no answer);
     - apply the address policy before any hold;
     - reserve (again while the journal is busy), re-read the endpoint's plan and serve the new hold.
  - A failed attempt's lab is deleted at once, unless a hold for the profile appeared meanwhile. Attempts back off from 30 s to 5 min.
- **Stops, leaving what exists:**
  - a failed or unretired release;
  - `STATE_UNCERTAIN` and the other unconfirmed or authority codes;
  - a helper that changed;
  - `LAB_LIMIT`;
  - the attempt budget. A fault with no attempt left releases nothing.
- **Under `same`**, the reserve's own probe cannot commit another address: the first probe pins the generation's address, and the agent faults a tunnel that reports another (sticky IP). A hold with another address would still be released at once.
- **Restarting the endpoint** with a hold and a faulted lab resumes the recovery. Without a hold, a crash between release and reserve, it refuses to start, as before.
- **Limits:**
  - each recovery adds a hold and a helper retirement record, so the journal (4096 reservations) and the helper's records (1024 per epoch) bound how often a profile can recover;
  - `createLab` writes `runtimes.json` back whole, so an `untrust-runtime` run at that very moment can be undone; each attempt checks the trust first, which narrows the window without closing it.

Tests (fake runtime, real authority):
- recovery at the same address, the new hold minted, and the faulted lab deleted;
- refusal during the release and after it;
- the same-address policy making no hold and leaving no lab;
- another address accepted under `any`;
- a failed release, and anything but a fault, stopping;
- an uncertain probe stopping at once;
- release retries for the documented codes only;
- the budget leaving the next fault alone;
- a helper restart and a deleted endpoint stopping before a new lab;
- a lab with a hold left in place;
- flag validation.
- 11 mutations, each failed a test:
  - recovering a non-faulted lab;
  - reserving despite another address;
  - going on after a failed release;
  - no attempt cap;
  - admitting connections during a recovery;
  - retrying uncertain outcomes;
  - no release retry, or retrying any refusal;
  - releasing with no attempt left;
  - no preflight;
  - deleting a lab with a hold.
- `go test -race` passed in WSL.
- Codex reviewed it. Fixed:
  - the helper epoch was not carried into a recovery;
  - a leftover lab was deleted after the backoff, with no check for a hold;
  - a revocation the helper had not confirmed yet stopped the recovery;
  - the budget was checked after destructive steps, and `LAB_LIMIT` was retried;
  - Ctrl+C did not reach the supervisor, and could hide its last error;
  - a DNS lookup and its CONNECT could use two routes;
  - `-recover=false` was accepted on other commands;
  - two tests were too weak.
- Codex also flagged two points left as they are:
  - a hold committed at another address: the sticky pin prevents it;
  - the `untrust-runtime` race: noted above.

### Soak runs (scripts/soak)

`scripts/soak/windows-wsl.ps1` runs one soak on Windows with a WSL runtime, and `scripts/soak/wsl-root.sh` is its root side. Start the orchestrator detached, so that it outlives the shell:

```powershell
Start-Process powershell -WindowStyle Hidden -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','scripts\soak\windows-wsl.ps1',
  '-ControllerDir','<folder with both controller binaries>','-ProfileId','<profile ID>','-OutDir','<results folder>','-Hours','1','-FaultAfterMinutes','30'
```

The orchestrator:
- keeps the machine awake while it runs (`SetThreadExecutionState`);
- starts the helper and builds a route with one approved hold;
- creates an endpoint and serves it with `-recover -recover-ip same`;
- sends one hostname request every 15 s, keeps one 2 KB/s download running, and optionally takes `wg0` down once;
- writes one sample a minute to `samples.csv`:
  - the helper's RSS, fds and threads;
  - the controller's memory, handles and threads;
  - `wsl.exe` processes and the journal size;
  - recoveries and request results;
  - the helper log counts: healthy checks, soft checks (and among them the pins confirmed after a cut handshake), clock steps, faults, authorization pauses and stream ends by reason;
- writes `requests.csv`, `downloads.csv`, `clocksteps.log` and `events.log` as it goes;
- at the end tears down: endpoint, hold, lab and helper, then writes `summary.json`.

Addresses are compared, never written, and the SOCKS credentials are deleted at the end. A file named `stop` in the results folder ends a run early, with the same teardown. `scripts/soak/summarize.py RUN_DIR` prints the run's figures. Its helper log counts come from the last minute sample, so they miss up to a minute before the teardown. For the whole log, run `wsl-root.sh logcounts <helper log> 0` as root.

First run, on 2026-11-28 with the user's approval:
- Setup:
  - 1 hour on Windows and WSL2, with the runtime built from `56e03a8` (helper `e2bfe8a4`) and the controller from the recovery change before it was committed in `c5b661f`;
  - `-recover-attempts 3`, and `wg0` taken down at minute 30;
  - the earlier binaries are in `/root/egresslab-bin-backup-pre-soak`.
- Recovery:
  - `wg0` went down at 09:09:18, and the keeper's window faulted the lab (`Traffic window fault`, the new line);
  - the route was replaced before 09:09:42, at the same address, using 1 attempt of 3;
  - one request was refused meanwhile (curl 97), and the next one went through the new hold.
- Requests: 228 of 231 at the reserved address, none elsewhere.
  - Median 5.0 s, 95th percentile 11.1 s, maximum 17.6 s.
  - Failures: the one during the outage, one TLS error (curl 35) and one reset (curl 56).
- The clock stepped 106 times, by +1.23 to +1.85 s, every one over the old 1 s limit. There were 12 soft clock-step rechecks, 165 healthy checks and no monitor fault.
- Stream ends: 457 closed by both sides, 5 streams closed by the fault, 1 download reset.
- Resources: the helper's RSS stayed at 12.7 to 14.0 MB, with 15 threads. The controller grew from 209 to 329 handles and from 14 to 25 threads; the second run below leveled off.
- Teardown:
  - release with `generation_retired: true`, the lab deleted, the endpoint deleted, the helper stopped;
  - nothing was left;
  - the journal went from 15209 to 18561 bytes.

Findings:
- **Latency.** A new connection waits for the keeper's next traffic window (about 6 s), and a hostname request opens two in a row (the DoH lookup, then the CONNECT). That gives medians of about 5 s and a tail near 15 s. It is the traffic gate's design, and it matters for a messaging client's first connections.
- **A fault ends a stream as a FIN.** When the helper closes a stream after a fault, `helperctl` forwards it as the destination's FIN, so the client gets a clean half-close after any data still buffered. The rate-limited download read its buffered data for six more minutes before it ended. An application that reads as data arrives sees it at once.
- **Half-closed streams linger.** After a client closes, its stream lives until the destination closes too: 2 to 12 minutes here, each holding one of the 32 slots.

Second run, planned for 24 hours, on 2026-11-28 with the user's approval:
- Setup: the same binaries, `-recover-attempts 5`, no injected fault.
- Length: 09:39 to 13:00, about 3 h 20 min. The user asked to end it at 13:00, so `serve-endpoint` was stopped then, and the orchestrator's own teardown ran.
- One natural fault, at 09:50: `cloudflare_trace` `HTTPS_TLS_FAILED`, probably a stalled handshake (see "A TLS handshake cut short").
  - New connections were refused from 09:50:03 to 09:50:28, and the route was replaced at the same address, using 1 attempt of 5.
  - No other fault in the next 3 h 10 min.
- Requests: 769 of 773 at the reserved address, none elsewhere.
  - Median 5.3 s, 95th percentile 11.7 s, maximum 19.8 s.
  - Failures: three during the outage (curl 97), and one cut by the teardown at 13:00 (curl 56).
- The whole helper log, counted after the run: 517 healthy checks, 59 soft clock-step rechecks, 1 monitor fault, no traffic window fault, no authorization pause. The clock stepped 352 times, by +0.69 to +2.18 s.
- Stream ends: 1545 closed by both sides, 6 download resets, 1 download timeout, and 1 client gone plus 1 upload reset at the teardown. After the fault, the 2 KB/s download ended with curl 56 five more times: four after about 40 minutes and 4.9 MB each, and one after 23 minutes.
- Resources:
  - the helper: RSS 12.1 to 13.7 MB, 14 to 16 threads, 13 to 33 fds;
  - the controller's handles rose in steps: 213 to about 280 in the first 11 minutes, about 280 until minute 72, about 310 from minute 100, and 306 to 314 for the last 100 minutes. Threads went from 15 to 23, and the working set stayed at 17 to 21 MB.
  - Steps that level off look like pools filling, not a leak, but 3 hours cannot rule out slow growth.
- Teardown:
  - release with `generation_retired: true`, the lab deleted, the endpoint deleted, the helper stopped;
  - nothing was left;
  - the journal went from 18561 to 21914 bytes.

Since this run, the helper log counts include `pin_confirmed`: soft checks where the other source confirmed the pin after an `HTTPS_TLS_INTERRUPTED` cut. A run with the new runtime is the way to see one.

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

If DNS returns several addresses, do not take the first one blindly. The provider does not promise a stable address: on 2026-11-27, `4.ident.me` had moved, the old pin no longer answered, and every multi-source probe faulted its lab until the pin was provisioned again (see "Release binaries on macOS and two Lima runtimes (Step 36)"). DNS at probe time, automatic replacement of the address and skipping certificate verification (`curl -k`) are not allowed. A host-side check reveals the host's own public IP to the provider; it is not a managed observation and never activates an egress lease. The helper reads the approved pin from `/etc/egresslab/multi-probe-pin` at startup (Step 29C.4b, see "Multi-source helper").

## Windows checks

Pending (Step 37): run `yarn tauri:dev` (the embedded frontend, no dev port) on Windows with a scratch `EGRESSLAB_DATA_DIR`, and check four things:
- the sidecar starts without a console window and answers;
- a second controller is refused through `LockFileEx`, and with a controller already holding the directory, the window shows "Another EgressLab controller is using this data directory";
- nothing listens on 8787, 5173 or 1430;
- no controller is left after the app exits normally and after the app process is killed.

Pending (more and longer streams): with a route up through WSL2, open more than eight streams at once through `serve-endpoint`, each with its own `wsl.exe`, and keep one open for more than 30 minutes.

Both checks that were pending for Windows ran on 2026-11-26; see "Windows and WSL2 run (Step 35)".

1. Shared journal read lock (Step 35): passed. The lock tests ran 20 times in a row, and `go test` passed for both modules with Go 1.26.2 and 1.23.2. `-race` needs cgo, which is missing on that Windows machine, so it ran in WSL.
2. Controller state files during `serve-endpoint` (Step 35, from the Codex review): saves did fail, and so did some CONNECTs. This is fixed in the store's read and save paths, which every lab command and the API share: delete sharing, a POSIX rename, and bounded retries.

## Next Milestone

The network engine MVP is complete: release v0.3.0-alpha.1 (Step 36), packaged and checked with its release binaries on Windows through WSL2, and on macOS with two Lima runtimes (a local build of the release commit); v0.3.0-alpha.2 adds the `list-labs` fix. A source without an answer no longer faults a lab since then, which needs a new release. Further work belongs to the next product phase (VPN rotation, UDP, IPv6, automatic VM management, desktop activation, Universal Messenger integration), not to the engine MVP. It builds on the monitor traffic overlay and the isolated DNS resolver for domain names verified on Windows through WSL2 and on two Lima runtimes (Step 35), the proxy plane and an API-created endpoint verified on Windows through WSL2, with the fix for the Windows state files (Step 35), several streams per runtime verified on two Lima runtimes (Step 35), the endpoint-to-runtime integration verified on two Lima runtimes (Step 35), the SOCKS5 proxy runtime verified on Lima through the real tunnel (Step 34), the kernel-timed traffic gate verified in throwaway namespaces on Lima (Step 33), the continuous egress monitoring of prepared generations verified on Lima (Step 32), the reboot-bound reservation recovery verified on Lima through a real helper crash and guest reboot (Step 31E.3), the persistent helper epoch witness (Step 31E.3a), the cross-process authority races and the concurrent reservations and releases on two Lima runtimes (Step 31E.2), the collision refused across two Lima runtimes (Step 31E.1), the reservation lifecycle verified on Lima against the real tunnel (Step 31D.3e), the controller's release command (Step 31D.3d.2), the durable release journal (Step 31D.3d.1), the helper's generation-bound revocation (Step 31D.3c), the controller's lease preparation (Step 31D.3b), the helper's prepared lease (Step 31D.3a), the provisioned reservation authority and its CLI commands (Step 31D.2), the signed reservation orchestration (Step 31D.1), the controller's durable reservation authority (Step 31C), its in-process registry (Step 31B), the helper's local egress candidate (Step 31A), the generation-scoped pin (Step 30A), the signed generation binding (Step 30B.1) and the V2 cutover (Step 30B.2). Open: the first signed attempt of a session sometimes fails because a probe worker exits with an error the helper does not record (Steps 29B.1, 29B.2b, 29C.4c, 30A and 30B.2 on Lima, and the single-source probe on WSL2; in the last four it was the first probe of the session, and a fresh lab then succeeded; in Step 31E.1 it was the first probe right after `connect-tunnel` on runtime B's second config, and in Step 31E.2 the first probe of both new helpers, about a second after `connect-tunnel`; each time a fresh lab then succeeded, in Step 31E.2 probed 10 s after connecting; in Step 31E.3 both reservations, 10 s after `connect-tunnel`, succeeded at the first attempt); since Step 32 a failed worker names a coded reason in the helper's error, but no failure has recurred since, so the cause is still unknown. (On 2026-11-27 the first probes on Lima failed with `ident_me … HTTPS_REQUEST_FAILED` because `4.ident.me` had moved; that is a different, known cause.) WSL2 ran the single-source and multi-source paths on 2026-11-25 and the proxy plane, then the monitor overlay and the isolated DNS resolver, on 2026-11-26 (the first probe of every session succeeded); native Linux has not. See `docs/PRIVILEGED-HELPER.md`.
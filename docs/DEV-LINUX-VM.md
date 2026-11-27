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
- A fault found by the keeper's traffic window is not written to the helper log, unlike a monitor fault; the controller sees `LAB_FAULTED`.
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
  - Any such failure during a monitor check faults the lab, with no retry. Three of the five holds below ended that way.

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
, from the release commit with the official Go version. The official GitHub artifact was not run on macOS.
- The host's own DNS traffic was not captured, since packet capture on macOS needs root, which this run did not have. The isolated resolver sends nothing to the host's resolver by design (Step 35), and the instances' captures saw none of the names.
- ident.me's unreliability faulted three of the five holds. By design, any source failure during a check faults the generation. A source that fails this often makes long sessions impractical.
- An idle route's first request may wait up to a monitor interval for a window. If it arrives during a check longer than 5 s, it is likely refused with `LAB_BUSY` (seen once).
- In `727fc84`, `list-labs` answered `LAB_BUSY` while a runtime had streams (seen on B); fixed after the run.
- A release that arrives during a check waits for it (4.7 s here).
- Gatekeeper with a browser-downloaded (quarantined) archive was not tried.
- Native Linux has not run end to end.

Application networking as a whole remained disabled.

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

Both checks that were pending for Windows ran on 2026-11-26; see "Windows and WSL2 run (Step 35)".

1. Shared journal read lock (Step 35): passed. The lock tests ran 20 times in a row, and `go test` passed for both modules with Go 1.26.2 and 1.23.2. `-race` needs cgo, which is missing on that Windows machine, so it ran in WSL.
2. Controller state files during `serve-endpoint` (Step 35, from the Codex review): saves did fail, and so did some CONNECTs. This is fixed in the store's read and save paths, which every lab command and the API share: delete sharing, a POSIX rename, and bounded retries.

## Next Milestone

The network engine MVP is complete: release v0.3.0-alpha.1 (Step 36), packaged and checked with its release binaries on Windows through WSL2, and on macOS with two Lima runtimes (a local build of the release commit). Further work belongs to the next product phase (VPN rotation, UDP, IPv6, automatic VM management, desktop activation, Universal Messenger integration), not to the engine MVP. It builds on the monitor traffic overlay and the isolated DNS resolver for domain names verified on Windows through WSL2 and on two Lima runtimes (Step 35), the proxy plane and an API-created endpoint verified on Windows through WSL2, with the fix for the Windows state files (Step 35), several streams per runtime verified on two Lima runtimes (Step 35), the endpoint-to-runtime integration verified on two Lima runtimes (Step 35), the SOCKS5 proxy runtime verified on Lima through the real tunnel (Step 34), the kernel-timed traffic gate verified in throwaway namespaces on Lima (Step 33), the continuous egress monitoring of prepared generations verified on Lima (Step 32), the reboot-bound reservation recovery verified on Lima through a real helper crash and guest reboot (Step 31E.3), the persistent helper epoch witness (Step 31E.3a), the cross-process authority races and the concurrent reservations and releases on two Lima runtimes (Step 31E.2), the collision refused across two Lima runtimes (Step 31E.1), the reservation lifecycle verified on Lima against the real tunnel (Step 31D.3e), the controller's release command (Step 31D.3d.2), the durable release journal (Step 31D.3d.1), the helper's generation-bound revocation (Step 31D.3c), the controller's lease preparation (Step 31D.3b), the helper's prepared lease (Step 31D.3a), the provisioned reservation authority and its CLI commands (Step 31D.2), the signed reservation orchestration (Step 31D.1), the controller's durable reservation authority (Step 31C), its in-process registry (Step 31B), the helper's local egress candidate (Step 31A), the generation-scoped pin (Step 30A), the signed generation binding (Step 30B.1) and the V2 cutover (Step 30B.2). Open: the first signed attempt of a session sometimes fails because a probe worker exits with an error the helper does not record (Steps 29B.1, 29B.2b, 29C.4c, 30A and 30B.2 on Lima, and the single-source probe on WSL2; in the last four it was the first probe of the session, and a fresh lab then succeeded; in Step 31E.1 it was the first probe right after `connect-tunnel` on runtime B's second config, and in Step 31E.2 the first probe of both new helpers, about a second after `connect-tunnel`; each time a fresh lab then succeeded, in Step 31E.2 probed 10 s after connecting; in Step 31E.3 both reservations, 10 s after `connect-tunnel`, succeeded at the first attempt); since Step 32 a failed worker names a coded reason in the helper's error, but no failure has recurred since, so the cause is still unknown. (On 2026-11-27 the first probes on Lima failed with `ident_me … HTTPS_REQUEST_FAILED` because `4.ident.me` had moved; that is a different, known cause.) WSL2 ran the single-source and multi-source paths on 2026-11-25 and the proxy plane, then the monitor overlay and the isolated DNS resolver, on 2026-11-26 (the first probe of every session succeeded); native Linux has not. See `docs/PRIVILEGED-HELPER.md`.
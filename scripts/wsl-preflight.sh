#!/usr/bin/env bash
set -Eeuo pipefail

# Checks that WSL2 can run the EgressLab lab CLIs: network namespaces, a WireGuard
# kernel interface plus wg(8), and nftables check/apply/readback.
#
# All kernel changes stay in a temporary network namespace. This script never
# changes the WSL root namespace routes or firewall.
#
# Run it as your normal WSL user (it asks for your sudo password):
#   bash scripts/wsl-preflight.sh

if [[ "$EUID" -eq 0 ]]; then
  echo "Run as a normal WSL user, not root." >&2
  exit 1
fi

osrelease="$(cat /proc/sys/kernel/osrelease)"

# WSL1 kernels end in "-Microsoft" and have no network namespaces.
if [[ "$osrelease" == *-Microsoft ]]; then
  echo "WSL1 detected ($osrelease): it has no network namespaces." >&2
  echo "Convert the distro from Windows: wsl --set-version <distro> 2" >&2
  exit 1
fi

if ! grep -qiE 'microsoft|wsl' <<<"$osrelease" &&
   [[ ! -e /proc/sys/fs/binfmt_misc/WSLInterop ]]; then
  echo "This preflight is intended for WSL2 (kernel: $osrelease)." >&2
  exit 1
fi

# The lab CLIs resolve ip, nft and wg only from these directories
# (internal/agent/system_binary.go), not from PATH, so check the same places.
find_system_binary() {
  local dir
  for dir in /usr/sbin /usr/bin /sbin /bin; do
    if [[ -f "$dir/$1" && -x "$dir/$1" ]]; then
      printf '%s\n' "$dir/$1"
      return 0
    fi
  done
  return 1
}

missing=0
for program in ip nft wg; do
  if ! find_system_binary "$program" >/dev/null; then
    echo "Required command missing: $program (looked in /usr/sbin /usr/bin /sbin /bin)" >&2
    missing=1
  fi
done

for program in sudo od tr grep; do
  if ! command -v "$program" >/dev/null 2>&1; then
    echo "Required command missing: $program" >&2
    missing=1
  fi
done

if [[ "$missing" -ne 0 ]]; then
  echo "Install the missing tools, for example: sudo apt install -y iproute2 nftables wireguard-tools" >&2
  exit 1
fi

ip_bin="$(find_system_binary ip)"
nft_bin="$(find_system_binary nft)"
wg_bin="$(find_system_binary wg)"

sudo -v

nonce="$(
  od -An -N8 -tx1 /dev/urandom |
    tr -d '[:space:]'
)"

namespace="egresslab-preflight-${nonce}"
created=0

cleanup() {
  # Checks for the namespace itself, so an interrupt during "netns add" is still cleaned up.
  if [[ "$created" -eq 1 && -e "/run/netns/$namespace" ]]; then
    if ! sudo "$ip_bin" netns delete "$namespace"; then
      echo "WARNING: inspect leftover namespace $namespace manually:" >&2
      echo "  sudo ip netns delete $namespace" >&2
    fi
  fi
}

trap cleanup EXIT

echo '[1/5] Create temporary network namespace'

# Set before the add: if the add is interrupted after the kernel created it,
# cleanup still finds and deletes it.
created=1
sudo "$ip_bin" netns add "$namespace"

echo '[2/5] Test WireGuard kernel interface and wg(8)'

sudo "$ip_bin" -n "$namespace" link add \
  dev wg-preflight type wireguard

sudo "$ip_bin" -n "$namespace" link show \
  dev wg-preflight >/dev/null

sudo "$ip_bin" netns exec "$namespace" "$wg_bin" show wg-preflight >/dev/null

echo '[3/5] Test nftables check, apply and readback'

sudo "$ip_bin" netns exec "$namespace" "$nft_bin" --check -f - <<'NFT'
add table inet egresslab_preflight
add chain inet egresslab_preflight output { type filter hook output priority 0; policy drop; }
NFT

sudo "$ip_bin" netns exec "$namespace" "$nft_bin" -f - <<'NFT'
add table inet egresslab_preflight
add chain inet egresslab_preflight output { type filter hook output priority 0; policy drop; }
NFT

rules="$(
  sudo "$ip_bin" netns exec "$namespace" \
    "$nft_bin" list chain inet egresslab_preflight output
)"

if ! grep -Eq 'policy[[:space:]]+drop' <<<"$rules"; then
  echo "nftables policy-drop readback failed." >&2
  exit 1
fi

echo '[4/5] Verify namespace has no default route'

# Each listing is its own assignment, so a failing ip command stops the script
# (set -e) instead of reading as "no route".
v4_default="$(sudo "$ip_bin" -n "$namespace" -4 route show default)"
v6_default="$(sudo "$ip_bin" -n "$namespace" -6 route show default)"

if [[ -n "$v4_default" || -n "$v6_default" ]]; then
  echo "Unexpected default route inside fresh namespace." >&2
  exit 1
fi

echo '[5/5] Clean up temporary namespace'

sudo "$ip_bin" netns delete "$namespace"
created=0
trap - EXIT

echo 'PASS: netns, WireGuard, nftables and cleanup work in WSL2.'

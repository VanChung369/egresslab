
#!/usr/bin/env bash
set -Eeuo pipefail

# All kernel modifications stay in a temporary
# network namespace. This script never changes
# the WSL root namespace routes or firewall.

if [[ "$EUID" -eq 0 ]]; then
  echo "Run as a normal WSL user, not root." >&2
  exit 1
fi

if ! grep -qi 'microsoft' /proc/sys/kernel/osrelease; then
  echo "This preflight is intended for WSL2." >&2
  exit 1
fi

for program in sudo ip nft wg od tr grep; do
  if ! command -v "$program" >/dev/null 2>&1; then
    echo "Required command missing: $program" >&2
    exit 1
  fi
done

sudo -v

nonce="$(
  od -An -N8 -tx1 /dev/urandom |
    tr -d '[:space:]'
)"

namespace="egresslab-preflight-${nonce}"
created=0

cleanup() {
  if [[ "$created" -eq 1 ]]; then
    if ! sudo ip netns delete "$namespace"; then
      echo "WARNING: inspect leftover namespace $namespace manually." >&2
    fi
  fi
}

trap cleanup EXIT

echo '[1/5] Create temporary network namespace'

sudo ip netns add "$namespace"
created=1

echo '[2/5] Test WireGuard kernel interface'

sudo ip -n "$namespace" link add \
  dev wg-preflight type wireguard

sudo ip -n "$namespace" link show \
  dev wg-preflight >/dev/null

echo '[3/5] Test nftables check, apply and readback'

sudo ip netns exec "$namespace" nft --check -f - <<'NFT'
add table inet egresslab_preflight
add chain inet egresslab_preflight output { type filter hook output priority 0; policy drop; }
NFT

sudo ip netns exec "$namespace" nft -f - <<'NFT'
add table inet egresslab_preflight
add chain inet egresslab_preflight output { type filter hook output priority 0; policy drop; }
NFT

rules="$(
  sudo ip netns exec "$namespace" \
    nft list chain inet egresslab_preflight output
)"

if ! grep -Eq 'policy[[:space:]]+drop' <<<"$rules"; then
  echo "nftables policy-drop readback failed." >&2
  exit 1
fi

echo '[4/5] Verify namespace has no default route'

if [[ -n "$(sudo ip -n "$namespace" -4 route show default)" ]] ||
   [[ -n "$(sudo ip -n "$namespace" -6 route show default)" ]]; then

  echo "Unexpected default route inside fresh namespace." >&2
  exit 1
fi

echo '[5/5] Clean up temporary namespace'

sudo ip netns delete "$namespace"
created=0
trap - EXIT

echo 'PASS: netns, WireGuard, nftables and cleanup work in WSL2.'

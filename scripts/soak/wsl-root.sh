#!/usr/bin/env bash
# Root-side helper control and sampling for a soak run (scripts/soak/windows-wsl.ps1), run as
# root in the WSL distribution. It never prints a key, an endpoint or an egress address.
set -u

SOCK=/run/egresslab/helper.sock

case "${1:-}" in
start-helper)
  # start-helper LOG UID GID: the helper with every flag the proxy needs; returns when it exits.
  log=$2 uid=$3 gid=$4
  exec /usr/local/bin/egresslab-helper -uid "$uid" -gid "$gid" \
    -auth-public-key-file /etc/egresslab/helper-auth.pub -enable-lab-lifecycle -enable-vault -enable-tunnel \
    -enable-multi-probe -probe-uid "$(id -u egresslab-probe)" -probe-gid "$(id -g egresslab-probe)" \
    -enable-proxy -proxy-uid "$(id -u egresslab-proxy)" -proxy-gid "$(id -g egresslab-proxy)" >>"$log" 2>&1 ;;

wait-helper)
  for _ in $(seq 1 75); do [ -S "$SOCK" ] && exit 0; sleep 0.2; done
  exit 1 ;;

stop-helper)
  pid=$(pidof egresslab-helper) || exit 0
  kill -TERM "$pid"
  for _ in $(seq 1 150); do pidof egresslab-helper >/dev/null || exit 0; sleep 0.2; done
  exit 1 ;;

precheck)
  # Refuses to start over anything left from an earlier run.
  if pidof egresslab-helper >/dev/null || [ -e "$SOCK" ]; then echo "a helper or its socket exists"; exit 1; fi
  ns=$(ip netns list | grep -c '^egresslab-lab-'); tables=$(nft list tables | grep -c egresslab_ul_)
  [ "$ns" -eq 0 ] && [ "$tables" -eq 0 ] || { echo "leftovers: namespaces $ns, tables $tables"; exit 1; } ;;

leftovers)
  echo "namespaces=$(ip netns list | grep -c '^egresslab-lab-') tables=$(nft list tables | grep -c egresslab_ul_) probe_processes=$(pgrep -u egresslab-probe | wc -l) proxy_processes=$(pgrep -u egresslab-proxy | wc -l) socket=$([ -e $SOCK ] && echo 1 || echo 0)" ;;

sample)
  # One CSV fragment: helper_alive,rss_kb,fds,threads,namespaces,proxy_processes
  pid=$(pidof egresslab-helper)
  if [ -n "$pid" ]; then
    rss=$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status"); threads=$(awk '/^Threads:/ {print $2}' "/proc/$pid/status")
    fds=$(ls "/proc/$pid/fd" | wc -l)
    echo "1,$rss,$fds,$threads,$(ip netns list | grep -c '^egresslab-lab-'),$(pgrep -u egresslab-proxy | wc -l)"
  else
    echo "0,0,0,0,$(ip netns list | grep -c '^egresslab-lab-'),$(pgrep -u egresslab-proxy | wc -l)"
  fi ;;

logcounts)
  # logcounts LOG FROM_LINE: counts in the helper log after FROM_LINE, as key=value pairs.
  log=$2 from=$3
  tail -n +"$((from + 1))" "$log" | awk '
    /Egress monitor healthy/ {healthy++}
    /health not renewed/ {soft++; if (/pin confirmed by/) pin_confirmed++}
    /WALL_CLOCK_STEPPED|wall clock stepped/ {clock++}
    /Egress monitor fault/ {monitor_fault++}
    /Traffic window fault/ {window_fault++}
    /Authorization paused/ {auth_paused++}
    /proxy stream ended after/ {
      ended++
      reason = $0; sub(/.*proxy stream ended after [0-9hms.]+: /, "", reason); sub(/ \(up .*/, "", reason)
      gsub(/[^a-z]+/, "_", reason); reasons[reason]++
    }
    END {
      printf "healthy=%d soft=%d pin_confirmed=%d clock=%d monitor_fault=%d window_fault=%d auth_paused=%d ended=%d",
        healthy, soft, pin_confirmed, clock, monitor_fault, window_fault, auth_paused, ended
      for (r in reasons) printf " end_%s=%d", r, reasons[r]
      printf "\n"
    }' ;;

loglines)
  wc -l < "$2" ;;

linkdown)
  # Takes the lab's wg0 down from the root namespace, as a dropped tunnel would.
  ip -n "$2" link set wg0 down && echo "wg0 down in $2" ;;

clocksteps)
  # clocksteps SECONDS: prints every wall-clock step of more than 50 ms against monotonic time.
  exec python3 -I -c '
import sys, time
end = time.monotonic() + float(sys.argv[1])
prev = time.time() - time.monotonic()
while time.monotonic() < end:
    time.sleep(0.1)
    off = time.time() - time.monotonic()
    if abs(off - prev) > 0.05:
        print(time.strftime("%Y-%m-%dT%H:%M:%S"), "%+.3f" % (off - prev), flush=True)
    prev = off
' "$2" ;;

*)
  echo "usage: $0 start-helper|wait-helper|stop-helper|precheck|leftovers|sample|logcounts|loglines|linkdown|clocksteps" >&2
  exit 2 ;;
esac

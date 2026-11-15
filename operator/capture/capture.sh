#!/bin/sh
# Capture job of pcap-operator: capture with tcpdump, upload the pcap to pcap-analyzer and write
# {"runId": N, ...} to the termination message (read by the operator).
#
# MODE=Pod  : hostPID; finds the network namespace that holds POD_IP and captures inside it.
# MODE=Node : hostNetwork; captures on IFACE (default: the default-route interface).
#
# Env: MODE POD_IP IFACE FILTER DURATION MAX_SIZE_MB SNAPLEN PCAP_NAME METADATA
#      ANALYZER_URL ANALYSIS_ID PROVIDER DRY_RUN COMPARE_PREVIOUS ANALYZER_USERNAME ANALYZER_PASSWORD
set -eu

WORK=/work
OUT=$WORK/capture.pcap
TERM_LOG=/dev/termination-log

fail() {
  echo "error: $*" >&2
  jq -cn --arg e "$*" '{error: $e}' > "$TERM_LOG" 2>/dev/null || printf '{"error":"capture failed"}' > "$TERM_LOG"
  exit 1
}

: "${MODE:?}" "${DURATION:?}" "${ANALYZER_URL:?}" "${ANALYSIS_ID:?}"
MAX_SIZE_MB=${MAX_SIZE_MB:-100}
SNAPLEN=${SNAPLEN:-0}
IFACE=${IFACE:-}
FILTER=${FILTER:-}

# ------------------------------------------------------------ where to capture
NSENTER=""
case "$MODE" in
  Pod)
    [ -n "${POD_IP:-}" ] || fail "POD_IP is not set"
    pid="" line="" seen="|"
    # One process per distinct network namespace is enough; the netns holding POD_IP is the pod's.
    for d in /proc/[0-9]*; do
      ns=$(readlink "$d/ns/net" 2>/dev/null) || continue
      case "$seen" in *"|$ns|"*) continue ;; esac
      seen="$seen$ns|"
      p=${d#/proc/}
      line=$(nsenter -t "$p" -n ip -o addr show 2>/dev/null | grep -F " $POD_IP/" | head -n 1) || true
      if [ -n "$line" ]; then pid=$p; break; fi
    done
    [ -n "$pid" ] || fail "network namespace of pod IP $POD_IP not found on this node"
    if [ -z "$IFACE" ]; then
      IFACE=$(echo "$line" | awk '{print $2}' | cut -d@ -f1)
    fi
    NSENTER="nsenter -t $pid -n"
    echo "pod $POD_IP: netns of pid $pid, interface $IFACE"
    ;;
  Node)
    if [ -z "$IFACE" ]; then
      IFACE=$(ip route show default | awk '{for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit }}')
    fi
    [ -n "$IFACE" ] || fail "could not determine the default-route interface; set spec.node.interface"
    echo "node: interface $IFACE"
    ;;
  *) fail "unknown MODE $MODE" ;;
esac

# ------------------------------------------------------------ capture
set -- -i "$IFACE" -n -U -s "$SNAPLEN" -w "$OUT"
[ -n "$FILTER" ] && set -- "$@" "$FILTER"

# nsenter -n execs tcpdump, so $! is tcpdump's pid.
$NSENTER tcpdump "$@" 2> "$WORK/tcpdump.log" &
tpid=$!

limit=$((MAX_SIZE_MB * 1024 * 1024))
end=$(($(date +%s) + DURATION))
reason=duration
while kill -0 "$tpid" 2> /dev/null; do
  if [ "$(date +%s)" -ge "$end" ]; then break; fi
  size=$(stat -c %s "$OUT" 2> /dev/null || echo 0)
  if [ "$size" -ge "$limit" ]; then reason=size; break; fi
  sleep 1
done
if kill -0 "$tpid" 2> /dev/null; then
  kill -INT "$tpid" 2> /dev/null || true
else
  reason=exited
fi
wait "$tpid" || true
cat "$WORK/tcpdump.log" >&2

size=$(stat -c %s "$OUT" 2> /dev/null || echo 0)
if [ "$size" -le 24 ]; then # 24 bytes = pcap header only
  fail "no packets captured on $IFACE (filter: ${FILTER:-none}): $(tail -n 3 "$WORK/tcpdump.log" | tr '\n' ' ')"
fi
echo "captured $size bytes (stopped by $reason)"

# ------------------------------------------------------------ upload
printf '%s' "${METADATA:-}" > "$WORK/metadata.json"
# Credentials go through a header file so they don't show up in the host's process list (hostPID).
umask 077
printf 'Authorization: Basic %s\n' "$(printf '%s:%s' "${ANALYZER_USERNAME:?}" "${ANALYZER_PASSWORD:?}" | base64 | tr -d '\n')" > "$WORK/auth"

if ! resp=$(curl -sS --fail-with-body --retry 3 --max-time 600 -H "@$WORK/auth" \
  -F "pcap=@$OUT;filename=${PCAP_NAME:-capture.pcap}" \
  -F "metadata=<$WORK/metadata.json" \
  -F "provider=${PROVIDER:-claude}" \
  -F "dry_run=${DRY_RUN:-false}" \
  -F "compare_previous=${COMPARE_PREVIOUS:-true}" \
  "$ANALYZER_URL/analyses/$ANALYSIS_ID/runs" 2>&1); then
  rm -f "$WORK/auth"
  fail "upload to pcap-analyzer failed: $(echo "$resp" | head -c 800)"
fi
rm -f "$WORK/auth"

run_id=$(echo "$resp" | jq -r '.id // empty' 2> /dev/null || true)
[ -n "$run_id" ] || fail "unexpected pcap-analyzer response: $(echo "$resp" | head -c 800)"
echo "submitted run $run_id"
jq -cn --argjson id "$run_id" --arg r "$reason" --argjson b "$size" \
  '{runId: $id, stopReason: $r, bytes: $b}' > "$TERM_LOG"

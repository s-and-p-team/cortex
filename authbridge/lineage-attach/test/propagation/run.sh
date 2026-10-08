#!/usr/bin/env bash
# Propagation matrix: one row per instrumented library, each proven against
# a real exchange. A client row makes one outbound call with the library to a
# header-echo sink; a server row serves one request with the framework and
# makes an outbound `requests` call to the sink from inside the handler. Each
# row is built as a stock-python probe image, baked with build-otel-shim.sh,
# and run four ways:
#   base      the un-baked image                       -> sink sees no traceparent
#   inert     baked, gate off                          -> sink sees no traceparent
#   on        baked, LINEAGE_PROPAGATE=1               -> sink sees a traceparent
#   carried   on, with a known inbound trace id        -> sink sees THAT trace id
# A client row gets its inbound context from a span the probe opens itself
# (INBOUND_TRACEPARENT); a server row gets it on the wire from driver.py. The
# gRPC row is both: the probe's server half reports the metadata it received
# and what the sink saw on its own outbound hop.
#
# Usage: ./run.sh [row ...]      (default: every row)     KEEP=1 keeps the images
# Needs: podman or docker (container-runtime.sh), host python3, network for pip.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
KIT="$(cd "${HERE}/../.." && pwd)"
. "${KIT}/container-runtime.sh"
TID=cde6dbb8b57de0ee569519a4084bde6e
INBOUND="00-${TID}-00f067aa0ba902b7-01"
NET=lineage-propagation
PREFIX=lineage-probe

# row -> "kind pip-packages" (a function, not an associative array: bash 3 hosts)
row_spec() {
  case "$1" in
    httpx)          echo "client httpx" ;;
    requests)       echo "client requests" ;;
    aiohttp_client) echo "client aiohttp" ;;
    urllib3)        echo "client urllib3" ;;
    urllib)         echo "client" ;;
    threading)      echo "client requests" ;;
    starlette)      echo "server starlette uvicorn requests" ;;
    fastapi)        echo "server fastapi uvicorn requests" ;;
    aiohttp_server) echo "server aiohttp requests" ;;
    flask)          echo "server flask requests" ;;
    django)         echo "server django requests" ;;
    falcon)         echo "server falcon requests" ;;
    pyramid)        echo "server pyramid requests" ;;
    tornado)        echo "server tornado requests" ;;
    grpc)           echo "rpc grpcio requests" ;;
    *) return 1 ;;
  esac
}
ORDER=(httpx requests aiohttp_client urllib3 urllib threading starlette fastapi aiohttp_server flask django falcon pyramid tornado grpc)
[ $# -gt 0 ] && ORDER=("$@")

run() { "$CONTAINER_TOOL" "$@"; }
log()  { printf '>> %s\n' "$*" >&2; }

cleanup() {
  run rm -f "${PREFIX}-sink" >/dev/null 2>&1 || true
  run network rm "$NET" >/dev/null 2>&1 || true
  [ "${KEEP:-0}" = 1 ] && return 0
  for row in "${ORDER[@]}"; do run rmi -f "${PREFIX}-${row}:latest" "${PREFIX}-${row}-otel:latest" >/dev/null 2>&1 || true; done
  run rmi -f "${PREFIX}-sink:latest" >/dev/null 2>&1 || true
}
trap cleanup EXIT

build_probe() {  # row pip...
  local row=$1; shift
  run build -q -f "${HERE}/Dockerfile.probe" --build-arg "PIP=$*" -t "${PREFIX}-${row}:latest" "${HERE}" >/dev/null
}

bake() {  # row; the bake's own output goes to a log the failure line names
  BAKE_LOG="${TMPDIR:-/tmp}/${PREFIX}-$1.bake.log"
  NO_KIND_LOAD=1 "${KIT}/build-otel-shim.sh" "${PREFIX}-$1:latest" "${PREFIX}-$1-otel:latest" >"$BAKE_LOG" 2>&1
}

# traceparent the sink (or server) reported: "-" when it reported none, "?"
# when the probe printed nothing at all (did not start, crashed, no answer)
seen() { python3 -c 'import json,sys
s=sys.stdin.read().strip(); print((json.loads(s).get("traceparent") or "-") if s else "?")' 2>/dev/null || echo "?"; }

verdict() {  # expectation seen-value  -> ok/FAIL
  case "$1" in
    absent)  [ "$2" = "-" ] ;;
    present) [ "$2" != "-" ] && [ "$2" != "?" ] ;;
    carried) [[ "$2" == 00-${TID}-* ]] ;;
  esac && echo ok || echo FAIL
}

client_case() {  # image gate inbound
  local img=$1 gate=$2 inbound=$3 args=()
  [ "$gate" = 1 ] && args+=(-e LINEAGE_PROPAGATE=1)
  [ -n "$inbound" ] && args+=(-e INBOUND_TRACEPARENT="$inbound")
  run run --rm --network "$NET" ${args[@]+"${args[@]}"} -e TARGET="http://${PREFIX}-sink:8000/" "$img" \
    python /probe/clients.py "$row" 2>/dev/null | seen
}

server_case() {  # image gate
  local img=$1 gate=$2 args=() name="${PREFIX}-${row}-srv"
  [ "$gate" = 1 ] && args+=(-e LINEAGE_PROPAGATE=1)
  [ "$row" = django ] && args+=(-e DJANGO_SETTINGS_MODULE=servers)
  run run -d --rm --name "$name" --network "$NET" ${args[@]+"${args[@]}"} -e SINK="http://${PREFIX}-sink:8000/" "$img" \
    python /probe/servers.py "$row" >/dev/null
  run run --rm --network "$NET" "${PREFIX}-sink:latest" python /probe/driver.py "http://${name}:8000/" "$INBOUND" 2>/dev/null | seen
  run rm -f "$name" >/dev/null 2>&1
}

rpc_case() {  # image gate inbound -> "metadata-seen sink-seen"
  local img=$1 gate=$2 inbound=$3 args=() name="${PREFIX}-${row}-srv"
  [ "$gate" = 1 ] && args+=(-e LINEAGE_PROPAGATE=1)
  run run -d --rm --name "$name" --network "$NET" ${args[@]+"${args[@]}"} -e SINK="http://${PREFIX}-sink:8000/" "$img" \
    python /probe/servers.py grpc >/dev/null
  [ -n "$inbound" ] && args+=(-e INBOUND_TRACEPARENT="$inbound")
  run run --rm --network "$NET" ${args[@]+"${args[@]}"} -e TARGET="${name}:8000" "$img" python /probe/clients.py grpc 2>/dev/null \
    | python3 -c 'import json,sys
s=sys.stdin.read().strip()
if not s: print("? ?")
else:
    d=json.loads(s); print(d.get("inbound") or "-", (d.get("sink") or {}).get("traceparent") or "-")' 2>/dev/null || echo "? ?"
  run rm -f "$name" >/dev/null 2>&1
}

main() {
  local fail=0 row spec kind pip base otel
  run network create "$NET" >/dev/null 2>&1 || true
  build_probe sink || { echo "sink image failed to build" >&2; exit 1; }
  run rm -f "${PREFIX}-sink" >/dev/null 2>&1
  run run -d --rm --name "${PREFIX}-sink" --network "$NET" "${PREFIX}-sink:latest" python /probe/sink.py >/dev/null \
    || { echo "the sink container failed to start" >&2; exit 1; }
  printf '%-15s %-7s %-8s %-8s %-8s %-8s\n' row kind base inert on carried
  for row in "${ORDER[@]}"; do
    spec="$(row_spec "$row")" || { printf '%-15s unknown row\n' "$row"; fail=1; continue; }
    read -r kind pip <<<"$spec"
    base="${PREFIX}-${row}:latest"; otel="${PREFIX}-${row}-otel:latest"
    if ! build_probe "$row" $pip; then printf '%-15s %-7s %s\n' "$row" "$kind" "probe image failed to build"; fail=1; continue; fi
    if ! bake "$row"; then printf '%-15s %-7s %s\n' "$row" "$kind" "bake refused or failed: see ${BAKE_LOG}"; fail=1; continue; fi
    case "$kind" in
      client)
        r1=$(verdict absent  "$(client_case "$base" 0 "")")
        r2=$(verdict absent  "$(client_case "$otel" 0 "")")
        r3=$(verdict present "$(client_case "$otel" 1 "")")
        r4=$(verdict carried "$(client_case "$otel" 1 "$INBOUND")") ;;
      server)
        r1=$(verdict absent  "$(server_case "$base" 0)")
        r2=$(verdict absent  "$(server_case "$otel" 0)")
        r3=n/a
        r4=$(verdict carried "$(server_case "$otel" 1)") ;;
      rpc)  # metadata = client half, sink = server half; both must agree
        read -r m s <<<"$(rpc_case "$base" 0 "")";        r1="$(verdict absent "$m")/$(verdict absent "$s")"
        read -r m s <<<"$(rpc_case "$otel" 0 "")";        r2="$(verdict absent "$m")/$(verdict absent "$s")"
        read -r m s <<<"$(rpc_case "$otel" 1 "")";        r3="$(verdict present "$m")/$(verdict present "$s")"
        read -r m s <<<"$(rpc_case "$otel" 1 "$INBOUND")"; r4="$(verdict carried "$m")/$(verdict carried "$s")" ;;
    esac
    printf '%-15s %-7s %-8s %-8s %-8s %-8s\n' "$row" "$kind" "$r1" "$r2" "$r3" "$r4"
    case "$r1$r2$r3$r4" in *FAIL*) fail=1 ;; esac
    [ "${KEEP:-0}" = 1 ] || run rmi -f "$base" "$otel" >/dev/null 2>&1
  done
  [ "$fail" = 0 ] && log "every row propagates" || log "FAIL: see the table"
  return "$fail"
}
main "$@"

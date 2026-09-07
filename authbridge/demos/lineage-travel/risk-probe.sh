#!/usr/bin/env bash
# risk-probe.sh — ride an existing travel trace with two PII-bearing calls,
# one to an internal-classified destination and one to an external-classified
# one, so the DG risk engine sees both classes inside a single app trace.
#
# The two calls go to the SAME in-cluster mock PSP; only the NAME the
# request carries differs:
#
#   internal: http://psp-mock:9091/charge
#             (cluster short name — no dot, structurally internal)
#   external: the same connection, but the request says
#             "Host: api.travel-partner.example" — the sidecar records the
#             request authority as lineage.peer.host, the whitelist does not
#             list that name, so the destination classifies external
#
# Destination classification is name-based (the risk engine's wildcard
# hostname whitelist over the recorded facts), so the same bytes over the
# same connection classify differently — that asymmetry IS the probe: both
# payloads must come back privacy-classified, and only the external one must
# draw an external-sharing risk decision (DG-001 when the payload carries
# PII).
#
# Both calls are sent from the demo-client pod (its sidecar records them)
# with a `traceparent` carrying the trace id of the demo turn, so they land
# under the same root as the travel conversation.
#
# Usage: ./risk-probe.sh [trace-id]
#        With no argument, the newest demo-client-rooted trace is taken from
#        the collector log (i.e. the last `run-demo.sh` turn).
set -euo pipefail
NS="${NS:-travel-advisor}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TRACE="${1:-}"
if [ -z "$TRACE" ]; then
    TRACE=$("$HERE/last-trace-id.sh")
    [ -n "$TRACE" ] || { echo "no demo-client trace found — run the demo first (run-demo.sh)" >&2; exit 1; }
fi
echo "riding trace: $TRACE"

probe() { # <label> [host-header]
    local label=$1 host=${2:-}
    local span; span=$(python3 -c 'import secrets; print(secrets.token_hex(8))')
    echo ">> $label: POST http://psp-mock:9091/charge ${host:+(Host: $host)}"
    kubectl -n "$NS" exec deploy/demo-client -c client -- python3 -c "
import json, urllib.request
# The card data, once as the mock PSP's own top-level fields (so it answers
# 200) and once as JSON-RPC tools/call arguments: the sidecar captures
# payloads through its protocol parsers only (a2a/mcp/inference — a plain
# HTTP body is metadata-only by design), and the mcp-parser is content-gated
# on any JSON-RPC body, surfacing exactly params.arguments as the captured
# input. The probe thus reads as what it simulates: a tool call carrying
# card data off somewhere.
card = {
    'pan': '4111 1111 1111 1111', 'expiry': '12/27', 'cvv': '123',
    'amount_cents': 320000, 'currency': 'usd', 'merchant': 'Atlas Air',
    'cardholder': 'Dana Cohen', 'email': 'dana.cohen@example.com',
    'note': 'risk-probe: deliberate PII in transit',
}
payload = dict(card, jsonrpc='2.0', id='1', method='tools/call',
               params={'name': 'charge_card', 'arguments': card})
headers = {'content-type': 'application/json',
           'traceparent': '00-$TRACE-$span-01'}
if '$host':
    headers['Host'] = '$host'
req = urllib.request.Request('http://psp-mock:9091/charge',
                             data=json.dumps(payload).encode(), headers=headers)
print('   status:', urllib.request.urlopen(req, timeout=30).status)
"
}

probe internal
probe external api.travel-partner.example:9091

echo
echo "trace id: $TRACE"
echo "then check, in order:"
echo "  ../lineage/show-trace.py $TRACE          # both probes inside the app trace"
echo "  http://dg.localtest.me:8080/ui/traces/$TRACE/spans   # spans arrived at DG"
echo "  http://dg.localtest.me:8080/ui/traces/$TRACE/flow    # the interaction graph"
echo "  the risk UI / risk API for this trace: both probe interactions"
echo "  privacy-classified; the external one carrying the external-sharing"
echo "  risk decision, the internal one not"

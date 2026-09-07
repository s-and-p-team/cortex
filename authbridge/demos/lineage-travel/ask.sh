#!/usr/bin/env bash
# ask.sh — the app's one scripted turn (plan + negotiate + book + pay), sent
# from the demo-client pod as a plain JSON-RPC `message/send` with a trace id
# of our choosing.
#
# Why not run-demo.sh? Two reasons, both lineage-mechanical, neither the
# app's fault: the app repo's script execs into the pod without naming a
# container (after the attach, envoy-proxy is first and the exec lands
# there), and its demo.py client STREAMS the reply (SSE), which the
# capturing sidecar buffers — the turn runs to completion inside the app,
# but the streamed reply reaches the client empty. The same turn as one
# non-streaming message/send comes back whole, and the sidecars record
# every hop either way. The message text below is demo.py's own USER_TURN,
# verbatim.
#
# Usage: ./ask.sh            (prints the trace id and the final answer)
set -euo pipefail
NS="${NS:-travel-advisor}"

trace_id="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
echo "trace id: ${trace_id}"

kubectl -n "$NS" exec deploy/demo-client -c client -- sh -c "python3 - <<'EOF'
import json, urllib.request, uuid
turn = (
    'Plan and book a trip:\n'
    '- country: Japan\n'
    '- city: Tokyo\n'
    '- month: October\n'
    '- dates: 2027-09-10 to 2027-09-15\n'
    '- passengers: 2\n'
    '- from_city: New York\n'
    '- to_city: Tokyo\n'
    '- guest_name: Maya Park\n'
    '- payment_account: acct_001\n'
    '- initial_budget: 3000\n'
    '- maximum_approval: 3500\n'
    'Follow all 7 steps of your script. Pass payment_account=acct_001 '
    'in your booking delegation message so booking-agent can have '
    'payment-agent process the charge. If booking-agent asks for '
    'approval up to \$3500, approve once. Return the final summary.'
)
body = json.dumps({'jsonrpc': '2.0', 'id': '1', 'method': 'message/send',
    'params': {'message': {'role': 'user', 'messageId': uuid.uuid4().hex,
        'contextId': uuid.uuid4().hex,
        'parts': [{'kind': 'text', 'text': turn}]}}}).encode()
req = urllib.request.Request('http://travel-advisor:8080/', data=body,
    headers={'content-type': 'application/json',
             'traceparent': '00-${trace_id}-0000000000000001-01'})
r = json.load(urllib.request.urlopen(req, timeout=580))
res = r.get('result', r)
parts = [p for a in res.get('artifacts') or [] for p in a.get('parts', [])]
state = (res.get('status') or {}).get('state', '?')
print('[state=%s]' % state)
print('answer:', ' '.join(p.get('text', '') for p in parts) or json.dumps(r)[:400])
EOF"
echo "trace id: ${trace_id}"

#!/usr/bin/env bash
# ask.sh — one A2A turn to the weather agent, sent from inside the cluster (a
# port-forward would bypass the sidecar) with a trace id of our choosing, so
# the spans it produces can be found by that id.
#
# The request is the A2A 0.3 JSON-RPC shape (`message/send`, `parts: [{kind:
# text}]`); the agent runs a2a-sdk 1.x and answers it through its 0.3
# compatibility routes. The result is a Task (answer in status.message or the
# artifacts) or a Message (answer in parts); both are read.
#
# Usage: ./ask.sh ["What is the weather in Paris?"]
#        NS=team1 SVC=weather-service PORT=8080 override the target.
#        TOKEN=<access token> sends it as `authorization: Bearer` — the user
#        the turn is asked by, once the sidecar's user gate is on (README
#        step 6; `token.sh` mints one). Without it the request is anonymous,
#        and a gated agent answers 401.
#        A turn is given --max-time 300 (curl); the trace exists even if the
#        answer arrives later than that.
set -euo pipefail
NS="${NS:-team1}"; SVC="${SVC:-weather-service}"; PORT="${PORT:-8080}"
question="${1:-What is the weather in Paris?}"
trace_id="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
body="$(python3 -c 'import json, sys, uuid
print(json.dumps({"jsonrpc": "2.0", "id": "1", "method": "message/send", "params": {"message": {
  "role": "user", "messageId": uuid.uuid4().hex, "parts": [{"kind": "text", "text": sys.argv[1]}]}}}))' "$question")"
echo "trace id: ${trace_id}"
# The bearer header only when TOKEN is set; the `${a[@]+...}` form keeps an
# empty array legal under `set -u` on bash 3.2 (macOS).
auth=()
[ -z "${TOKEN:-}" ] || auth=(-H "authorization: Bearer ${TOKEN}")
kubectl -n "$NS" run "ask-${trace_id:0:12}" --rm -i --quiet --restart=Never --image=curlimages/curl:8.11.1 -- \
  curl -sS --max-time 300 -H 'content-type: application/json' \
  -H "traceparent: 00-${trace_id}-0000000000000001-01" ${auth[@]+"${auth[@]}"} \
  -d "$body" "http://${SVC}:${PORT}/" \
  | python3 -c 'import json, sys
raw = sys.stdin.read()
try:
    r = json.loads(raw)
except ValueError:
    # curl failed (nothing came back) or the agent answered with non-JSON:
    # show what arrived, not a traceback; kubectl/curl said why above.
    sys.exit("no answer: " + (raw.strip()[:300] or "empty response — see the error above"))
if "error" in r and "plugin" in r:
    # The sidecar answered, not the agent: a gate plugin denied the request
    # (jwt-validation: no or invalid bearer token). No span exists for it.
    sys.exit("denied by the sidecar (%s): %s — %s" % (r["plugin"], r["error"], r.get("message", "")))
res = r.get("result", r)
parts = (res.get("status", {}).get("message", {}).get("parts", [])
         or [p for a in res.get("artifacts", []) for p in a.get("parts", [])]
         or res.get("parts", []))
print("answer:", " ".join(p.get("text", "") for p in parts) or json.dumps(r)[:300])'
echo "trace id: ${trace_id}   (kubectl -n rossoctl-system logs deploy/otel-collector | grep -c ${trace_id})"

#!/usr/bin/env bash
# run-turn.sh — one demo turn, from the demo-client pod's app container.
#
# The app repo's run-demo.sh execs into the pod without naming a container;
# once the lineage sidecar is attached, envoy-proxy is the pod's first
# container and that exec lands in the wrong one. Same command, with
# `-c client`. Pass-through args go to demo.py (e.g. --continue <ctx>).
set -euo pipefail
NS="${NS:-travel-advisor}"
kubectl -n "$NS" exec deploy/demo-client -c client -- \
    sh -c 'exec python3 /app/app/demo.py "$@"' -- "$@"

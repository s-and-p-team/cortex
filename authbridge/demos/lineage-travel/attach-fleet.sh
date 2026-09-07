#!/usr/bin/env bash
# attach-fleet.sh — bake the propagation shim onto the travel_advisor image
# and attach the lineage sidecar to every Deployment of the app. The app repo
# is untouched: one bake of its already-built image, one strategic-merge
# patch per Deployment, all of it the kit's (../../lineage-attach).
#
# Usage: ./attach-fleet.sh
# Requires: the app deployed (APP=travel_advisor bash deploy.sh in the app
# repo), the image present locally under $IMAGE, and SIDECAR_IMAGE /
# PROXY_INIT_IMAGE exported (RECIPE step 1).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT="${KIT:-$HERE/../../lineage-attach}"
NS="${NS:-travel-advisor}"
IMAGE="${IMAGE:-agent-examples-snp:latest}"
SHIMMED="${SHIMMED:-docker.io/library/agent-examples-snp-otel:latest}"
CAPTURE_IO="${CAPTURE_IO:-true}"

# The app lives in its own namespace, which the platform chart did not
# render an `envoy-config` ConfigMap into (it only renders team namespaces).
# The config is namespace-agnostic — copy it in from a platform namespace.
if ! kubectl -n "$NS" get cm envoy-config >/dev/null 2>&1; then
    src="${ENVOY_CONFIG_SOURCE_NS:-team1}"
    echo ">> copying envoy-config from ns/$src into ns/$NS"
    kubectl -n "$src" get cm envoy-config -o jsonpath='{.data.envoy\.yaml}' \
        | kubectl -n "$NS" create cm envoy-config --from-file=envoy.yaml=/dev/stdin
fi

KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-rossoctl}" "$KIT/build-otel-shim.sh" "$IMAGE"

attach() { # <deployment> <app container> [outbound ports to exclude]
    local d=$1 c=$2 exclude=${3:-}
    NAMESPACE="$NS" DEPLOY="$d" APP_CONTAINER="$c" APP_IMAGE="$SHIMMED" \
        CAPTURE_IO="$CAPTURE_IO" OUTBOUND_PORTS_EXCLUDE="$exclude" \
        "$KIT/sidecar-patch.sh"
}

# Leaves first, orchestrator last, external caller at the end: each agent
# resolves its peers' agent cards at process start, so by the time a caller
# rolls, everything it dials is already serving. (The sidecar itself is a
# native init sidecar, so an app can never race its own proxy either.)

# The seven tools: exclude the plaintext NON-HTTP store ports (Postgres 5432,
# SMTP 1025) per the RECIPE. MinIO (9000, S3 over HTTP) and the mock PSP
# (9091) stay captured on purpose — they are the hops the story is about.
attach search-destinations mcp 5432
attach create-booking      mcp 5432
attach get-payment-info    mcp 5432
attach send-notification   mcp 5432,1025
attach get-weather         mcp
attach get-flights         mcp
attach charge-card         mcp

# The four agents (all-HTTP outbound, nothing to exclude — their LLM, when
# HTTPS, is TLS passthrough on its own), then the external caller.
attach payment-agent  agent
attach research-agent agent
attach booking-agent  agent
attach travel-advisor agent
attach demo-client    client

echo
echo ">> fleet attached: 12 Deployments in ns=$NS (4 agents, 7 tools, demo-client)"
echo ">> back-out lines were printed by each attach above; keep them"

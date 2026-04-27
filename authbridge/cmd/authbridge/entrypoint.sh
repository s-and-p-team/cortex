#!/bin/bash
set -euo pipefail

# Envoy + authbridge entrypoint with process supervision.
# Both processes run in the background; the shell stays as PID 1.
# If either process exits, the other is killed and the container exits
# non-zero so Kubernetes restarts it.
#
# authbridge args are passed through from the container command/args.
# Envoy config is expected at /etc/envoy/envoy.yaml.

cleanup() {
  echo "[entrypoint] Received signal, shutting down..."
  kill "$AUTHBRIDGE_PID" "$TELEMETRY_PROCESSOR_PID" "$ENVOY_PID" 2>/dev/null || true
  wait
  exit 0
}
trap cleanup TERM INT

# Start authbridge (ext_proc gRPC server) in the background
echo "[entrypoint] Starting authbridge..."
/usr/local/bin/authbridge "$@" &
AUTHBRIDGE_PID=$!

# Start telemetry-processor (OTEL span emitter, ext_proc on :9091) in the background
echo "[entrypoint] Starting telemetry-processor..."
/usr/local/bin/telemetry-processor &
TELEMETRY_PROCESSOR_PID=$!

# Give processors a moment to start their gRPC listeners
sleep 2

# Start Envoy in the background
echo "[entrypoint] Starting Envoy..."
/usr/local/bin/envoy -c /etc/envoy/envoy.yaml \
  --service-cluster auth-proxy --service-node auth-proxy &
ENVOY_PID=$!

# Wait for the first child to exit. If any dies, restart the container.
wait -n "$AUTHBRIDGE_PID" "$TELEMETRY_PROCESSOR_PID" "$ENVOY_PID"
EXIT_CODE=$?
echo "[entrypoint] A process exited unexpectedly (exit code $EXIT_CODE), terminating container"
kill "$AUTHBRIDGE_PID" "$TELEMETRY_PROCESSOR_PID" "$ENVOY_PID" 2>/dev/null || true
wait
exit 1

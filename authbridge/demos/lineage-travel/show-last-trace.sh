#!/usr/bin/env bash
# show-last-trace.sh — trace id of the last demo turn, then its shape.
# The id comes from last-trace-id.sh; the shape from the weather demo's
# reader (one root, unstamped only at the entry, strays counted).
#
# Usage: ./show-last-trace.sh [show-trace.py args...]
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TRACE=$("$HERE/last-trace-id.sh")
[ -n "$TRACE" ] || { echo "no demo-client trace found — attach first (attach-fleet.sh), then run the demo (run-demo.sh)" >&2; exit 1; }

echo "trace id: $TRACE"
exec "$HERE/../lineage/show-trace.py" "$TRACE" "$@"

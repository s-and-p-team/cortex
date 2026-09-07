#!/usr/bin/env bash
# last-trace-id.sh — print the trace id of the newest demo-client-rooted
# trace in the collector log (the last `run-demo.sh` turn), nothing else.
# The demo client sends no traceparent; its sidecar mints the root
# (parent.source=none, contract v1.6), so the id exists only on the wire.
set -euo pipefail
kubectl -n rossoctl-system logs deploy/otel-collector | python3 -c '
import re, sys
best = None
for block in re.split(r"\n(?=Span #\d+)", sys.stdin.read()):
    if "lineage.role" not in block:
        continue
    attrs = dict(re.findall(r"-> ([\w.]+): Str\((.*)\)$", block, re.M))
    tid = re.search(r"Trace ID\s*:\s*(\w+)", block)
    start = re.search(r"Start time\s*:\s*(\S+ \S+)", block)
    if not (tid and start):
        continue
    if (attrs.get("lineage.self.id") == "demo-client"
            and attrs.get("lineage.direction") == "outbound"
            and attrs.get("lineage.role") == "request"
            and attrs.get("lineage.parent.source") in ("none", "wire")):
        if best is None or start.group(1) > best[0]:
            best = (start.group(1), tid.group(1))
print(best[1] if best else "")'

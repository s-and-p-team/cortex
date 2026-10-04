#!/usr/bin/env python3
"""Print the shape of one trace from the platform collector's debug log.

The stock collector prints every span it receives (debug exporter,
verbosity: detailed). This reads that log, keeps the sidecar's spans for one
trace id and lists them in time order — self id, direction, protocol, role,
where the parent came from, the peer — then says whether the shape is right:
one unstamped hop at the entry (an inbound: `wire` when the caller sent a
`traceparent`, `none` when it sent nothing), `tracestate` everywhere else, and
the app's own outbound calls *in this trace*. An entry alone is not a good
shape: it means the app's calls went to traces of their own, and those are
counted too.

Usage: ./show-trace.py <trace-id> [--since 10m] [--namespace rossoctl-system]

Exit status: 0 the good shape (one root, the app's calls inside), 1 no sidecar
spans for that id in the window (or the collector log could not be read), 2
the wrong shape (ENTRY ONLY or FRAGMENTED).
"""

import argparse
import collections
import re
import subprocess
import sys

ATTR = re.compile(r"-> ([\w.]+): Str\((.*)\)$", re.M)
TRACE = re.compile(r"Trace ID\s*:\s*(\w+)")
START = re.compile(r"Start time\s*:\s*(\S+ \S+)")

# Blocks the parser could not trust, reported once at the end: no parseable
# start time, or a lineage.* key seen twice with different values.
skipped_no_start = 0
ambiguous = 0


def facts(block: str) -> dict:
    """The block's attributes, robust to captured content.

    With capture_io on, input.value / output.value hold user content printed
    verbatim, newlines included; a line of it shaped like `-> lineage.role:
    Str(response)` would otherwise be read as a fact. The plugin emits every
    fact except lineage.parent.source BEFORE the captured value, and
    lineage.parent.source after it, so the first occurrence wins for the
    former and the last for the latter; a key seen twice with different
    values is counted as ambiguous."""
    global ambiguous
    attrs: dict = {}
    seen_twice = False
    for key, value in ATTR.findall(block):
        if key in attrs and attrs[key] != value:
            seen_twice = True
        if key == "lineage.parent.source":
            attrs[key] = value
        else:
            attrs.setdefault(key, value)
    if seen_twice:
        ambiguous += 1
    return attrs


def sidecar_blocks(log: str):
    """Yield the debug-exporter span blocks that carry a `lineage.*` attribute."""
    for block in re.split(r"\n(?=Span #\d+)", log):
        if "lineage.role" in block:
            yield block


def stray_outbound_traces(log: str, trace_id: str, first: str, last: str) -> int:
    """Traces other than trace_id that begin with an outbound hop that had no
    stamp to parent on (`wire` or `none`) — an app call that started a trace
    of its own — started while trace_id was in flight (between its first and
    last span)."""
    strays = set()
    for block in sidecar_blocks(log):
        attrs = facts(block)
        tid = TRACE.search(block)
        start = START.search(block)
        if (
            tid
            and start
            and tid.group(1) != trace_id
            and first <= start.group(1) <= last
            and attrs.get("lineage.role") == "request"
            and attrs.get("lineage.direction") == "outbound"
            and attrs.get("lineage.parent.source") in ("wire", "none")
        ):
            strays.add(tid.group(1))
    return len(strays)


def spans_for(log: str, trace_id: str):
    """The sidecar spans of one trace as rows, in start-time order.

    A block whose start time does not parse is skipped (and counted) rather
    than sorted first as an empty string: the first and last timestamps bound
    the stray window, and an empty one would open it to the start of the log."""
    global skipped_no_start
    rows = []
    for block in sidecar_blocks(log):
        tid = TRACE.search(block)
        if not tid or tid.group(1) != trace_id:
            continue
        start = START.search(block)
        if not start:
            skipped_no_start += 1
            continue
        attrs = facts(block)
        rows.append(
            (
                start.group(1),  # full timestamp: sorts across midnight
                attrs.get("lineage.self.id", ""),
                attrs.get("lineage.direction", ""),
                attrs.get("lineage.protocol", ""),
                attrs.get("lineage.role", ""),
                attrs.get("lineage.parent.source", ""),
                attrs.get("lineage.peer.host", "")[:30],
                attrs.get("lineage.outcome", ""),
                # The validated caller — present only on an inbound request
                # span behind a jwt-validation gate (README step 6).
                attrs.get("lineage.principal.sub", ""),
            )
        )
    rows.sort()
    return rows


def main() -> int:
    """Read the collector log, print the trace's rows and totals, judge the shape."""
    ap = argparse.ArgumentParser()
    ap.add_argument("trace_id")
    ap.add_argument("--since", default="10m", help="collector log window (kubectl --since)")
    ap.add_argument("--namespace", default="rossoctl-system")
    args = ap.parse_args()
    try:
        log = subprocess.run(  # nosec B603 B607 — fixed argv, no shell
            ["kubectl", "-n", args.namespace, "logs", "deploy/otel-collector", "--since", args.since],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except subprocess.CalledProcessError as exc:
        # kubectl's own message is the useful one (no such deployment, no
        # pods/log permission, no such namespace) — show it, not a traceback.
        print(f"kubectl logs failed (exit {exc.returncode}): {exc.stderr.strip()}", file=sys.stderr)
        return 1
    rows = spans_for(log, args.trace_id)
    if skipped_no_start:
        print(f"warning: {skipped_no_start} span block(s) of this trace had no start time; skipped", file=sys.stderr)
    if not rows:
        print(f"no sidecar spans for {args.trace_id} in the last {args.since}", file=sys.stderr)
        return 1
    print(f"{'time':<13}{'self':<17}{'dir':<10}{'proto':<11}{'role':<10}{'parent':<12}{'peer':<31}{'outcome':<11}user")
    for r in rows:
        print(f"{r[0][11:23]:<13}{r[1]:<17}{r[2]:<10}{r[3]:<11}{r[4]:<10}{r[5]:<12}{r[6]:<31}{r[7]:<11}{r[8]}")
    requests = [r for r in rows if r[4] == "request"]
    parents = collections.Counter(r[5] for r in requests)
    by_proto = collections.Counter(f"{r[2]} {r[3]}" for r in requests)
    strays = stray_outbound_traces(log, args.trace_id, rows[0][0], rows[-1][0])
    if ambiguous:
        print(
            f"warning: {ambiguous} span block(s) repeated a lineage.* key with different values;"
            " captured content may hold a fact-shaped line (first occurrence used, last for parent.source)",
            file=sys.stderr,
        )
    print()
    mix = ", ".join(f"{n} {k}" for k, n in sorted(by_proto.items()))
    print(f"{len(rows)} sidecar spans, {len(requests)} exchanges: {mix}")
    wire, stamped, none = parents.get("wire", 0), parents.get("tracestate", 0), parents.get("none", 0)
    print(f"parent.source: {wire} wire, {stamped} tracestate, {none} none")
    # Who asked: the principal is a fact of the entry's inbound request span
    # only — the hops behind it carry the agent's identity, not the user's.
    # A window holding only response spans has no entry to name.
    entry = requests[0] if requests else None
    who = entry[8] if entry and entry[2] == "inbound" else ""
    principal = f"user {who}" if who else "none — anonymous (no validated token on the inbound request)"
    print(f"principal on the entry: {principal}")
    print(f"traces begun by an unparented outbound hop while this one was in flight: {strays}")
    has_outbound = any(r[2] == "outbound" for r in requests)
    # The one unstamped hop must be the first request AND an inbound: an
    # unstamped outbound root is a stray trace, whatever else it holds.
    unstamped = parents.get("wire", 0) + parents.get("none", 0)
    one_root = unstamped == 1 and requests[0][5] in ("wire", "none") and requests[0][2] == "inbound"
    if one_root and has_outbound and strays == 0:
        print("shape: OK — one root, unstamped only at the entry, the app's calls are in this trace")
        return 0
    if not has_outbound:
        print("shape: ENTRY ONLY — nothing the app called landed here; its calls are the stray traces above")
    else:
        print("shape: FRAGMENTED — an unstamped non-entry hop, an outbound root or strays mark un-propagated calls")
    return 2


if __name__ == "__main__":
    sys.exit(main())

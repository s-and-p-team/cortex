# Lineage demo — the travel advisor fleet, with a risk probe

The `travel_advisor` app from
[`s-and-p-team/agent-examples-snp`](https://github.com/s-and-p-team/agent-examples-snp)
— 4 agents (travel-advisor → research-agent, booking-agent → payment-agent)
and 7 MCP tools over Postgres/MinIO/SMTP/HTTP, driven from a dedicated
demo-client pod — deployed **exactly as that repo ships it** (a clone, zero
edits), then given per-request lineage with the
[lineage attach kit](../../lineage-attach/README.md). On top of the app turn,
[`risk-probe.sh`](risk-probe.sh) rides the same trace with two PII-bearing
calls — one internally-classified destination, one externally-classified —
giving the DG risk engine both classes inside one app trace.

This is the bigger sibling of the [weather demo](../README.md): read that one
first — the six-step shape (deploy plain → attach → look → switch propagation
on → look again → back out) is the same and is not repeated here. What this
page adds is a real fleet (12 Deployments, one shared image), a naked app
that takes the kit's **shim** path rather than an own-instrumentation switch,
and the risk probe.

## Prerequisites

Everything the weather demo lists (platform on kind `rossoctl`, a sidecar
image carrying cortex #761, `SIDECAR_IMAGE`/`PROXY_INIT_IMAGE` exported),
plus:

- A clone of the app repo, and its own prerequisites (`README-agent.md`
  there): `git clone https://github.com/s-and-p-team/agent-examples-snp`.
- An LLM the agents can reach over **plaintext HTTP** if you want the
  inference hops captured (the repo's default LLM is an HTTPS gateway —
  fine functionally, but TLS passthrough records no LLM hop). Default
  override below: Ollama on the host with `qwen2.5:7b`.
- For the risk part: the DG service consuming this collector's
  `traces/data_governance` pipeline, running the `sidecar_interactions`
  processor and the risk engine (lab-data-governance branch `risk-dev-L`),
  with `CAPTURE_IO=true` at attach time (the default in
  [`attach-fleet.sh`](attach-fleet.sh)) so payloads reach classification.

Run everything from this directory.

## 1. Deploy the app, plain

In the app clone (naked is that repo's default — telemetry is opt-in there,
and we deliberately do not opt in; the kit provides propagation instead):

```sh
APP=travel_advisor bash deploy.sh
APP=travel_advisor bash run-demo.sh      # sanity: a full turn, no lineage yet
```

Optional, for captured LLM hops — point the agents at a plaintext LLM by env
only (the clone stays pristine); podman kind resolves the host as
`host.containers.internal`, docker kind as `host.docker.internal`:

```sh
for d in travel-advisor research-agent booking-agent payment-agent; do
  kubectl -n travel-advisor set env deploy/$d \
    LLM_URL=http://host.containers.internal:11434/v1 LLM_MODEL=qwen2.5:7b
done
```

## 2. Attach lineage to the fleet

```sh
./attach-fleet.sh
```

One bake (every app pod runs the same `agent-examples-snp:latest` image; the
naked image brings no instrumentation, so the shim's interlock accepts it),
then one `sidecar-patch.sh` per Deployment — 4 agents, 7 tools, demo-client.
The app's namespace is its own, which the platform chart rendered no
`envoy-config` into; the script first copies that ConfigMap in from `team1`
(it is namespace-agnostic; override the source with
`ENVOY_CONFIG_SOURCE_NS`).
The tool pods that speak plaintext non-HTTP to their stores get
`OUTBOUND_PORTS_EXCLUDE` (Postgres 5432, SMTP 1025); MinIO and the mock PSP
are HTTP and stay captured. All 12 pods come back `2/2`.

## 3. One turn, one trace

```sh
./ask.sh                                 # prints the trace id, runs the scripted turn
../lineage/show-trace.py <trace-id>      # the shape
```

`ask.sh` sends the app's own scripted turn (demo.py's `USER_TURN`, verbatim)
from the demo-client pod as one non-streaming `message/send`, with a trace id
of our choosing. Two lineage-mechanical reasons not to use the app's
`run-demo.sh` here (neither is the app's fault, both are explained in
`ask.sh`'s header): the app's script execs into the pod without naming a
container (post-attach, envoy-proxy is first), and its client STREAMS the
reply, which the sidecar's body pipeline buffers — the turn completes inside
the app but the streamed reply reaches the client empty.

The one trace holds the whole conversation: the A2A entry (`wire` — ask.sh
minted the trace), the agent-to-agent consultations, every MCP handshake and
tool call, the LLM calls, the MinIO read, the PSP charge — outbound at the
caller and inbound at the callee, `tracestate` everywhere after the entry.
Pass: `shape: OK — one root, unstamped only at the entry`.

(`run-turn.sh` and `show-last-trace.sh`/`last-trace-id.sh` remain for the
minted-root variant: a turn driven by the app's own demo.py — fine before
the attach, and its sidecar mints the root after it — with the id recovered
from the collector log.)

## 4. The risk probe

```sh
./risk-probe.sh <trace-id>     # the id ask.sh printed (defaults to the newest turn)
```

Two more calls from the demo-client pod, both carrying the turn's trace id in
`traceparent`, both POSTing the same PII payload (PAN, CVV, cardholder,
email) over the same connection to the in-cluster mock PSP — but the request
names its destination differently:

| call | what the request says | classifies |
|---|---|---|
| internal | `Host: psp-mock:9091` (the URL as-is) | internal (a short name has no dot — structurally in-cluster) |
| external | `Host: api.travel-partner.example:9091` | external (the sidecar records the request authority as `lineage.peer.host`; the whitelist does not list that name) |

Same bytes, same connection, different names — destination classification is
name-based over the recorded facts, and that asymmetry is the probe.
Expected on the DG side, all within the one app trace:

- both probe exchanges appear as interactions with their payloads
  **privacy-classified** (PII found);
- the **external** one draws the external-sharing risk decision (DG-001,
  `pii_to_untrusted_external`: PII + `event_type=external_sharing` +
  `UNTRUSTED_EXTERNAL`) — risk level per the shipped catalog;
- the **internal** one draws no external-sharing rule — `internal_sharing`,
  the policy's fallback decision.

Where to look: `http://dg.localtest.me:8080/ui/traces/<id>/spans` (arrival),
`…/flow` (the interaction graph), and the risk UI/API for the trace's risk
levels and triggered rules.

## 5. Back out

Each attach printed its back-out line (a `rollout undo --to-revision` plus a
ConfigMap delete); run them, or tear the app down entirely in the clone:
`APP=travel_advisor bash undeploy.sh`. The step-1 `set env` rolls back with
`kubectl -n travel-advisor set env deploy/<d> LLM_URL- LLM_MODEL-`.

## Files

| file | what |
|---|---|
| `attach-fleet.sh` | the kit, applied to the whole app: one bake + 12 attaches (leaves first), with the per-store port exclusions |
| `ask.sh` | the app's scripted turn as one non-streaming `message/send`, trace id chosen and printed |
| `risk-probe.sh` | the two PII calls riding the app trace, one per destination class |
| `run-turn.sh` | the app's own demo.py, exec'd into the right container |
| `last-trace-id.sh` / `show-last-trace.sh` | trace id of the last demo.py turn (minted root), and its shape |

The app is not here — it stays in its own repo, unmodified; this directory
holds only the attach loop and the two readers/probes.

## If it does not work

The weather demo's [table](../README.md#if-it-does-not-work) covers the
lineage side. Travel-specific:

| symptom | cause |
|---|---|
| the turn fails before any lineage question | the app itself — follow `README-agent.md` in the app repo (stores seeded? LLM reachable? `kubectl -n travel-advisor get pods`) |
| `run-demo.sh` works but `show-last-trace.sh` finds no trace | the fleet is not attached (step 2), or the collector restarted since the turn |
| the trace fragments (strays > 0) | a pod rolled after the attach and lost the shimmed image — re-run `attach-fleet.sh` for that Deployment |
| probes captured but never classified | `CAPTURE_IO` was not `true` at attach time, or the DG consumer is not on `risk-dev-L` |
| both probes classify external | the internal call's short name did not resolve — check it ran in-namespace (`psp-mock` resolves only from `travel-advisor`) |

# Lineage demo — the weather agent and its tool, with per-request lineage

The [Weather Agent](../weather-agent/demo-ui.md) pair from `rossoctl/examples`
— an A2A agent that asks an LLM and calls one MCP tool — deployed plain, then
given per-request lineage with the [lineage attach kit](../../deploy/lineage-attach/README.md)
and nothing else. Eight steps. You will see the same turn twice: first as
**19 separate traces** (the entry alone and each of the app's 18 calls in a
trace of its own, because the app does not carry `traceparent`), then as
**one trace of 70 spans** with one root, after the
app's own propagation is switched on. Nothing about the app is edited except
one environment variable that the app itself defines. Then the same turn a
third time, **asked by a named user**: the agent's sidecar validates the
caller's token and the trace's root caller becomes that person — from the
command line in step 6, from the platform UI's chat in step 7.

Read [the kit's README](../../deploy/lineage-attach/README.md) for what the spans
carry and [DESIGN](../../deploy/lineage-attach/DESIGN.md) for why propagation is the
app's job; this page is only the walk-through.

## Prerequisites

- The rossoctl platform on kind (`rossoctl` cluster, Kubernetes 1.29 or newer —
  the kit attaches the sidecar as a native sidecar), namespace `team1` with
  its platform-rendered `envoy-config` ConfigMap, and the platform collector
  (`deploy/otel-collector` in `rossoctl-system`, stock `debug` exporter).
- The sidecar images: the kit's defaults are the published release
  `ghcr.io/rossoctl/cortex/{authbridge-envoy,proxy-init}:v0.8.1`, which the
  node pulls on first use. (To run a build of this tree instead,
  [RECIPE step 1](../../deploy/lineage-attach/RECIPE.md#1-build-the-sidecar-from-source-optional)
  builds and loads it and exports `SIDECAR_IMAGE`/`PROXY_INIT_IMAGE`.) For the
  whole session, in this directory:

  ```sh
  export KIT=../../deploy/lineage-attach
  ```
- An LLM the agent can reach over **plaintext HTTP** (an HTTPS LLM is TLS
  passthrough: the sidecar records no hop for it). Default: Ollama on the host
  with `qwen2.5:7b` (`ollama pull qwen2.5:7b`); edit `k8s/weather.yaml`'s
  `weather-llm` ConfigMap for anything else.
- Egress from the cluster to `https://wttr.in`, which the tool queries.
- `kubectl` and `python3` on the host (`ask.sh`, `show-trace.py`).
- For steps 6 and 7 only: the platform's Keycloak (realm `rossoctl`, reachable
  from the host at `http://keycloak.localtest.me:8080`) and its admin Secret
  `keycloak-initial-admin` in namespace `keycloak`, which `setup-keycloak.sh`
  reads; a realm user to ask as (the platform's realm init creates `dev-user`
  with password `dev-user`). Step 7 also needs the platform UI
  (`http://rossoctl-ui.localtest.me:8080`) and its Helm chart source.
- Permissions, all free to a kind admin: `ask.sh` creates a pod in `team1`;
  `show-trace.py` gets `deployments` and reads `pods/log` in `rossoctl-system`;
  steps 2, 4 and 6 get and patch Deployments (step 2 with a server-side dry
  run first) and watch the rollout, and steps 2, 6 and 8 get, create or delete
  ConfigMaps, in `team1`; step 6 reads the Keycloak admin Secret and writes to
  the realm as its admin; step 7 creates (step 8 deletes) an `AgentRuntime` in
  `team1` and runs `helm upgrade` (or `kubectl set env`) in `rossoctl-system`.

Run everything from this directory.

## 1. Deploy the pair, plain

```sh
kubectl apply -f k8s/weather.yaml
kubectl -n team1 rollout status deploy/weather-tool && kubectl -n team1 rollout status deploy/weather-service
./ask.sh "What is the weather in Paris?"
```

`k8s/weather.yaml` is the two stock images (`weather_service`, `weather_tool`)
as two Deployments and two Services — no `AgentRuntime`, no platform sidecar,
no auth. `ask.sh` sends one A2A `message/send` from a pod inside the cluster
(a port-forward would bypass the sidecar) with a `traceparent` whose trace id
it prints. Pass: an `answer:` line with the weather. Nothing is captured yet:
no sidecar is attached. (The tool's own OTel spans do reach the collector
from step 1 — its code defaults the endpoint — but those are the app's spans,
not lineage.)

## 2. Attach lineage (capture)

```sh
for d in weather-tool weather-service; do NAMESPACE=team1 DEPLOY=$d CAPTURE_IO=true $KIT/sidecar-patch.sh; done
```

Pass — each prints, in this order (rollout progress lines omitted):

```
configmap/authbridge-lineage-config-<name> created
deployment.apps/<name> patched
>> back out: kubectl -n team1 patch deploy/<name> --type strategic -p '<the reverse patch>' && kubectl -n team1 delete cm authbridge-lineage-config-<name>
deployment "<name>" successfully rolled out
>> lineage sidecar attached to deploy/<name> (self_id=<name>, ns=team1)
```

Two `NOTE:` blocks precede that on stderr: the sidecar records every hop but
attribution is the app's job (which is what steps 3 to 5 show), and
`CAPTURE_IO=true` sends parsed content to the collector over plain gRPC
(in-cluster here). That is the whole attachment: a ConfigMap and a strategic-merge patch per Deployment, both
generated by the kit. Both pods are now `2/2`. `CAPTURE_IO=true` is the demo's
choice, not the kit's default: the spans then carry the question, the tool
arguments and the prompts, so the trace reads as a story. Demo only — with the
stock `debug` exporter that content lands in the collector's pod log, readable
by anyone with `pods/log` in `rossoctl-system`, for the log's lifetime. The
back-out line is right at any later time; step 6 uses it.

## 3. One turn — every hop alone

```sh
./ask.sh "What is the weather in Paris?"      # prints: trace id: <id>
./show-trace.py <id>
```

`show-trace.py` reads the collector's log and lists the sidecar spans of one
trace. Measured:

```
2 sidecar spans, 1 exchanges: 1 inbound a2a
parent.source: 1 wire, 0 tracestate, 0 none
traces begun by an unparented outbound hop while this one was in flight: 18
shape: ENTRY ONLY — nothing the app called landed here; its calls are the stray traces above
```

The sidecar saw everything the turn did — 35 exchanges: the A2A entry, 16 MCP
exchanges to the tool (session handshakes, tool listing, the call), 2 LLM
calls, and the tool's 16 inbound sides — and recorded all 70 spans. But the
app forwarded no `traceparent`, so the entry is alone in your trace and each
of the app's 18 calls started a trace of its own: its sidecar found nothing on
the wire to parent on (`parent.source=none`), forwarded a `traceparent` of its
own making, and the tool's side of each MCP call joined *that* trace — 19
traces, each internally consistent and each useless, because nothing links a
call to the question that caused it. This is the case DESIGN calls *the one
that looks fine and is not*: count spans and it passes; read the shape and it
fails. (The counts are one run's — the LLM may plan a turn differently and
add or drop an MCP exchange; the shape lines are what hold from run to run.)

## 4. Switch the app's propagation on

The weather agent ships its own OpenTelemetry setup, activated by one
variable it defines: when `OTEL_EXPORTER_OTLP_ENDPOINT` is set it extracts the
inbound `traceparent` and instruments `httpx`, so its LLM and tool calls carry
it. Point it at the platform collector's OTLP/HTTP receiver — port 8335 on the
stock chart, not 4318 — on the app container only:

```sh
kubectl -n team1 set env deploy/weather-service -c agent OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector.rossoctl-system.svc.cluster.local:8335
kubectl -n team1 rollout status deploy/weather-service
```

Three collector ports are in play and two of them are right: the apps export
OTLP/HTTP to `8335`, the plugin exports OTLP/gRPC to `4317` (the kit's
default `OTEL_ENDPOINT`), and the Service's `4318` has nothing behind it on
the stock chart. Both apps' own exports go out through their lineage sidecars
without an `OUTBOUND_PORTS_EXCLUDE`; that works because the collector's host
is on the plugin's default `bypass_hosts`, so the sidecar records no span for
them.

> **Why not the kit's shim here?** Because the interlock refuses this image,
> correctly: after `podman pull ghcr.io/rossoctl/examples/weather_service:latest`
> (the interlock probes a local image; an absent one is refused with a
> different message), `$KIT/build-otel-shim.sh ghcr.io/rossoctl/examples/weather_service:latest`
> exits 3 with `REFUSING to bake …: it already instruments httpx`. An app that
> brings its own instrumentation gets its own switch; the shim is for the app
> that brings none ([RECIPE step 2](../../deploy/lineage-attach/RECIPE.md#2-bake-the-propagation-shim-onto-the-app-image-once-per-image)).
> The tool image bakes, but it does not need to: its one call that matters is
> HTTPS to `wttr.in`, which the sidecar passes through unseen, and its own
> OTLP export (the tool's code defaults the endpoint to the collector's 8335;
> `k8s/weather.yaml` states it) is bypassed as above, so capture is all it
> needs.

## 5. The same turn — one trace

```sh
./ask.sh "What is the weather in Paris?"
./show-trace.py <id>
```

Measured:

```
70 sidecar spans, 35 exchanges: 1 inbound a2a, 16 inbound mcp, 2 outbound inference, 16 outbound mcp
parent.source: 1 wire, 34 tracestate, 0 none
traces begun by an unparented outbound hop while this one was in flight: 0
shape: OK — one root, unstamped only at the entry, the app's calls are in this trace
```

The table above those lines is the turn, hop by hop, in time order: the A2A
entry (`wire` — the caller minted the trace), then each MCP exchange seen
twice (outbound at the agent, inbound at the tool, both `tracestate`), the two
LLM calls (`inference`, peer `host.containers.internal:11434`), and the A2A
response last. The apps' own spans arrive in the same trace too — the agent's
A2A server, LangChain and `openai.chat` spans and its `httpx` `POST`s, the
tool's `tools/list` and `tools/call` — 82 of them on this turn, 78 from the
agent and 4 from the tool; the sidecar's are the ones with `lineage.*`
attributes.

## 6. Who asked — the user on the entry hop

Every row above names a workload. None names the person: the entry's `user`
column is empty and the data-governance consumer files the trace's root caller
as `client:(unknown)`. The plugin emits `lineage.principal.sub` — the `sub`
claim of the caller's token — only when a gate plugin ahead of it validated
that token; it never infers who called from an address (the wire contract:
"raw identity facts, never inferred"). So two things have to be true: the
caller must present a token that **names** a user, and the agent's sidecar
must **validate** it.

**The demo's client, once.** `setup-keycloak.sh` creates one public client,
`lineage-demo`, that allows the password grant so a token can be minted from a
terminal (the UI's own client refuses that grant, correctly). First, though,
it checks that the realm can name a user at all: since Keycloak 25 the `sub`
claim rides on the `basic` client scope, and a rossoctl realm imported before
the fix for [rossoctl#2446](https://github.com/rossoctl/rossoctl/issues/2446)
has no such scope — every token it mints, the UI's included, has no `sub`. On
such a realm the script stops and prints the realm-wide change it would make;
`APPLY_STOPGAP_2446=1` lets it make it, labelled as the stopgap it is. On a
realm installed with the fix it finds the scope and moves on.

```sh
./setup-keycloak.sh                        # on an unfixed realm: prints the plan, exit 3
APPLY_STOPGAP_2446=1 ./setup-keycloak.sh   # applies it, then the demo client
```

Measured on a realm without the fix — the refusal, the apply, then a plain
re-run (idempotent):

```
realm rossoctl: no basic client scope among the realm defaults — tokens carry no sub (rossoctl#2446)
  stopgap for rossoctl#2446 NOT applied — it would, realm-wide: create client scope basic (sub mapper),
  make it a realm default, and attach it to these existing clients: rossoctl.
  Re-run with APPLY_STOPGAP_2446=1 to make that change. Nothing was written.
```

```
realm rossoctl: no basic client scope among the realm defaults — tokens carry no sub (rossoctl#2446)
  stopgap: client scope basic created (sub mapper)
  stopgap: client scope basic is now a realm default (clients created from here on carry sub)
  stopgap: client rossoctl: basic scope attached
client lineage-demo: created (public, password grant)
client lineage-demo: basic scope attached (its tokens name the user)
```

and the plain re-run (the realm now carries the fix):

```
realm rossoctl: client scope basic is a realm default — stopgap for rossoctl#2446 not needed
client lineage-demo: present
client lineage-demo: basic scope attached (its tokens name the user)
```

**The gate, on the agent only.** Re-attach `weather-service` with the three
`AUTH_*` knobs — back it out first (the kit refuses to patch over its own
sidecar), then attach with the issuer, and the JWKS URL the sidecar can reach
from inside the cluster (`keycloak.localtest.me` is the pod's own loopback
there). The tool keeps its step-2 attachment: an agent's call to a tool
carries no user token, so a gate on the tool would deny the agent.

```sh
kubectl -n team1 patch deploy/weather-service --type strategic -p "$(EMIT=undo NAME=weather-service NAMESPACE=team1 $KIT/attach-lineage.sh)" \
  && kubectl -n team1 delete cm authbridge-lineage-config-weather-service
NAMESPACE=team1 DEPLOY=weather-service CAPTURE_IO=true \
  AUTH_ISSUER=http://keycloak.localtest.me:8080/realms/rossoctl \
  AUTH_JWKS_URL=http://keycloak-service.keycloak.svc:8080/realms/rossoctl/protocol/openid-connect/certs \
  $KIT/sidecar-patch.sh
```

A third `NOTE:` precedes the attach on stderr: every inbound request to
`weather-service` must now carry a bearer token from that issuer or is denied
with 401. Step 4's variable survives the re-attach (the patch touches only
what it adds), so the turn stays one trace.

**The turn, anonymous and named.** The same question twice:

```sh
./ask.sh "What is the weather in Paris?"
TOKEN=$(./token.sh dev-user dev-user) ./ask.sh "What is the weather in Paris?"
./show-trace.py <id>
```

Measured — the anonymous turn is refused by the sidecar before the agent sees
it, and **no span exists for it** (the pipeline stops at the gate; the contract's
"Scope of denied"), so its trace id finds nothing:

```
denied by the sidecar (jwt-validation): auth.unauthorized — missing Authorization header
```

`token.sh` says on stderr whom its token names — `user: dev-user  sub:
044dff09-…` — and the named turn answers as before. `show-trace.py` now fills
the `user` column on the entry row and adds one line to the summary:

```
time         self             dir       proto      role      parent      peer                           outcome    user
09:44:12.182 weather-service  inbound   a2a        request   wire                                                  044dff09-1804-4c48-b29e-a4aa9787d359
09:44:12.342 weather-service  outbound  mcp        request   tracestate  weather-tool-mcp:8000
…
70 sidecar spans, 35 exchanges: 1 inbound a2a, 16 inbound mcp, 2 outbound inference, 16 outbound mcp
parent.source: 1 wire, 34 tracestate, 0 none
principal on the entry: user 044dff09-1804-4c48-b29e-a4aa9787d359
traces begun by an unparented outbound hop while this one was in flight: 0
shape: OK — one root, unstamped only at the entry, the app's calls are in this trace
```

The user is a fact of the **entry** request span only. The 34 hops behind it
carry the agent's identity, not the user's — the agent calls the tool and the
LLM as itself; what links those calls to the person is the trace. The value is
the token's `sub` as Keycloak minted it, an opaque UUID: a display name is a
lookup against the IdP, not a span attribute (the plugin emits `sub` and the
client id `azp`, nothing else — see the kit's README, "The user").

On a platform whose collector feeds the data-governance service, the same
trace derives with the person as its root caller. Measured on this turn, from
the `entities` and `interactions` tables (19 interactions, 1 root):

```
user   user:044dff09-1804-4c48-b29e-a4aa9787d359
agent  agent:team1/weather-service
tool   tool:team1/weather-tool
llm    llm:host.containers.internal:11434/qwen2.5:7b
root:  044dff09-1804-4c48-b29e-a4aa9787d359 → team1/weather-service
```

## 7. The same, from the platform UI

The platform UI's chat forwards the signed-in user's `Authorization` header to
the agent as-is (`rossoctl/backend/app/routers/chat.py`), so once the UI
authenticates its users, a chat turn is exactly the named turn of step 6 —
nothing on the agent changes. Three things make it so.

**UI authentication on.** The platform ships it off on kind (`ui.auth.enabled:
false`); the chart value turns it on, which renders the `ENABLE_AUTH` env on
the backend and a one-shot Job that registers the UI's Keycloak client
(`rossoctl`, a public SPA client with PKCE), creates the demo users `bob`
(viewer) and `alice` (operator; chat needs operator) and writes the
`rossoctl-ui-oauth-secret` the backend reads. From the chart source at the
installed version:

```sh
helm -n rossoctl-system upgrade rossoctl charts/rossoctl --reuse-values --set ui.auth.enabled=true
```

(On a cluster whose live render has drifted from the chart, the same two
effects by hand: `helm template … --set ui.auth.enabled=true -s templates/ui-oauth-secret-job.yaml | kubectl apply -f -`,
wait for the Job, then `kubectl -n rossoctl-system set env deploy/rossoctl-backend ENABLE_AUTH=true`.)
Pass: `curl http://rossoctl-ui.localtest.me:8080/api/v1/auth/config` answers
`"enabled":true` with `"client_id":"rossoctl"`.

**The UI's client names the user too.** Either order works. A client the Job
creates *after* step 6 inherits the realm default (measured: its default
scopes `basic email openid profile roles rossoctl-platform-audience
web-origins`); a client that already existed when step 6 ran is what the
stopgap's `STOPGAP_CLIENTS` is for (measured above: `stopgap: client rossoctl:
basic scope attached`). The users' next sign-in mints a token with `sub`;
nothing to re-run.

**The agent appears in the UI.** The UI lists a workload only when it carries
the `rossoctl.io/type=agent` label, and an admission policy lets nobody but the
operator set it. The CR asks the operator to adopt the running Deployment:

```sh
kubectl apply -f k8s/weather-agentruntime.yaml
kubectl -n team1 get agentruntime weather-service      # READY True
kubectl -n team1 rollout status deploy/weather-service
```

The operator stamps the label and rolls the pod once. `k8s/weather.yaml`
carries `rossoctl.io/inject: disabled` on the pod template for this moment: it
is the documented opt-out from the operator's own sidecar injection, so the
adopted pod comes back `2/2` with the kit's sidecar as its only one (measured:
init containers `proxy-init envoy-proxy`, label `rossoctl.io/type: agent` on
both the Deployment and its template).

Then, in a browser: `http://rossoctl-ui.localtest.me:8080`, sign in as `alice`
(password `rossoctl2`, the Job's default), **team1 → weather-service → chat**,
ask for the weather. What the browser does is one request the terminal can
also make, and that is how this was measured:

```sh
TOKEN=$(./token.sh alice rossoctl2)
curl -s -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"message":"What is the weather in Berlin?"}' \
  http://rossoctl-ui.localtest.me:8080/api/v1/chat/team1/weather-service/send
```

The UI sends no `traceparent`, so the sidecar restarts one and the entry's
parent is `none` rather than `wire` — the id is in the collector log, keyed by
the user:

```sh
./show-trace.py "$(kubectl -n rossoctl-system logs deploy/otel-collector --since 10m \
  | grep -B60 'lineage.principal.sub: Str(<alice sub>)' | grep -o 'Trace ID *: [0-9a-f]*' | tail -1 | awk '{print $NF}')"
```

Measured:

```
70 sidecar spans, 35 exchanges: 1 inbound a2a, 16 inbound mcp, 2 outbound inference, 16 outbound mcp
parent.source: 0 wire, 34 tracestate, 1 none
principal on the entry: user 818e6062-3535-417a-942a-adfed87dcf10
shape: OK — one root, unstamped only at the entry, the app's calls are in this trace
```

`818e6062-…` is alice's `sub`. (The backend's chat reply read `No response
from agent` on this platform version — its reading of the A2A `Task` answer,
not the turn: the agent answered, the spans say so. The platform fix is in
the rossoctl repo, not here.)

## 8. Back out

Steps 6 and 7 first, in reverse: the AgentRuntime (the operator removes the
label it stamped), then UI auth if you turned it on (`--set
ui.auth.enabled=false`, or `set env deploy/rossoctl-backend ENABLE_AUTH=false`;
the Keycloak client, users and Secret it created are harmless to leave). The
realm's `basic` scope and `lineage-demo` client stay — a realm that mints
`sub` is the correct state, not a demo artifact.

```sh
kubectl delete -f k8s/weather-agentruntime.yaml
```

Then run the two back-out lines step 2 printed (step 6 re-printed the agent's).
Each is a strategic-merge reverse
patch that deletes, by name, exactly what the attach added, then deletes the
ConfigMap; it is right at any later revision, so the roll step 4 caused does
not matter. If the printed lines are gone, the kit regenerates them:

```sh
for d in weather-tool weather-service; do
  kubectl -n team1 patch deploy/$d --type strategic -p "$(EMIT=undo NAME=$d NAMESPACE=team1 $KIT/attach-lineage.sh)" \
    && kubectl -n team1 delete cm authbridge-lineage-config-$d
done
kubectl -n team1 set env deploy/weather-service -c agent OTEL_EXPORTER_OTLP_ENDPOINT-
```

Pass: `kubectl -n team1 get pods` shows both pods `1/1` again. The last line
removes step 4's variable, so the agent is plain again too. Then the app:
`kubectl delete -f k8s/weather.yaml`.

## Files

| file | what |
|---|---|
| `k8s/weather.yaml` | the pair, plain: two Deployments, two Services, one ConfigMap for the LLM |
| `k8s/weather-agentruntime.yaml` | step 7: the operator adopts the agent so the platform UI lists it |
| `ask.sh` | one A2A turn from inside the cluster with a chosen trace id; `TOKEN=` sends it as a user |
| `setup-keycloak.sh` | step 6, once per cluster: the `lineage-demo` client; the labelled rossoctl#2446 stopgap when the realm mints no `sub`; idempotent |
| `token.sh` | a user's access token on stdout (password grant on `lineage-demo`); whom it names and its `iss`/`aud` on stderr |
| `show-trace.py` | the shape of one trace from the collector log, with a verdict; exit 0 only for one root with the app's calls inside it, 1 for no spans, 2 for the wrong shape |

Everything that attaches lineage is the kit's; this directory holds only the
application and the two readers.

## If it does not work

| symptom | cause |
|---|---|
| `ask.sh` prints no answer, or the agent logs `Cannot connect to MCP` | the tool is not ready, or `MCP_URL` in `k8s/weather.yaml` does not match the Service name |
| the answer is an LLM error | `weather-llm` ConfigMap: the base URL is not reachable from a pod (podman kind: `host.containers.internal`; docker kind: `host.docker.internal`), or the model is not pulled |
| `show-trace.py` says `no sidecar spans for … in the last 10m` | most often the window: `--since` defaults to `10m` and a turn can take minutes — pass `--since 1h`. Otherwise the sidecar image predates the plugin, or the collector was restarted — `kubectl -n team1 logs deploy/weather-service -c envoy-proxy` |
| step 5 still says `ENTRY ONLY` (or `FRAGMENTED`) | the agent did not restart with the variable — `kubectl -n team1 logs deploy/weather-service -c agent \| grep 'httpx instrumented'` |
| the agent logs export failures after step 4 | wrong collector port: the stock chart serves OTLP/HTTP on `8335`, not `4318`; propagation works regardless, but the agent's own spans do not arrive |
| the answer is a tool error about `wttr.in` | the tool needs egress to `https://wttr.in`; the sidecar passes HTTPS through, so this is cluster egress, not lineage |
| step 6: `denied by the sidecar (jwt-validation): … missing Authorization header` on the **named** turn | `TOKEN` is empty — `token.sh` failed; its stderr says why (wrong password, `lineage-demo` client absent: run `setup-keycloak.sh`) |
| step 6: the **named** turn is denied with `auth.unauthorized — token validation failed` | the generic message is deliberate (the sidecar logs the detail: `kubectl -n team1 logs deploy/weather-service -c envoy-proxy`); the usual causes are an `AUTH_ISSUER` that differs from the token's `iss` bit for bit (a trailing slash is enough), a token without the realm audience, or the JWKS fetch failing — `token.sh` prints the token's `iss` and `aud` on stderr for the comparison |
| the named turn answers but the `user` column stays empty; `token.sh` says `sub: ABSENT` | the token has no `sub`: the realm lacks the `basic` scope (rossoctl#2446) — run `setup-keycloak.sh`; if the minting client predates it and is not the UI's, add it to `STOPGAP_CLIENTS` |
| the sidecar logs `jwks` fetch errors, every request 401 | `AUTH_JWKS_URL` not reachable from the pod — on kind the issuer host is the pod's loopback, pass the in-cluster Keycloak Service URL |
| step 7: the UI does not list `weather-service` | the AgentRuntime is not Ready, or the UI is on another namespace — `kubectl -n team1 get agentruntime`; the signed-in user needs `rossoctl-viewer` to list and `rossoctl-operator` to chat (alice has both) |
| step 7: the pod comes back `3/3` or the kit's sidecar is gone after adoption | `rossoctl.io/inject: disabled` missing from the pod template — the operator's webhook injected its own sidecar; it is in `k8s/weather.yaml` |
| anything about the attachment itself | the kit's [Troubleshooting](../../deploy/lineage-attach/README.md#troubleshooting) |

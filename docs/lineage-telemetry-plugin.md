# `lineage-telemetry`

Emits two facts-only OpenTelemetry spans per HTTP exchange — a request
span on sight and a response span at stream end, paired by
`lineage.exchange.id` — carrying direction, protocol, endpoints, outcome
and, optionally, the payload (parsed, or the raw body of a plain HTTP exchange). Cross-pod parenting rides one
`tracestate` member, `lineage-parent`; a request that arrives with no
valid `traceparent` is forwarded with one naming the request span, and a
valid one is never modified. The wire format is
[lineage-wire-contract.md](./lineage-wire-contract.md). Place it after
the protocol parsers (declared in `RequiresAny`) and after
`jwt-validation` when the principal facts are wanted; a request-phase
denial by a plugin ordered before it emits no spans.

- `otel_endpoint` (string) — OTLP gRPC target: `host:port`, `http://host:port` or `https://host:port`; any other scheme is refused. Default `localhost:4317`.
- `otel_tls` (bool) — dial the collector with TLS, verified against the system roots or `otel_ca_file`. An `https://` endpoint implies it; `https://` with `otel_tls: false`, and `http://` with `otel_tls: true` or `otel_ca_file`, are refused. A plaintext dial to a non-loopback collector is allowed and logged as a WARN at start. Default `false`.
- `otel_ca_file` (string) — PEM bundle to verify the collector's certificate against (a private CA, e.g. cert-manager issued). Implies `otel_tls`; with an explicit `otel_tls: false` it is refused; an unreadable file or one with no certificate refuses to start. Default: system roots.
- `capture_io` (bool) — attach the request/response content as `input.value` / `output.value`: the parsers' reduction for a2a, mcp and inference, the raw body for plain HTTP when it is text (and, for the response, whole). A plain-HTTP body is whatever the app sent, credentials included. Default `false`.
- `max_payload_bytes` (int) — cap on those two values, cut on a UTF-8 boundary with a `…[truncated]` marker; `0` or unset takes the default, `-1` attaches whole, any other negative is refused at start. Default `4096`.
- `max_attr_bytes` (int) — cap on every variable-content string attribute (`url.path`, `lineage.peer.host`, `mcp.tool`, …) and the span name — except the two identity facts `lineage.self.id` and `lineage.self.namespace`, which are operator configuration and never truncated; same `0` / `-1` / negative semantics as `max_payload_bytes`. Default `256`.
- `mint_traceparent` (bool) — forward a `traceparent` naming this request span when the request carried no valid one; `false` = a pure observer that writes no `traceparent`. Default `true`.
- `bypass_paths` (`[]string`) — path globs (`path.Match`, query stripped, path normalized — the shared bypass matcher `jwt-validation` and `sparc` use) that produce no spans. Default `/.well-known/*`, `/healthz`, `/readyz`, `/health`. Setting either bypass key replaces its default list rather than extending it, as in `ibac` / `sparc` / `cpex`; an entry matching everything is refused at start.
- `bypass_hosts` (`[]string`) — outbound host globs (`path.Match`, port stripped, case folded) that produce no spans; ignored inbound, where `Host` is caller-controlled. Default `otel-collector`, `otel-collector.*`, `jaeger`, `jaeger.*`, `zipkin`, `zipkin.*`, `prometheus`, `prometheus.*`.
- `self_id` (string) — this workload's identity, emitted as `lineage.self.id` (a SPIFFE ID reduced to its last path segment); a blank value, or one with no non-empty `/`-segment (`/`), is refused at start.
- `self_id_file` (string) — read when `self_id` is empty. Until it is readable and carries an identity the plugin is not ready and skips every exchange (no span, no header), re-reading the file in the background while `/readyz` names it — the same handling `jwt-validation` gives this path, so a late Secret mount never fails the sidecar (a pod probing `/readyz` stays out of rotation until the file lands). Refused at start only when `self_id` is also empty. Default `/shared/client-id.txt`.
- `namespace` (string) — this workload's Kubernetes namespace (an RFC 1123 DNS label), emitted as `lineage.self.namespace` on every span: the other half of its identity, since `self_id` is the last segment of a SPIFFE ID and the same segment in two namespaces is two workloads. **Required** (or `namespace_file`) — absent, blank, or not a DNS label is refused at start; never derived from the SPIFFE path. The attach kit writes its `NAMESPACE`; a sidecar older than this key rejects a config that carries it, so image and config flip together.
- `namespace_file` (string) — read once at start when `namespace` is empty; meant for `/var/run/secrets/kubernetes.io/serviceaccount/namespace`, the file the kubelet projects from the pod's own metadata — the one source that is right in every copy of a ConfigMap shared across namespaces (the platform's `authbridge-runtime-config`), where an inline literal would be wrong everywhere but one. Absent, blank, or not a DNS label refuses at start; no default, no poller.
- `export_delay_ms` (int) — the longest a recorded span waits in the batch exporter before it is sent (the batch span processor's schedule delay). `0` or unset keeps the SDK default, 5000 ms, which suits a reader that consumes the record later; a reader that answers about an exchange while it is still in flight, such as a gate holding an egress request until the record is judged, needs a short one (e.g. `10`). A short delay means more, smaller export calls; the spans are unchanged. Negative is refused at start.

The plugin's invocation record of a request pass whose `lineage-parent` stamp it wrote is
`modify/stamped_tracestate`, read by `sentry-gate` later in the chain. Its details are
`self_id` (the workload's identity as `lineage.self.id` carries it, the last segment of a
SPIFFE ID), `capture_io` (`"true"` or `"false"`, the setting that emitted this exchange's span) and,
with `capture_io` on, one mark when the request body did not reach `input.value` whole:
`body_cut: "true"` when it was cut at `max_payload_bytes`, `body_not_captured: "true"`
when the body has bytes and `input.value` got none of them. With `capture_io` off there
is no mark: nothing is captured, by design.

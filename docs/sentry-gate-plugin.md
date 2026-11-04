# `sentry-gate`

An outbound plugin (`core/plugins/sentrygate`) that holds a request to a
destination outside its pass list until a verdict service has answered for that
exchange, and refuses the request when the answer is a deny verdict (`block` by
default). The plugin judges no content: the verdict is the service's, keyed by
the exchange. The service is the verdict service in
[rossoctl/lab-data-governance](https://github.com/rossoctl/lab-data-governance);
it answers `state` (`decided`, `unjudged`, `pending`),
`verdict` when there is a record, and `reason` when `unjudged`.

The key is the [lineage wire contract](./lineage-wire-contract.md)'s: the trace
id of the forwarded `traceparent` and the request span id `lineage-telemetry`
stamps into the forwarded `tracestate` member `lineage-parent`. The gate
therefore requires `lineage-telemetry` before it on the outbound chain, and asks
only when lineage recorded, in the same pass, that it stamped this exchange.

The service can answer only once it has the request span, so run
`lineage-telemetry` with `export_delay_ms` well under `wait_ms`; use `10`, so
batching adds at most 10 ms to a hold. At lineage's default, 5000 ms, a request is often
held for `wait_ms` and gets no verdict (`verdict_pending`), so the fallback decides it.

A plugin that moves a request to another host (`inference-router`) belongs before
the gate: after it, the request goes to a host the gate never saw.

Per request, in order:

- Inbound: skipped (`skip/inbound`).
- A host on the pass list: continues at once, nothing asked (`skip/pass_host`).
- A tunnel, a `CONNECT` that opens one: never judged, continues, recorded `allow/unjudged`
  (`kind: tunnel`). A tunnel `tls-bridge` decrypts runs the pipeline again for
  each request inside it, and each of those is judged, a `CONNECT` sent inside it
  included.
- A message that can carry no data: continues at once, nothing asked, recorded
  `allow/no_data` (`kind` names it). That is a `GET` of `/.well-known/agent-card.json`
  or `/.well-known/agent.json` with no body, and a `POST` of MCP
  `notifications/initialized`, `ping` or `tools/list` whose body holds only `jsonrpc`,
  a numeric `id` of at most six digits and `method`, with `params` absent, empty or
  null, and of `initialize` whose `params` are a date-shaped `protocolVersion`, empty
  `capabilities`, and a `clientInfo` of a short `name` and `version`, in at most 256
  bytes. So an agent can start against an outside peer and connect to an outside MCP
  tool; a tool that needs OAuth discovery needs its host on `pass_hosts`. Any other form of these messages is asked about like any other request.
- Otherwise the gate asks
  `GET {verdict_url}/verdicts/{trace_id}/{exchange_id}?wait_ms=N` and waits up to
  `wait_ms`. A verdict listed in `deny_on` is refused with a 403; any other
  decided verdict continues.
- An `unjudged` answer, a record that did not see the whole request body, is
  refused with a 503 unless its verdict is in `deny_on`, recorded
  `verdict_unjudged`. A body longer than `max_payload_bytes` that nothing blocked
  is one, and so, with `capture_io` on, is a body that could not be captured.
- With `capture_io` off, an `unjudged` answer whose reason is `body_not_captured`
  continues, recorded `allow/unread_capture_off`, unless its verdict is in
  `deny_on`: turning capture off gives up judging bodies. `capture_io` defaults to
  off. The gate learns the setting from lineage's record of the same pass, so a
  change needs no pod restart, and it logs one warning per loaded config at the
  first body it lets through this way. Turning capture on puts raw bodies on the
  spans, credentials included, and refuses a clean body over `max_payload_bytes`.
- No verdict from a slow or dead service: the `fallback` setting decides (below).
  `deny`, the default, refuses with a 503, recorded `deny/fallback_deny`; `allow`
  continues unjudged, recorded `allow/fallback_allow`. Either record names the cause
  in `no_verdict`.
- Any other missing verdict is a fault and is refused with a 503 whatever the
  setting, recorded under its cause: `verdict_unauthorized`, `verdict_error` (any other
  status below 500, an answer that is not a verdict, a certificate the gate does not
  trust, a service that requires a client certificate, plain HTTP at an https URL),
  `verdict_empty` (an `unjudged` answer naming no verdict), `no_lineage_stamp`
  or `no_exchange_key`.
- A client that hangs up during the hold: nothing recorded by the gate, and the
  listener records a 499 (`pipeline.cancelled`).

A path `lineage-telemetry` bypasses (`bypass_paths`, `bypass_hosts`) is never
stamped, so a request on one to an unlisted host is refused `no_lineage_stamp`;
add that host to `pass_hosts` if it should leave.

The gate judges a plain request sent through the forward proxy (the app's
`HTTP_PROXY`) and each request inside a tunnel `tls-bridge` decrypts. It does not
judge a tunnel `tls-bridge` does not decrypt, whether an HTTPS request through
the proxy or a connection the transparent listener captured. A `skip_hosts`
destination never reaches it. A WebSocket is judged at its handshake, and on a
Responses API socket the proxy carries (`listener.responses_websockets`) at each
turn as well; the frames of any other WebSocket are not judged.

It is carried by the `full` and `fullcpex` profiles only, so to gate egress run
the proxy-sidecar `authbridge` image.

## The fallback

`fallback` speaks only for a slow or dead service: the service answered `pending`
(nothing to judge yet within `wait_ms`), answered 503 `verdict_busy` (its waiter cap
is full), answered any other 5xx, answered `decided` with no verdict, or did not
answer at all (refused, reset, a name that does not resolve, the call running past
`wait_ms` + 500 ms; recorded `error_kind: transport`). A status below 500 other than 200 (a wrong path, a
wrong secret), an answer that is not a verdict (`error_kind: answer`), a certificate the
gate does not trust, a service that requires a client certificate or plain HTTP at an
https URL (`error_kind: tls`), an `unjudged` answer, and a request with no lineage stamp or no exchange key are setup or code
faults, or a verdict about the request, and `allow` does not deliver them. The record of a fallback carries
`no_verdict` (the cause: `verdict_pending`, `verdict_busy`, `verdict_empty` or
`verdict_error`), `exchange_id`, `waited_ms`, and the cause's `status`, `error` and
`error_kind` where it has them. `allow` trades fail-closed for availability: while the
service is slow, down or at its waiter cap, unlisted egress leaves unjudged, and only the record says so.

## Refusal bodies

A refusal has two readers. A model reads one `message`, the processed text. A program reads the raw facts beside it: `details`, what
the service answered and how long the gate waited. The refusal reaches the app in the reply its stock client hands to its caller:

| request | status | reply | the message | the raw facts |
|---|---|---|---|---|
| MCP `tools/call` with an id | 200 | a JSON-RPC result with `isError: true` | `content[0].text` | `structuredContent` |
| A2A `message/send` with an id | 200 | a JSON-RPC result, an agent message | `parts[0].text` | `metadata["sentry-gate"]` |
| A2A `message/stream` with an id | 200 | the same, as one server-sent event | `parts[0].text` | `metadata["sentry-gate"]` |
| another MCP call with an id | 200 | a JSON-RPC error | `error.message` | `error.data` |
| anything else | 403 or 503 | the envelope `{"error", "message", "plugin", "details"}` | `message` | `error`, `plugin`, `details` |

An MCP result and an A2A message look like answers at the HTTP level. Code that reads such a reply itself must check `isError`, or read
the part's text; a client that counts any 200 as delivered is wrong about a refused call. The refusal is still a denial in the
session record and in lineage.

The raw facts are `error` (the code), `plugin` and `details`:

| refusal | code | `details` |
|---|---|---|
| a verdict in `deny_on` | `policy.content-blocked` (403 where the status shows) | `state`, `verdict`, `reason` if unjudged, `rules`, `labels`, `redacted_payload` if the service sent it, `exchange_id`, `waited_ms` |
| an `unjudged` answer, not denied | `policy.verdict-unavailable` (503) | `state`, `verdict`, `reason`, `rules`, `labels`, `exchange_id`, `waited_ms` |
| no verdict, `fallback: deny` | `policy.verdict-unavailable` (503) | `reason` (the cause, as `no_verdict` in the record), `fallback: "deny"`, `waited_ms`, `exchange_id` |
| no verdict, a fault | `policy.verdict-unavailable` (503) | `reason` (the recorded one), `waited_ms`, `exchange_id` once the key is known |

Every message starts `Sentry gate (data governance) refused this request to <host>. Nothing was delivered.` The rest depends on the
refusal:

| refusal | the rest of the message |
|---|---|
| labels and the service's redacted payload | the marked text, then how to send the rest |
| labels and no redacted payload | `Flagged:` and the labels |
| nothing flagged | nothing more |
| `unjudged` | `Only part of it could be judged.` before any of the above |
| no verdict, `fallback: deny` | `No verdict arrived, so nothing was judged and nothing is flagged.` |
| no verdict, a fault | `No verdict was given, so nothing was judged and nothing is flagged.` |

A block's reply to a `tools/call`, for example:

```json
{"jsonrpc": "2.0", "id": 7, "result": {"isError": true,
 "content": [{"type": "text", "text": "Sentry gate (data governance) refused this request to peer.example. Nothing was delivered.\nFlagged parts are marked [category]:\n{\"drug\": \"Lisinopril\", \"ssn\": \"[person.govID]\"}\nTo deliver the rest, make the same call again now with the marked parts removed, then answer. It will be judged again."}],
 "structuredContent": {"error": "policy.content-blocked", "plugin": "sentry-gate",
  "details": {"state": "decided", "verdict": "block", "rules": ["DG-001"], "labels": ["person.govID"],
              "redacted_payload": "{\"drug\": \"Lisinopril\", \"ssn\": \"[person.govID]\"}",
              "exchange_id": "00f067aa0ba902b7", "waited_ms": 410}}}}
```

The marked text is the service's, passed as it came: the text the classifier judged, each finding replaced by its category. It
replaces findings and nothing else. It is text, not always JSON: a flagged bare number leaves `"quantity": [medical.codes]`.

The last sentences promise nothing: a new request is judged like any other. A caller that does not want a partial delivery can
decline it.

A `rules`, `labels` or `redacted_payload` of the wrong shape is dropped, and the refusal stands. The gate reads at most 64 KiB of an
answer. The service's cap on `redacted_payload` keeps an answer under that.

The invocation record carries `verdict`, `version`, `exchange_id`, `waited_ms`, `rules` and `labels` (comma-joined, when not empty),
`unread` on an `unjudged` answer that was not denied, and `rules_error`, `labels_error` or `redacted_payload_error` for a value of the
wrong shape. It does not carry `redacted_payload`. The service's `status` and `error` on a failed call are in the record only:
that text can carry the internal URL, so a refusal never does.

## Config

| Field | Type | Default | Notes |
|---|---|---|---|
| `verdict_url` | string | required | Base URL of the verdict service; the plugin appends `/verdicts/{trace_id}/{exchange_id}`. For the lab-data-governance service it ends in `/enforce/v1`. The call never goes through a proxy. |
| `pass_hosts` | `[]string` | `[]` | Outbound host globs that never wait: `path.Match` on the host, port stripped, case folded. |
| `pass_single_label` | bool | `true` | A cluster short name never waits: one label of lowercase letters, digits and hyphens, not a number. |
| `wait_ms` | int | `2000` | Longest hold for a verdict, `1..3000`. The HTTP call may take `wait_ms` + 500 ms. |
| `deny_on` | `[]string` | `["block"]` | Verdicts that refuse the request, compared trimmed and case-folded. Empty is refused: remove the plugin instead. |
| `fallback` | string | `deny` | What a request gets when no verdict arrives from a slow or dead service ([the fallback](#the-fallback)): `deny` refuses it with a 503, `allow` delivers it unjudged. Any other value is refused. |
| `verdict_secret` | string | `""` | Sent as `Authorization: Bearer <secret>` on every verdict call. Masked in config echoes by its key name, never logged or recorded. |
| `verdict_secret_file` | string | `""` | File holding the secret (a mounted Secret), read at configure, so a rotated secret is refused `verdict_unauthorized` until the config reloads. Exclusive with `verdict_secret`. |

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
held for `wait_ms` and refused `verdict_pending`.

A plugin that moves a request to another host (`inference-router`) belongs before
the gate: after it, the request goes to a host the gate never saw.

Per request, in order:

- Inbound: skipped (`skip/inbound`).
- A host on the pass list: continues at once, nothing asked (`skip/pass_host`).
- A tunnel, a `CONNECT` that opens one: never judged, continues, recorded `allow/unjudged`
  (`kind: tunnel`). A tunnel `tls-bridge` decrypts runs the pipeline again for
  each request inside it, and each of those is judged, a `CONNECT` sent inside it
  included.
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
- No verdict is refused with a 503, recorded under one of `verdict_pending`,
  `verdict_error`, `verdict_busy`, `verdict_unauthorized`, `verdict_empty`,
  `no_lineage_stamp` or `no_exchange_key`.
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

## Config

| Field | Type | Default | Notes |
|---|---|---|---|
| `verdict_url` | string | required | Base URL of the verdict service; the plugin appends `/verdicts/{trace_id}/{exchange_id}`. For the lab-data-governance service it ends in `/enforce/v1`. The call never goes through a proxy. |
| `pass_hosts` | `[]string` | `[]` | Outbound host globs that never wait: `path.Match` on the host, port stripped, case folded. |
| `pass_single_label` | bool | `true` | A cluster short name never waits: one label of lowercase letters, digits and hyphens, not a number. |
| `wait_ms` | int | `2000` | Longest hold for a verdict, `1..3000`. The HTTP call may take `wait_ms` + 500 ms. |
| `deny_on` | `[]string` | `["block"]` | Verdicts that refuse the request, compared trimmed and case-folded. Empty is refused: remove the plugin instead. |
| `verdict_secret` | string | `""` | Sent as `Authorization: Bearer <secret>` on every verdict call. Masked in config echoes by its key name, never logged or recorded. |
| `verdict_secret_file` | string | `""` | File holding the secret (a mounted Secret), read at configure, so a rotated secret is refused `verdict_unauthorized` until the config reloads. Exclusive with `verdict_secret`. |

# Propagation matrix

One row per library the shim instruments, each proven against a real exchange
rather than inferred from the install list.

```sh
./run.sh                 # every row, ~10 min under podman; needs host python3 and network for pip
./run.sh urllib flask    # a subset
KEEP=1 ./run.sh grpc     # keep the probe images for a closer look
```

Each row is a stock `python:3.12-slim` image carrying only the library under
test, baked with the kit's own `build-otel-shim.sh`, then run four ways:

| column | image | gate | expected at the sink |
|---|---|---|---|
| base | the base image, not baked | n/a | no `traceparent` |
| inert | baked | off | no `traceparent` (the bake changed nothing) |
| on | baked | `LINEAGE_PROPAGATE=1` | a `traceparent` |
| carried | baked | on, with a known inbound trace id | that trace id |

A **client** row (`clients.py`) makes one outbound call with the library to
a header-echo sink; the inbound context for `carried` is a span the probe
opens itself. A **server** row (`servers.py`) serves one request with the
framework and makes an outbound `requests` call from inside the handler; the
inbound context arrives on the wire from `driver.py`, so `on` without a known
id is not a separate case. The
**gRPC** row is both halves in one image, and reports two verdicts per
column: what the gRPC server saw in metadata (client half) and what the sink
saw on the server's own outbound hop (server half).

What a row proves is propagation *by that library*, not the presence of one
instrumentor: `requests` rides on `urllib3`, so its row would still pass with
the `requests` instrumentor gone. A `FAIL` in `base` or `inert` means the
probe image is not the clean baseline it claims to be; a `?` means the probe
printed nothing (did not start, crashed, or the server never answered) and is
counted as a failure. A `FAIL` in `on` or `carried` means the library's
instrumentor did not activate or did not inject: the kit's install list and
this matrix disagree, and the matrix is right. A bake refusal names the log
that holds the bake's own output.

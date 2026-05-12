# AuthBridge Binary

A single binary that replaces three separate codebases (go-processor, waypoint, klaviger) with a unified auth proxy supporting three deployment modes.

## Images

| Image | Dockerfile | Size | Contents |
|-------|-----------|------|----------|
| `authbridge-envoy` | `Dockerfile` | 140 MB | Envoy + authbridge (UBI9-micro) |
| `authbridge-light` | `Dockerfile.light` | 29 MB | authbridge only (distroless) |
| `authbridge-unified` | `Dockerfile` | 140 MB | Deprecated alias (same image as `authbridge-envoy`) |

## Modes

| Mode | Image | Interception | Listeners |
|------|-------|-------------|-----------|
| `envoy-sidecar` | `authbridge-envoy` | Envoy iptables + ext_proc | gRPC ext_proc on :9090 |
| `proxy-sidecar` | `authbridge-light` | HTTP_PROXY env + port-stealing | HTTP reverse proxy + forward proxy |
| `waypoint` | `authbridge-light` | Istio ambient + ext_authz | gRPC ext_authz + HTTP forward proxy |

### proxy-sidecar port reassignment

In proxy-sidecar mode, the kagenti-operator webhook transparently reassigns the agent's port to interpose the reverse proxy:

1. The reverse proxy takes over the agent's original port (e.g., `:8000`)
2. The agent is moved to a free port (e.g., `:8001`) via `PORT` env var
3. `HTTP_PROXY`/`HTTPS_PROXY` env vars are injected into the agent container
4. The Service targetPort remains unchanged — traffic flows through the reverse proxy

The operator passes the dynamically assigned ports via env vars (`REVERSE_PROXY_ADDR`, `REVERSE_PROXY_BACKEND`, `FORWARD_PROXY_ADDR`) which are expanded via `${...}` in the config YAML.

## Selecting a Mode

The operator selects the mode via annotation on the workload's pod template:

```yaml
# Default (envoy-sidecar) — no annotation needed
metadata:
  labels:
    kagenti.io/type: agent

# Proxy-sidecar mode
metadata:
  labels:
    kagenti.io/type: agent
  annotations:
    kagenti.io/authbridge-mode: "proxy-sidecar"
```

## Building

All builds run from the **repo root** with `authbridge/` as the build context:

```bash
# Envoy variant (envoy-sidecar mode)
podman build -f authbridge/cmd/authbridge/Dockerfile -t authbridge-envoy:local authbridge/

# Lightweight variant (proxy-sidecar / waypoint modes)
podman build -f authbridge/cmd/authbridge/Dockerfile.light -t authbridge-light:local authbridge/

# Load into Kind
kind load docker-image authbridge-envoy:local --name kagenti
kind load docker-image authbridge-light:local --name kagenti
```

The Envoy image contains both Envoy and the authbridge binary. The entrypoint starts both processes with `wait -n` supervision (if either dies, the container restarts). The light image runs the authbridge binary directly as the entrypoint.

## Running

```bash
authbridge --mode envoy-sidecar --config /etc/authbridge/config.yaml
```

The `--mode` flag can also be set in the YAML config. The flag overrides the config file value.

## Configuration

YAML with `${ENV_VAR}` expansion. Undefined env vars are preserved as-is (not expanded to empty).

The runtime config is intentionally thin — it covers the mode, the listener addresses, session tracking, and the plugin pipeline. Everything a plugin needs (issuer, token URL, credentials, routes, bypass paths) lives under its own `config:` block inside the pipeline entry. See [`docs/plugin-reference.md`](../../docs/plugin-reference.md) for the per-plugin decode / defaults / validate convention.

### envoy-sidecar mode

Drop-in replacement for `envoy-with-processor`. Used as a sidecar alongside Envoy in each agent pod.

Minimum viable config — every Kagenti-convention default applies:

```yaml
mode: envoy-sidecar

pipeline:
  inbound:
    plugins:
      - name: jwt-validation
        config:
          issuer: "${ISSUER}"

  outbound:
    plugins:
      - name: token-exchange
        config:
          keycloak_url: "${KEYCLOAK_URL}"
          keycloak_realm: "${KEYCLOAK_REALM}"
          identity:
            type: spiffe                           # spiffe or client-secret
```

Defaults filled in by the plugins (override any by setting them explicitly):

| Plugin | Default | Value |
|---|---|---|
| jwt-validation | `jwks_url` | `<issuer>/protocol/openid-connect/certs` |
| jwt-validation | `audience_file` | `/shared/client-id.txt` (client-registration convention) |
| jwt-validation | `bypass_paths` | `/.well-known/*`, `/healthz`, `/readyz`, `/livez` |
| jwt-validation | `audience_mode` | `static` |
| token-exchange | `token_url` | `<keycloak_url>/realms/<realm>/protocol/openid-connect/token` |
| token-exchange | `default_policy` | `passthrough` |
| token-exchange | `no_token_policy` | `deny` |
| token-exchange | `routes.file` | `/etc/authproxy/routes.yaml` |
| token-exchange | `identity.client_id_file` | `/shared/client-id.txt` (both types) |
| token-exchange | `identity.client_secret_file` | `/shared/client-secret.txt` (client-secret type) |
| token-exchange | `identity.jwt_svid_path` | `/opt/jwt_svid.token` (spiffe type) |

Full form — every field spelled out, for deployments that diverge from defaults:

```yaml
mode: envoy-sidecar

pipeline:
  inbound:
    plugins:
      - name: jwt-validation
        config:
          issuer: "${ISSUER}"
          jwks_url: "${JWKS_URL}"                  # optional; derived from issuer
          audience_file: "/shared/client-id.txt"   # audience written by client-registration
          bypass_paths:
            - "/.well-known/*"
            - "/healthz"
            - "/readyz"
            - "/livez"

  outbound:
    plugins:
      - name: token-exchange
        config:
          token_url: "${TOKEN_URL}"                # or derived from keycloak_url + keycloak_realm
          keycloak_url: "${KEYCLOAK_URL}"
          keycloak_realm: "${KEYCLOAK_REALM}"
          default_policy: "passthrough"            # passthrough (default) or exchange
          no_token_policy: "deny"                  # deny (default), allow, or client-credentials
          identity:
            type: spiffe                           # spiffe or client-secret
            client_id_file: "/shared/client-id.txt"
            client_secret_file: "/shared/client-secret.txt"
            jwt_svid_path: "/opt/jwt_svid.token"
          routes:
            file: "/etc/authproxy/routes.yaml"     # loaded when present, ignored when absent
            rules:                                 # inline; merged with file
              - host: "target-service.**"
                target_audience: "target"
                token_scopes: "openid target-aud"
```

### waypoint mode

Shared service for Istio ambient mesh. `jwt-validation` derives audience from destination hostname when `audience_mode: per-host` is set.

```yaml
mode: waypoint

pipeline:
  inbound:
    plugins:
      - name: jwt-validation
        config:
          issuer: "${ISSUER}"
          audience_mode: per-host                  # derive from pctx.Host per request

  outbound:
    plugins:
      - name: token-exchange
        config:
          keycloak_url: "${KEYCLOAK_URL}"
          keycloak_realm: "${KEYCLOAK_REALM}"
          default_policy: "exchange"
          identity:
            type: client-secret
            client_id: "token-exchange-service"
            client_secret: "${CLIENT_SECRET}"
```

### proxy-sidecar mode

Sidecar without Envoy. Reverse proxy validates inbound, forward proxy exchanges outbound.

```yaml
mode: proxy-sidecar

listener:
  reverse_proxy_backend: "http://localhost:8081"

pipeline:
  inbound:
    plugins:
      - name: jwt-validation
        config:
          issuer: "${ISSUER}"
          audience_file: "/shared/client-id.txt"

  outbound:
    plugins:
      - name: token-exchange
        config:
          keycloak_url: "${KEYCLOAK_URL}"
          keycloak_realm: "${KEYCLOAK_REALM}"
          identity:
            type: spiffe
            client_id_file: "/shared/client-id.txt"
            jwt_svid_path: "/opt/jwt_svid.token"
```

### Bare-name plugin entries

Parsers and any other plugin that doesn't take configuration can appear as a bare name:

```yaml
pipeline:
  outbound:
    plugins:
      - name: token-exchange
        config: { ... }
      - mcp-parser        # equivalent to { name: mcp-parser }
      - inference-parser
```

### URL Derivation

Each plugin derives missing URLs from what you supply:

| Missing field | Derived from | Example |
|---|---|---|
| `jwt-validation.jwks_url` | `jwt-validation.issuer` | `<issuer>/protocol/openid-connect/certs` |
| `token-exchange.token_url` | `token-exchange.keycloak_url` + `keycloak_realm` | `http://keycloak:8080/realms/kagenti/protocol/openid-connect/token` |

Explicit values always take precedence over derived values.

### Credential File Waiting

When `audience_file` (jwt-validation) or `client_id_file` / `client_secret_file` / `jwt_svid_path` (token-exchange) are configured, the plugin first attempts a synchronous read at Configure time. If the file isn't readable yet (the common case during pod boot while client-registration is still provisioning), the plugin's `Init` spawns a background poll; once the file appears, `auth.UpdateIdentity` swaps the credentials into the live handler atomically. OnRequest returns 503 for traffic that arrives before credentials land.

## Logging

AuthBridge uses Go's `slog` structured logger. The log level is configurable at startup and at runtime.

### Set level at startup

Set the `LOG_LEVEL` env var (`debug`, `info`, `warn`, `error`). Default: `info`.

```bash
# In a deployment
kubectl set env deployment/weather-service -n team1 -c authbridge-proxy LOG_LEVEL=debug

# Standalone
LOG_LEVEL=debug authbridge --config /etc/authbridge/config.yaml
```

### Toggle at runtime (no restart)

Send `SIGUSR1` to toggle between `info` and `debug`:

```bash
# The container has no standalone kill/grep binaries — use bash builtins only.
# Match on the full binary path to skip the entrypoint script (also at PID 1).
kubectl exec deploy/weather-service -n team1 -c envoy-proxy -- \
  bash -c 'for f in /proc/[0-9]*/cmdline; do [ -r "$f" ] || continue; c=$(<"$f"); [[ "$c" == /usr/local/bin/authbridge* ]] && kill -USR1 "${f//[!0-9]/}" && break; done'
```

Send again to toggle back. The current level is logged on each toggle.

## Architecture

```
cmd/authbridge/
├── main.go              # --mode + --config, starts listeners, graceful shutdown
├── entrypoint.sh        # Envoy + authbridge process supervision (wait -n)
├── Dockerfile           # Combined Envoy + authbridge image (ubi-minimal)
└── listener/
    ├── extproc/         # Envoy ext_proc gRPC streaming (envoy-sidecar mode)
    ├── extauthz/        # Envoy ext_authz gRPC unary (waypoint mode)
    ├── forwardproxy/    # HTTP forward proxy (waypoint + proxy-sidecar)
    └── reverseproxy/    # HTTP reverse proxy (proxy-sidecar mode)
```

Listeners are thin protocol translators (~50-175 lines each). All auth logic lives in `authlib/`.

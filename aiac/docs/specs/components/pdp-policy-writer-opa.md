# Component PRD: PDP Policy Writer (OPA)

## Location
`aiac/src/aiac/pdp/service/policy/opa/`

## Description
A FastAPI web service that translates a **Policy Model** into OPA Rego packages and writes them to an `AuthorizationPolicy` Kubernetes Custom Resource. The OPA plugin embedded in each AuthBridge instance fetches the Rego packages relevant to its pod from this CR at startup.

The service is deployed as a container in the **Rossoctl Interface Pod** alongside the IdP Configuration Service, behind the `aiac-pdp-policy-service:7072` ClusterIP.

The service has no dependency on Keycloak. All Keycloak operations (entity reads) are handled by the **IdP Configuration Service** and its library (`aiac.idp.configuration`).

---

## Pydantic models (`aiac.policy.model.models`)

The Policy Writer deserializes the **canonical** `PolicyModel` / `AgentPolicyModel` / `PolicyRule` defined in [policy-model.md](policy-model.md) and imported from `aiac.policy.model.models`. This service does **not** define its own copies; the tables below summarize the fields the Rego generator consumes. (The former `aiac.pdp.library.models` module is deprecated — see policy-model.md "Replaces".)

All models use `model_config = ConfigDict(extra='ignore')`.

### `PolicyRule`

A single access rule pairing a typed role with a typed scope. Used in both inbound and outbound rule sets.

| Field | Type |
|-------|------|
| `role` | `Role` |
| `scope` | `Scope` |
| `effect` | `RuleEffect` (`Allow` default / `Deny`) |

`Role` and `Scope` are the typed models from `aiac.idp.configuration.models`. The Rego generator emits their `.name` as the string literal OPA matches against. `effect` selects whether the rule contributes to an `*_allow_scopes` or `*_deny_scopes` map (see below).

### `AgentPolicyModel`

Complete policy definition for a single agent (service). Contains two sets of `PolicyRule` entries plus supporting data maps used by the Rego packages.

| Field | Type | Description |
|-------|------|-------------|
| `agent_id` | `str` | Service ID from the AIAC trigger event (`aiac.apply.service.{id}`) |
| `agent_roles` | `list[Role]` | Realm roles assigned to this agent. Effect-agnostic identity. |
| `agent_scopes` | `list[Scope]` | Scopes this agent exposes. Effect-agnostic identity. |
| `source_roles` | `dict[str, list[Role]]` | Inbound: source (calling service) **id** → roles held. **Optional** gate input — an absent source passes. Effect-agnostic; **includes deny-edge roles**. |
| `subject_roles` | `dict[str, list[Role]]` | Inbound: subject (end-user) **id** → roles held. **Mandatory** gate input. Effect-agnostic; **includes deny-edge roles**. |
| `target_allow_scopes` | `dict[str, list[Scope]]` | Outbound: target service **id** → scopes this agent **may** request on it |
| `target_deny_scopes` | `dict[str, list[Scope]]` | Outbound: target service **id** → scopes this agent **must not** request on it |
| `inbound_subject_allow_rules` / `inbound_subject_deny_rules` | `list[PolicyRule]` | Who may / must-not call this agent: `(subject_role, agent_scope)` tuples |
| `inbound_source_allow_rules` / `inbound_source_deny_rules` | `list[PolicyRule]` | Which calling services may / must-not call this agent: `(source_role, agent_scope)` tuples |
| `outbound_target_allow_rules` / `outbound_target_deny_rules` | `list[PolicyRule]` | What this agent may / must-not call: `(this_agent_role, target_scope)` tuples |
| `outbound_subject_allow_rules` / `outbound_subject_deny_rules` | `list[PolicyRule]` | Which users may / must-not reach the agent's targets: `(user_role, tool_scope)` tuples. Default `[]`. |

**`agent_roles` / `agent_scopes` provenance:** these carry the agent's **own** identity — the service-account realm roles it holds and the scopes it exposes. The Policy Computation Engine resolves them from the agent's IdP `Service` record (P2) and embeds them on every agent model it writes; a realm-level agent with no owning service keeps `[]`. Together with `subject_roles` / `source_roles` they are **effect-agnostic**: a role appearing only in a DENY rule is still listed here, so the Rego deny lookup can resolve it.

**Inbound rule semantics (deny-overrides):** a subject holding realm role `role` may invoke this agent for agent scope `scope` iff an allow edge grants it and no deny edge prohibits it. Grouped by role, the allow/deny lists become `subject_role_allow_scopes` / `subject_role_deny_scopes` (and `source_role_allow_scopes` / `source_role_deny_scopes`) that the inbound package evaluates.

**Outbound target rule semantics (deny-overrides):** this agent acting as realm role `role` may request target scope `scope` iff an allow edge grants it and no deny edge prohibits it. Grouped by role, the lists become `agent_role_allow_scopes` / `agent_role_deny_scopes` (informational) and materialize into `target_allow_scopes` / `target_deny_scopes`.

**Outbound subject rule semantics (deny-overrides):** a **user** role may reach a **tool** exposing scope `scope` iff an allow edge grants it and no deny edge prohibits it. Grouped by role, the lists become `subject_role_allow_scopes` / `subject_role_deny_scopes` that the **outbound** package's subject gate evaluates against `target_allow_scopes[input.target]` / `target_deny_scopes[input.target]`. This is distinct from the inbound subject rules (user → *agent* scope): the outbound subject gate answers "may this user reach the tool?", not "may this user call the agent?".

**Note on target-map direction:** `target_allow_scopes` / `target_deny_scopes` are keyed by **target service id → scopes** (the inverse of the former `scope_targets`, which was `scope → targets`). The outbound Rego generator emits these maps **verbatim** and evaluates `target_allow_scopes[input.target]` / `target_deny_scopes[input.target]` directly — there is no inversion (see below).

### `PolicyModel`

A partial or full system policy model. When sent to the PDP Policy Writer, contains only the agents whose policies have changed.

| Field | Type |
|-------|------|
| `agents` | `list[AgentPolicyModel]` |

### Usage

```python
from aiac.policy.model.models import PolicyModel, AgentPolicyModel, PolicyRule
```

---

## Endpoints

No `?realm=` parameter — the service operates on a Kubernetes CR, not a Keycloak realm.

| Method | Path | Body | Operation |
|--------|------|------|-----------|
| `POST` | `/policy` | `PolicyModel` | Upsert Rego packages for all agents in the partial model |
| `POST` | `/policy/agents/{agent_id}` | `AgentPolicyModel` | Upsert Rego packages for a single agent |
| `DELETE` | `/policy/agents/{agent_id}` | — | Remove all Rego packages for a specific agent (off-boarding) |
| `DELETE` | `/policy` | — | Clear all Rego packages from the CR (rebuild pre-step) |
| `GET` | `/health` | — | Readiness probe |

### Status codes

| Endpoint | Success | Error |
|----------|---------|-------|
| `POST /policy` | `204 No Content` | `502 Bad Gateway` with `{"error": "..."}` if CR write fails |
| `POST /policy/agents/{agent_id}` | `204 No Content` | `502 Bad Gateway` if CR write fails |
| `DELETE /policy/agents/{agent_id}` | `204 No Content` | `502 Bad Gateway` if CR write fails |
| `DELETE /policy` | `204 No Content` | `502 Bad Gateway` if CR write fails |
| `GET /health` | `200 OK` `{"status": "ok"}` | `503 Service Unavailable` if CR is unreachable |

---

## Rego package structure

For each `AgentPolicyModel`, the service generates **two Rego packages**: one for the inbound pipeline and one for the outbound pipeline. The `agent_id` is slugified for use in the package name (and filename). `agent_id` is the Keycloak clientId — a SPIFFE URI under SPIRE (`spiffe://host/ns/{ns}/sa/{name}`), or the plain `{ns}/{name}` clientId without it — so slugifying is not a simple hyphen→underscore substitution: the trust domain/host is dropped, the `{ns}/{name}` portion is extracted, and every remaining non-alphanumeric run collapses to a single underscore, lowercased (`aiac.pdp.service.policy.opa.rego.slugify`). This keeps the slug short and identical regardless of whether SPIRE is enabled — e.g. both `spiffe://localtest.me/ns/team1/sa/github-agent` and `team1/github-agent` slugify to `team1_github_agent`.

> **Two identifiers, two layers (no contradiction).** UC-1 onboarding and the Trigger use the internal Keycloak **client UUID** (`service.id` / `Trigger.entity_id`) purely to *look up* a service in the IdP — that UUID **never reaches this writer**. What flows down the policy pipeline into `PolicyRule.scope.serviceId` / `Role.actorIds` and lands as `AgentPolicyModel.agent_id` is the **clientId** (the `{ns}/{name}` / SPIFFE form), which is what this writer slugifies for the Rego package name. The UUID→clientId resolution happens once, in the IdP Configuration Service, before the AgentPolicyModel is ever built.

**Input is identifiers only.** Both packages receive an input document of **IDs**, never roles or scopes: inbound input is `{subject, source}`, outbound input is `{subject, target}` (`subject` is the end-user id, `source` the calling service id, `target` the called service id). Every role/scope mapping is therefore **embedded in the package itself**, and the `allow` logic resolves IDs → roles → scopes internally. Because no per-request scope is supplied, the decision is **coarse**: a principal passes when it has access to **at least one** relevant scope.

The generator embeds these symbols, derived from the `AgentPolicyModel`:

**Symmetric rename — no alias, no back-compat.** The single inbound `role_scopes` map splits into `subject_role_allow_scopes` / `subject_role_deny_scopes` / `source_role_allow_scopes` / `source_role_deny_scopes`; the outbound `subject_role_scopes` splits into `subject_role_allow_scopes` / `subject_role_deny_scopes`; `target_scopes` splits into `target_allow_scopes` / `target_deny_scopes`. Identity maps `subject_roles` / `source_roles` / `agent_roles` keep their names.

| Rego symbol | Source | Shape |
|-------------|--------|-------|
| `subject_roles` | `model.subject_roles` | subject id → `[role.name, …]` (effect-agnostic; includes deny-edge roles) |
| `source_roles` | `model.source_roles` | source id → `[role.name, …]` (effect-agnostic; includes deny-edge roles) |
| `agent_scopes` | `model.agent_scopes` | `[scope.name, …]` — **inbound package only** (the audience gate; outbound decisions do not consider the agent's own scopes) |
| `agent_roles` | `model.agent_roles` | `[role.name, …]` |
| `subject_role_allow_scopes` / `subject_role_deny_scopes` | grouped `inbound_subject_{allow,deny}_rules` (inbound) / `outbound_subject_{allow,deny}_rules` (outbound) | role.name → `[scope.name, …]` |
| `source_role_allow_scopes` / `source_role_deny_scopes` | grouped `inbound_source_{allow,deny}_rules` | role.name → `[scope.name, …]` — **inbound package only** |
| `agent_role_allow_scopes` / `agent_role_deny_scopes` | grouped `outbound_target_{allow,deny}_rules` | role.name → `[scope.name, …]` (informational — `target_*_scopes` is the live gate) |
| `target_allow_scopes` / `target_deny_scopes` | `model.target_allow_scopes` / `model.target_deny_scopes` | target id → `[scope.name, …]` |

### Inbound package: `authz.{agent_slug}.inbound`

Evaluated by the AuthBridge OPA plugin in the **inbound pipeline** — "who may call this agent". Input document: `{subject, source}` (IDs). **`subject` is mandatory; `source` is optional** (an absent source passes). A principal passes the allow gate when it holds a role that grants at least one of the agent's own scopes (`agent_scopes`); the deny gates mirror that shape against the deny maps, and `allow` applies **deny-overrides**.

```rego
package authz.{agent_slug}.inbound

agent_scopes := ["{scope.name}", ...]                # from agent_scopes

subject_roles := { "{subject_id}": ["{role.name}", ...], ... }   # effect-agnostic
source_roles  := { "{source_id}":  ["{role.name}", ...], ... }   # effect-agnostic

subject_role_allow_scopes := { "{role.name}": ["{scope.name}", ...], ... }  # from inbound_subject_allow_rules
subject_role_deny_scopes  := { "{role.name}": ["{scope.name}", ...], ... }  # from inbound_subject_deny_rules
source_role_allow_scopes  := { "{role.name}": ["{scope.name}", ...], ... }  # from inbound_source_allow_rules
source_role_deny_scopes   := { "{role.name}": ["{scope.name}", ...], ... }  # from inbound_source_deny_rules

subject_allow_ok if {
    some role in subject_roles[input.subject]
    some scope in subject_role_allow_scopes[role]
    scope in agent_scopes
}
subject_deny_ok if {
    some role in subject_roles[input.subject]
    some scope in subject_role_deny_scopes[role]
    scope in agent_scopes
}
source_allow_ok if { not input.source }              # optional: absent source passes
source_allow_ok if {
    some role in source_roles[input.source]
    some scope in source_role_allow_scopes[role]
    scope in agent_scopes
}
source_deny_ok if {
    some role in source_roles[input.source]
    some scope in source_role_deny_scopes[role]
    scope in agent_scopes
}

default allow := false
allow if { subject_allow_ok; source_allow_ok; not subject_deny_ok; not source_deny_ok }
```

**Deny-overrides:** `allow` fires only when both allow gates pass **and** neither deny gate matches. A subject or source barred by a deny edge is rejected even when an allow edge would otherwise admit it. (An absent `input.source` makes `source_allow_ok` true and — because `source_roles[input.source]` is undefined — leaves `source_deny_ok` false, so an absent source still passes.)

### Outbound package: `authz.{agent_slug}.outbound`

Evaluated by the AuthBridge OPA plugin in the **outbound pipeline** — "what this agent may call". Input document: `{subject, target, function_name}` (IDs; `function_name` is the requested target scope). `allow` is a **per-scope AND** keyed on `input.function_name`, requiring **both** allow gates to pass on that same scope and **neither** deny gate to match it. The outbound **subject** gate is user→**tool** (distinct from the inbound user→agent gate): it passes iff the subject holds a role granted the **requested** `function_name` (via `subject_role_allow_scopes`, grouped from `outbound_subject_allow_rules`). The **capability** gate (`target_allow_ok`) passes iff the requested `function_name` is one of the scopes the `target` accepts — `target_allow_scopes[input.target]`, consumed **directly** (target id → scopes, not inverted). The two deny gates mirror them against `subject_role_deny_scopes` / `target_deny_scopes`. Because all gates test the *same* `function_name`, `allow` is a genuine per-scope intersection with deny-overrides. `agent_roles` / `agent_role_allow_scopes` / `agent_role_deny_scopes` are still emitted (informational / debugging) but `allow` does **not** reference them — `target_allow_scopes[input.target]` already *is* the per-scope capability gate. The inbound subject gate and `agent_scopes` are **not** used here: outbound decisions never consider the agent's own audience scopes.

```rego
package authz.{agent_slug}.outbound

agent_roles  := ["{role.name}", ...]                 # from agent_roles

subject_roles := { "{subject_id}": ["{role.name}", ...], ... }   # effect-agnostic

subject_role_allow_scopes := { "{role.name}": ["{scope.name}", ...], ... }  # from outbound_subject_allow_rules (user → tool)
subject_role_deny_scopes  := { "{role.name}": ["{scope.name}", ...], ... }  # from outbound_subject_deny_rules
agent_role_allow_scopes   := { "{role.name}": ["{scope.name}", ...], ... }  # from outbound_target_allow_rules (informational)
agent_role_deny_scopes    := { "{role.name}": ["{scope.name}", ...], ... }  # from outbound_target_deny_rules (informational)
target_allow_scopes       := { "{target_id}": ["{scope.name}", ...], ... }  # from target_allow_scopes
target_deny_scopes        := { "{target_id}": ["{scope.name}", ...], ... }  # from target_deny_scopes

# user may reach the tool: holds a role granted the REQUESTED scope (input.function_name)
subject_allow_ok if {
    some role in subject_roles[input.subject]
    input.function_name in subject_role_allow_scopes[role]
}
subject_deny_ok if {
    some role in subject_roles[input.subject]
    input.function_name in subject_role_deny_scopes[role]
}
# agent may reach the tool: the requested scope is one the target accepts (direct, per-scope)
target_allow_ok if {
    input.function_name in target_allow_scopes[input.target]
}
target_deny_ok if {
    input.function_name in target_deny_scopes[input.target]
}

default allow := false
allow if { subject_allow_ok; target_allow_ok; not subject_deny_ok; not target_deny_ok }
```

A worked example (agent `github-agent`, users `developer`/`tester`, tool `github-tool`) is maintained alongside the tests.

---

## Library: `aiac.pdp.policy.library.api`

HTTP client module wrapping the PDP Policy Writer REST API. Exposes four module-level functions. Service URL is read from the `AIAC_PDP_POLICY_URL` environment variable (default: `http://127.0.0.1:7072`). All functions raise `RuntimeError` on non-2xx response.

```python
def apply_policy(model: PolicyModel) -> None
    # POST /policy

def apply_agent_policy(agent_id: str, model: AgentPolicyModel) -> None
    # POST /policy/agents/{agent_id}

def delete_agent_policy(agent_id: str) -> None
    # DELETE /policy/agents/{agent_id}

def delete_policy() -> None
    # DELETE /policy
```

### Dependencies

```
requests
pydantic
python-dotenv
```

### Usage

```python
from aiac.pdp.policy.library.api import apply_policy, apply_agent_policy, delete_agent_policy, delete_policy
from aiac.policy.model.models import PolicyModel, AgentPolicyModel, PolicyRule

apply_agent_policy("weather-agent", agent_model)
delete_policy()
apply_policy(full_model)
```

---

## Configuration

| Variable | Required | Description |
|----------|----------|-------------|
| `AUTHORIZATION_POLICY_NAME` | TBD | Name of the `AuthorizationPolicy` CR to patch |
| `AUTHORIZATION_POLICY_NAMESPACE` | TBD | Namespace of the `AuthorizationPolicy` CR |

Authentication to the Kubernetes API: in-cluster service account (auto-detected by the `kubernetes` Python client). The pod's `ServiceAccount` must be bound to a `ClusterRole` granting `get`/`patch`/`update` on `AuthorizationPolicy` resources. The `ServiceAccount`, `ClusterRole`, and `ClusterRoleBinding` are declared in `pdp-interface-deployment.yaml`.

For local development, the `kubernetes` client falls back to `~/.kube/config` automatically.

> **Note:** `AuthorizationPolicy` CR schema and ConfigMap source for env vars are TBD.

---

## Runtime

- Framework: FastAPI
- Server: uvicorn
- Bind: `0.0.0.0:7072`
- Base image: `python:3.12-slim`
- Kubernetes ClusterIP Service: `aiac-pdp-policy-service:7072`
- Deployment: co-located with IdP Configuration Service as a container in the **Rossoctl Interface Pod** (`pdp-interface-deployment.yaml`)

---

## Dependencies (`requirements.txt`)

```
fastapi
uvicorn[standard]
kubernetes
pydantic
```

---

## File structure

```
aiac/src/aiac/pdp/service/
├── __init__.py
└── policy/
    ├── __init__.py
    └── opa/
        ├── __init__.py
        ├── Dockerfile
        ├── requirements.txt
        └── main.py

aiac/src/aiac/pdp/policy/
├── __init__.py
└── library/
    ├── __init__.py
    └── api.py          # apply_policy, apply_agent_policy, delete_agent_policy, delete_policy
                        # (models now imported from aiac.policy.model.models)
```

Build command:
```bash
docker build -f aiac/src/aiac/pdp/service/policy/opa/Dockerfile \
  -t aiac-pdp-policy-opa:latest aiac/src/
```

---

## `main.py` behaviour notes

- Load Kubernetes in-cluster config at startup via `kubernetes.config.load_incluster_config()`; fall back to `kubernetes.config.load_kube_config()` for local development.
- Instantiate a `kubernetes.client.CustomObjectsApi` for all CR operations.
- `_slugify(agent_id: str) -> str`: extract `{namespace}/{name}` from a SPIFFE URI (or use the plain `{ns}/{name}` clientId as-is), then collapse every non-alphanumeric run to `_` and lowercase — produces a valid Rego package name segment, short and SPIRE-independent.
- `_generate_inbound_rego(model: AgentPolicyModel) -> str`: render the inbound Rego package string. Embeds `agent_scopes`, `subject_roles`, `source_roles` (effect-agnostic), and the four grouped maps `subject_role_allow_scopes` / `subject_role_deny_scopes` (from `inbound_subject_{allow,deny}_rules`) and `source_role_allow_scopes` / `source_role_deny_scopes` (from `inbound_source_{allow,deny}_rules`); emits `subject_allow_ok` / `subject_deny_ok` and `source_allow_ok` (optional — an absent `input.source` passes) / `source_deny_ok`; `allow if { subject_allow_ok; source_allow_ok; not subject_deny_ok; not source_deny_ok }` (deny-overrides).
- `_generate_outbound_rego(model: AgentPolicyModel) -> str`: render the outbound Rego package string. Embeds `agent_roles`, `subject_roles` (effect-agnostic), `subject_role_allow_scopes` / `subject_role_deny_scopes` (from `outbound_subject_{allow,deny}_rules`), `agent_role_allow_scopes` / `agent_role_deny_scopes` (from `outbound_target_{allow,deny}_rules`, informational), and `target_allow_scopes` / `target_deny_scopes` (consumed directly, target id → scopes — **no inversion**); emits user→tool `subject_allow_ok` / `subject_deny_ok` (matching `input.function_name in subject_role_{allow,deny}_scopes[role]`) and capability `target_allow_ok` / `target_deny_ok` (matching `input.function_name in target_{allow,deny}_scopes[input.target]`); `allow if { subject_allow_ok; target_allow_ok; not subject_deny_ok; not target_deny_ok }` — a per-scope AND on the same `input.function_name` with deny-overrides. `agent_scopes` is not embedded in the outbound package — outbound decisions never consider the agent's own audience scopes.

> **Rollout impact.** These identifier renames are symmetric with **no alias / no back-compat**. All generated `.rego` **golden fixtures must be regenerated** to match the split gates. The demo helper `demo/use-cases/uc1-onboarding/lib/_lib.py` (which reads the `target_scopes` Rego map) must **retarget to `target_allow_scopes`**.
- `_upsert_agent(agent_id: str, inbound_rego: str, outbound_rego: str)`: patch the `AuthorizationPolicy` CR to upsert the two packages for `agent_id`. Schema TBD.
- `_delete_agent(agent_id: str)`: patch the CR to remove all packages for `agent_id`.
- `_delete_all()`: patch the CR to remove all packages.
- `POST /policy`: iterate `model.agents`; for each call `_generate_inbound_rego` + `_generate_outbound_rego` + `_upsert_agent`; return `Response(status_code=204)`.
- `POST /policy/agents/{agent_id}`: call `_generate_inbound_rego` + `_generate_outbound_rego` + `_upsert_agent`; return `Response(status_code=204)`.
- `DELETE /policy/agents/{agent_id}`: call `_delete_agent(agent_id)`; return `Response(status_code=204)`.
- `DELETE /policy`: call `_delete_all()`; return `Response(status_code=204)`.
- On Kubernetes API error, return HTTP 502 with `{"error": str(e)}`.
- `GET /health`: attempt to `get` the `AuthorizationPolicy` CR; return `200 {"status": "ok"}` on success, `503` on failure.

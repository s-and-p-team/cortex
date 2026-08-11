"""Rego package generation for the PDP Policy Writer (OPA).

Translates an ``AgentPolicyModel`` into Rego package strings ready to be
written to disk by the PDP Policy Writer.

The generated packages are **ID-only**: the Rego ``input`` carries only
``{subject, source, target}`` identifiers. All role/scope mappings are
embedded in the package, and ``allow`` resolves IDs -> roles -> scopes
internally.

**ALLOW/DENY (deny-overrides).** Each gate is emitted twice — an ``*_allow_ok``
gate driven by the ALLOW scope maps and a symmetric ``*_deny_ok`` gate driven by
the DENY scope maps. A request is permitted iff every ALLOW gate passes and no
DENY gate matches::

    # inbound
    allow if { subject_allow_ok; source_allow_ok; not subject_deny_ok; not source_deny_ok }
    # outbound
    allow if { subject_allow_ok; target_allow_ok; not subject_deny_ok; not target_deny_ok }
"""

import json
import re

from aiac.policy.model.models import AgentPolicyModel, PolicyRule

__all__ = ["slugify", "generate_inbound_rego", "generate_outbound_rego"]

_SPIFFE_RE = re.compile(r"^spiffe://[^/]+/ns/(?P<ns>[^/]+)/sa/(?P<name>[^/]+)$")

# A valid slug is a single filename/package segment: only [a-z0-9_], non-empty.
_SLUG_RE = re.compile(r"[a-z0-9_]+")


def _short_id(agent_id: str) -> str:
    """Reduce a clientId to ``{namespace}/{name}``, dropping the SPIFFE trust domain.

    Under SPIRE, agent_id is a SPIFFE URI (``spiffe://host/ns/{ns}/sa/{name}``); without
    SPIRE it's already ``{ns}/{name}``. Either way the trust domain/host is not part of a
    stable identity, so the slug must not depend on it.
    """
    match = _SPIFFE_RE.match(agent_id)
    return f"{match['ns']}/{match['name']}" if match else agent_id


def slugify(agent_id: str) -> str:
    """Turn an agent id into a valid Rego package name segment / filename.

    Predictable regardless of whether SPIRE is enabled: derived from ``{ns}/{name}``,
    not the full slash/colon-bearing clientId or SPIFFE URI.
    """
    slug = re.sub(r"[^a-z0-9]+", "_", _short_id(agent_id).lower()).strip("_")
    # The slug becomes a filename in the PDP Policy Writer's output dir, so it must be a single
    # inert segment: reject anything that isn't [a-z0-9_] (blocks ``/`` / ``..`` path traversal
    # from a hostile agent_id) or that collapses to empty (would yield ``.inbound.rego``).
    if not _SLUG_RE.fullmatch(slug):
        raise ValueError(f"agent_id {agent_id!r} does not yield a valid slug")
    return slug


def _render_list(var: str, values: list[str]) -> str:
    """Render ``{var} := ["a", "b"]`` as Rego (empty-safe: ``[]``).

    Each value is emitted via ``json.dumps`` so quotes/newlines/backslashes are escaped —
    Rego string syntax is JSON-compatible, and this prevents Rego injection / broken output."""
    inner = ", ".join(json.dumps(v) for v in values)
    return f"{var} := [{inner}]"


def _render_map(var: str, mapping: dict[str, list[str]]) -> str:
    """Render ``{var} := { "key": ["a", "b"], ... }`` as Rego (empty-safe: ``{}``).

    Keys and values are emitted via ``json.dumps`` so quotes/newlines/backslashes are escaped
    (JSON-compatible Rego string syntax) — this prevents Rego injection / broken output."""
    if not mapping:
        return f"{var} := {{}}"
    lines = [f"{var} := {{"]
    for key, values in mapping.items():
        inner = ", ".join(json.dumps(v) for v in values)
        lines.append(f"    {json.dumps(key)}: [{inner}],")
    lines.append("}")
    return "\n".join(lines)


def _group_rules(rules: list[PolicyRule]) -> dict[str, list[str]]:
    """Group rules into ``{role.name: [scope.name, ...]}`` preserving first-seen order."""
    grouped: dict[str, list[str]] = {}
    for rule in rules:
        scopes = grouped.setdefault(rule.role.name, [])
        if rule.scope.name not in scopes:
            scopes.append(rule.scope.name)
    return grouped


def _names(items) -> list[str]:
    """Extract the ``.name`` of each entity in a list."""
    return [item.name for item in items]


def _name_map(mapping) -> dict[str, list[str]]:
    """Turn ``{id: [entity, ...]}`` into ``{id: [entity.name, ...]}``."""
    return {key: _names(values) for key, values in mapping.items()}


# --- inbound gate templates -------------------------------------------------
#
# Each principal (subject / source) is gated twice against the SAME shape: an
# ``*_allow_ok`` gate reads the ALLOW scope map, a symmetric ``*_deny_ok`` gate
# reads the DENY scope map. Both require the matched scope to be one of the
# agent's own ``agent_scopes`` (the inbound audience). A subject/source that
# only appears in a DENY rule still resolves because the identity maps
# (``subject_roles`` / ``source_roles``) are effect-agnostic.


def _subject_gate(gate: str, scope_map: str) -> str:
    return (
        f"{gate} if {{\n"
        "    some role in subject_roles[input.subject]\n"
        f"    some scope in {scope_map}[role]\n"
        "    scope in agent_scopes\n"
        "}"
    )


def _source_allow_gate() -> str:
    # An absent source passes the ALLOW gate (source is optional inbound).
    return (
        "source_allow_ok if { not input.source }\n"
        "source_allow_ok if {\n"
        "    some role in source_roles[input.source]\n"
        "    some scope in source_role_allow_scopes[role]\n"
        "    scope in agent_scopes\n"
        "}"
    )


def _source_deny_gate() -> str:
    # An absent source has no roles, so the DENY gate simply never fires for it.
    return (
        "source_deny_ok if {\n"
        "    some role in source_roles[input.source]\n"
        "    some scope in source_role_deny_scopes[role]\n"
        "    scope in agent_scopes\n"
        "}"
    )


def generate_inbound_rego(model: AgentPolicyModel) -> str:
    """Render the ``authz.{slug}.inbound`` Rego package for an agent.

    Input is ``{subject, source}`` (ids only). ``subject`` is mandatory;
    ``source`` is optional (absent source passes the ALLOW gate). The decision is
    deny-overrides: it passes when the subject *and* source ALLOW gates pass and
    neither DENY gate matches. Each ALLOW/DENY gate is coarse — it fires when the
    principal holds a role granting/prohibiting >=1 of ``agent_scopes``.
    """
    slug = slugify(model.agent_id)
    parts = [
        f"package authz.{slug}.inbound",
        _render_list("agent_scopes", _names(model.agent_scopes)),
        _render_map("subject_roles", _name_map(model.subject_roles)),
        _render_map("source_roles", _name_map(model.source_roles)),
        _render_map(
            "subject_role_allow_scopes",
            _group_rules(model.inbound_subject_allow_rules),
        ),
        _render_map(
            "subject_role_deny_scopes",
            _group_rules(model.inbound_subject_deny_rules),
        ),
        _render_map(
            "source_role_allow_scopes",
            _group_rules(model.inbound_source_allow_rules),
        ),
        _render_map(
            "source_role_deny_scopes",
            _group_rules(model.inbound_source_deny_rules),
        ),
        _subject_gate("subject_allow_ok", "subject_role_allow_scopes"),
        _subject_gate("subject_deny_ok", "subject_role_deny_scopes"),
        _source_allow_gate(),
        _source_deny_gate(),
        (
            "default allow := false\n"
            "allow if { subject_allow_ok; source_allow_ok; "
            "not subject_deny_ok; not source_deny_ok }"
        ),
    ]
    return "\n\n".join(parts) + "\n"


# --- outbound gate templates ------------------------------------------------
#
# The outbound decision is a per-scope two-gate AND, both keyed on the requested
# scope ``input.function_name`` (user->target, where a target is a tool or another
# agent):
#   subject gate    — the user (subject) is granted the requested scope
#   capability gate — the agent reaches the requested scope on the requested target
# Each gate is emitted twice (allow/deny). ``allow`` is deny-overrides: both ALLOW
# gates pass on the requested scope and neither DENY gate matches it.


def _outbound_subject_gate(gate: str, scope_map: str) -> str:
    return (
        f"{gate} if {{\n"
        "    some role in subject_roles[input.subject]\n"
        f"    input.function_name in {scope_map}[role]\n"
        "}"
    )


def _target_gate(gate: str, scope_map: str) -> str:
    return f"{gate} if {{\n    input.function_name in {scope_map}[input.target]\n}}"


def generate_outbound_rego(model: AgentPolicyModel) -> str:
    """Render the ``authz.{slug}.outbound`` Rego package for an agent.

    Input is ``{subject, target, function_name}`` (ids only). ``function_name`` is the
    requested target scope. ``allow`` is a deny-overrides **per-scope AND** on that scope:
    the subject ALLOW gate passes iff the subject holds a role granted ``function_name``
    (user->target, via ``subject_role_allow_scopes`` from ``outbound_subject_allow_rules``),
    the capability ALLOW gate passes iff the agent reaches ``function_name`` on the requested
    ``target`` (``target_allow_scopes[input.target]``), and neither the ``subject_role_deny_scopes``
    nor the ``target_deny_scopes`` gate matches. Because every gate tests the *same*
    ``function_name``, ``allow`` is a genuine per-scope intersection minus the denies.

    ``target_allow_scopes`` / ``target_deny_scopes`` are used directly (target id -> scopes) --
    no inversion. A target is a tool the agent calls or another agent it calls. ``agent_roles`` /
    ``agent_role_scopes`` are still emitted (informational / debugging) but are not referenced by
    ``allow`` -- ``target_allow_scopes[input.target]`` already *is* the per-scope capability gate.
    """
    slug = slugify(model.agent_id)
    parts = [
        f"package authz.{slug}.outbound",
        _render_list("agent_roles", _names(model.agent_roles)),
        _render_map("subject_roles", _name_map(model.subject_roles)),
        _render_map(
            "subject_role_allow_scopes",
            _group_rules(model.outbound_subject_allow_rules),
        ),
        _render_map(
            "subject_role_deny_scopes",
            _group_rules(model.outbound_subject_deny_rules),
        ),
        _render_map(
            "agent_role_scopes", _group_rules(model.outbound_target_allow_rules)
        ),
        _render_map("target_allow_scopes", _name_map(model.target_allow_scopes)),
        _render_map("target_deny_scopes", _name_map(model.target_deny_scopes)),
        _outbound_subject_gate("subject_allow_ok", "subject_role_allow_scopes"),
        _outbound_subject_gate("subject_deny_ok", "subject_role_deny_scopes"),
        _target_gate("target_allow_ok", "target_allow_scopes"),
        _target_gate("target_deny_ok", "target_deny_scopes"),
        (
            "default allow := false\n"
            "allow if { subject_allow_ok; target_allow_ok; "
            "not subject_deny_ok; not target_deny_ok }"
        ),
    ]
    return "\n\n".join(parts) + "\n"

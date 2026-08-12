"""Unit tests for aiac.pdp.service.policy.opa.rego (ID-only model, ALLOW/DENY).

The writer emits split ``*_allow_ok`` / ``*_deny_ok`` gates and a deny-overrides
``allow`` rule. Scope maps are renamed symmetrically
(``subject_role_allow_scopes`` / ``_deny_scopes``, ``source_role_allow_scopes`` /
``_deny_scopes``, ``target_allow_scopes`` / ``target_deny_scopes``); the identity
maps (``subject_roles`` / ``source_roles`` / ``agent_roles``) keep their names.
"""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from aiac.idp.configuration.models import Role, Scope
from aiac.pdp.service.policy.opa.rego import (
    generate_inbound_rego,
    generate_outbound_rego,
    slugify,
)
from aiac.policy.model.models import AgentPolicyModel, PolicyRule, RuleEffect


def _role(name: str = "reader") -> Role:
    return Role(id=f"role-{name}", name=name, composite=False)


def _scope(name: str = "read") -> Scope:
    return Scope(id=f"scope-{name}", name=name)


def _rule(role: Role, scope: Scope, effect: RuleEffect = RuleEffect.ALLOW) -> PolicyRule:
    return PolicyRule(role=role, scope=scope, effect=effect)


def _model(
    agent_id: str = "weather-agent",
    agent_roles: list[Role] | None = None,
    agent_scopes: list[Scope] | None = None,
    subject_roles: dict[str, list[Role]] | None = None,
    source_roles: dict[str, list[Role]] | None = None,
    target_allow_scopes: dict[str, list[Scope]] | None = None,
    target_deny_scopes: dict[str, list[Scope]] | None = None,
    inbound_subject_allow_rules: list[PolicyRule] | None = None,
    inbound_subject_deny_rules: list[PolicyRule] | None = None,
    inbound_source_allow_rules: list[PolicyRule] | None = None,
    inbound_source_deny_rules: list[PolicyRule] | None = None,
    outbound_target_allow_rules: list[PolicyRule] | None = None,
    outbound_target_deny_rules: list[PolicyRule] | None = None,
    outbound_subject_allow_rules: list[PolicyRule] | None = None,
    outbound_subject_deny_rules: list[PolicyRule] | None = None,
) -> AgentPolicyModel:
    return AgentPolicyModel(
        agent_id=agent_id,
        agent_roles=agent_roles or [],
        agent_scopes=agent_scopes or [],
        subject_roles=subject_roles or {},
        source_roles=source_roles or {},
        target_allow_scopes=target_allow_scopes or {},
        target_deny_scopes=target_deny_scopes or {},
        inbound_subject_allow_rules=inbound_subject_allow_rules or [],
        inbound_subject_deny_rules=inbound_subject_deny_rules or [],
        inbound_source_allow_rules=inbound_source_allow_rules or [],
        inbound_source_deny_rules=inbound_source_deny_rules or [],
        outbound_target_allow_rules=outbound_target_allow_rules or [],
        outbound_target_deny_rules=outbound_target_deny_rules or [],
        outbound_subject_allow_rules=outbound_subject_allow_rules or [],
        outbound_subject_deny_rules=outbound_subject_deny_rules or [],
    )


def _github_agent() -> AgentPolicyModel:
    """The worked example from the handoff (allow-only)."""
    developer = _role("developer")
    tester = _role("tester")
    source_helper = _role("source-helper")
    issues_helper = _role("issues-helper")
    source_access = _scope("source-access")
    issues_access = _scope("issues-access")
    source_read = _scope("source-read")
    source_write = _scope("source-write")
    issues_read = _scope("issues-read")
    issues_write = _scope("issues-write")
    return _model(
        agent_id="github-agent",
        agent_roles=[source_helper, issues_helper],
        agent_scopes=[source_access, issues_access],
        subject_roles={"dev-user": [developer], "test-user": [tester]},
        target_allow_scopes={
            "github-tool": [source_read, source_write, issues_read, issues_write]
        },
        inbound_subject_allow_rules=[
            _rule(developer, source_access),
            _rule(developer, issues_access),
            _rule(tester, issues_access),
        ],
        outbound_target_allow_rules=[
            _rule(source_helper, source_read),
            _rule(source_helper, source_write),
            _rule(issues_helper, issues_read),
            _rule(issues_helper, issues_write),
        ],
        outbound_subject_allow_rules=[
            _rule(developer, source_read),
            _rule(developer, source_write),
            _rule(developer, issues_read),
            _rule(tester, issues_read),
            _rule(tester, issues_write),
        ],
    )


# --- slugify ---


def test_slugify_hyphens_become_underscores():
    assert slugify("weather-agent") == "weather_agent"


def test_slugify_lowercases_without_hyphens():
    assert slugify("WeatherAgent") == "weatheragent"


def test_slugify_strips_slashes_and_colons_from_spiffe_uri():
    slug = slugify("spiffe://localtest.me/ns/team1/sa/github-agent")
    assert "/" not in slug
    assert ":" not in slug
    assert "." not in slug


def test_slugify_spiffe_uri_extracts_namespace_and_name_short_id():
    """The slug must be predictable from just {namespace}/{name}, not the trust domain."""
    assert slugify("spiffe://localtest.me/ns/team1/sa/github-agent") == "team1_github_agent"
    assert (
        slugify("spiffe://other-trust-domain.example/ns/team1/sa/github-agent")
        == "team1_github_agent"
    )


def test_slugify_plain_ns_workload_clientid_matches_spiffe_slug():
    """Same {ns}/{workload} id, with or without SPIRE, must slugify identically."""
    assert slugify("team1/github-agent") == "team1_github_agent"


# --- generate_inbound_rego ---


def test_inbound_has_package_header_with_slug():
    rego = generate_inbound_rego(_model(agent_id="weather-agent"))
    assert "package authz.weather_agent.inbound" in rego


def test_inbound_embeds_agent_scopes_list():
    model = _model(agent_scopes=[_scope("source-access"), _scope("issues-access")])
    rego = generate_inbound_rego(model)
    assert 'agent_scopes := ["source-access", "issues-access"]' in rego


def test_inbound_embeds_subject_roles_map():
    model = _model(subject_roles={"dev-user": [_role("developer"), _role("tester")]})
    rego = generate_inbound_rego(model)
    assert "subject_roles := {" in rego
    assert '"dev-user": ["developer", "tester"]' in rego


def test_inbound_embeds_source_roles_map():
    model = _model(source_roles={"github-tool": [_role("reader")]})
    rego = generate_inbound_rego(model)
    assert "source_roles := {" in rego
    assert '"github-tool": ["reader"]' in rego


def test_inbound_subject_role_allow_scopes_grouped_from_allow_rules():
    model = _github_agent()
    rego = generate_inbound_rego(model)
    assert "subject_role_allow_scopes := {" in rego
    assert '"developer": ["source-access", "issues-access"]' in rego
    assert '"tester": ["issues-access"]' in rego


def test_inbound_split_scope_maps_from_split_rule_lists():
    """subject/source allow/deny scope maps each come from their own rule list."""
    dev = _role("developer")
    banned = _role("banned")
    src_ok = _role("src-ok")
    src_bad = _role("src-bad")
    access = _scope("access")
    model = _model(
        agent_scopes=[access],
        inbound_subject_allow_rules=[_rule(dev, access)],
        inbound_subject_deny_rules=[_rule(banned, access, RuleEffect.DENY)],
        inbound_source_allow_rules=[_rule(src_ok, access)],
        inbound_source_deny_rules=[_rule(src_bad, access, RuleEffect.DENY)],
    )
    rego = generate_inbound_rego(model)
    assert 'subject_role_allow_scopes := {\n    "developer": ["access"],' in rego
    assert 'subject_role_deny_scopes := {\n    "banned": ["access"],' in rego
    assert 'source_role_allow_scopes := {\n    "src-ok": ["access"],' in rego
    assert 'source_role_deny_scopes := {\n    "src-bad": ["access"],' in rego


def test_inbound_has_split_allow_deny_gates_and_deny_overrides_allow():
    rego = generate_inbound_rego(_github_agent())
    # split subject gates
    assert "subject_allow_ok if {" in rego
    assert "subject_deny_ok if {" in rego
    assert "some role in subject_roles[input.subject]" in rego
    assert "some scope in subject_role_allow_scopes[role]" in rego
    assert "some scope in subject_role_deny_scopes[role]" in rego
    assert "scope in agent_scopes" in rego
    # split source gates (absent source passes the allow gate)
    assert "source_allow_ok if { not input.source }" in rego
    assert "some scope in source_role_allow_scopes[role]" in rego
    assert "source_deny_ok if {" in rego
    assert "some scope in source_role_deny_scopes[role]" in rego
    # deny-overrides allow
    assert "default allow := false" in rego
    assert (
        "allow if { subject_allow_ok; source_allow_ok; "
        "not subject_deny_ok; not source_deny_ok }" in rego
    )


def test_inbound_has_no_legacy_identifiers():
    rego = generate_inbound_rego(_github_agent())
    assert "input.role" not in rego
    assert "input.scope" not in rego
    assert "scope_targets" not in rego
    # The pre-split single-effect names are gone (no alias / no back-compat).
    assert "role_scopes" not in rego
    assert "subject_ok" not in rego
    assert "source_ok if" not in rego


def test_inbound_empty_model_renders_valid_empty_literals():
    rego = generate_inbound_rego(_model())
    assert "agent_scopes := []" in rego
    assert "subject_roles := {}" in rego
    assert "source_roles := {}" in rego
    assert "subject_role_allow_scopes := {}" in rego
    assert "subject_role_deny_scopes := {}" in rego
    assert "source_role_allow_scopes := {}" in rego
    assert "source_role_deny_scopes := {}" in rego
    assert "default allow := false" in rego
    assert (
        "allow if { subject_allow_ok; source_allow_ok; "
        "not subject_deny_ok; not source_deny_ok }" in rego
    )


# --- generate_outbound_rego ---


def test_outbound_has_package_header_with_slug():
    rego = generate_outbound_rego(_model(agent_id="weather-agent"))
    assert "package authz.weather_agent.outbound" in rego


def test_outbound_embeds_agent_roles_list():
    rego = generate_outbound_rego(_github_agent())
    assert 'agent_roles := ["source-helper", "issues-helper"]' in rego
    # agent_scopes is the inbound audience gate; the outbound package must not emit it.
    assert "agent_scopes :=" not in rego


def test_outbound_agent_role_scopes_grouped_from_target_allow_rules():
    rego = generate_outbound_rego(_github_agent())
    assert "agent_role_scopes := {" in rego
    assert '"source-helper": ["source-read", "source-write"]' in rego
    assert '"issues-helper": ["issues-read", "issues-write"]' in rego


def test_outbound_target_allow_and_deny_scopes_rendered_directly():
    dev = _role("developer")
    read = _scope("source-read")
    secret = _scope("source-delete")
    model = _model(
        agent_id="github-agent",
        subject_roles={"dev-user": [dev]},
        target_allow_scopes={"github-tool": [read]},
        target_deny_scopes={"github-tool": [secret]},
        outbound_subject_allow_rules=[_rule(dev, read)],
        outbound_subject_deny_rules=[_rule(dev, secret, RuleEffect.DENY)],
    )
    rego = generate_outbound_rego(model)
    assert 'target_allow_scopes := {\n    "github-tool": ["source-read"],' in rego
    assert 'target_deny_scopes := {\n    "github-tool": ["source-delete"],' in rego
    assert "scope_targets" not in rego


def test_outbound_subject_role_allow_and_deny_scopes_grouped():
    rego = generate_outbound_rego(_github_agent())
    assert "subject_role_allow_scopes := {" in rego
    assert '"developer": ["source-read", "source-write", "issues-read"]' in rego
    assert '"tester": ["issues-read", "issues-write"]' in rego


def test_outbound_subject_gate_keys_on_function_name_not_agent_scopes():
    rego = generate_outbound_rego(_github_agent())
    # The outbound subject gate is user->target, keyed on the requested scope: it reads
    # subject_role_allow_scopes / _deny_scopes and tests input.function_name directly.
    assert "subject_allow_ok if {" in rego
    assert "subject_deny_ok if {" in rego
    assert "some role in subject_roles[input.subject]" in rego
    assert "input.function_name in subject_role_allow_scopes[role]" in rego
    assert "input.function_name in subject_role_deny_scopes[role]" in rego
    # The inbound-flavoured subject gate must NOT appear in the outbound package.
    assert "scope in agent_scopes" not in rego


def test_outbound_does_not_embed_inbound_scope_maps():
    rego = generate_outbound_rego(_github_agent())
    # The inbound source scope maps must not leak into the outbound package.
    assert "source_role_allow_scopes" not in rego
    assert "source_role_deny_scopes" not in rego


def test_outbound_has_split_target_gates_and_deny_overrides_allow():
    rego = generate_outbound_rego(_github_agent())
    # The capability gates test the requested scope against the target's scopes directly.
    assert "target_allow_ok if {" in rego
    assert "input.function_name in target_allow_scopes[input.target]" in rego
    assert "target_deny_ok if {" in rego
    assert "input.function_name in target_deny_scopes[input.target]" in rego
    assert "default allow := false" in rego
    assert (
        "allow if { subject_allow_ok; target_allow_ok; "
        "not subject_deny_ok; not target_deny_ok }" in rego
    )
    # allow must not reference the informational agent_roles/agent_role_scopes existential.
    assert "some role in agent_roles" not in rego


def test_outbound_has_no_legacy_identifiers():
    rego = generate_outbound_rego(_github_agent())
    assert "input.role" not in rego
    assert "input.scope" not in rego
    assert "scope_targets" not in rego
    # pre-split names gone (no alias / no back-compat).
    assert "subject_role_scopes" not in rego
    assert "target_scopes := " not in rego
    assert "subject_ok if" not in rego
    assert "target_ok if" not in rego


def test_outbound_empty_model_renders_valid_empty_literals():
    rego = generate_outbound_rego(_model())
    assert "agent_roles := []" in rego
    assert "subject_roles := {}" in rego
    assert "subject_role_allow_scopes := {}" in rego
    assert "subject_role_deny_scopes := {}" in rego
    assert "agent_role_scopes := {}" in rego
    assert "target_allow_scopes := {}" in rego
    assert "target_deny_scopes := {}" in rego
    assert "default allow := false" in rego
    assert (
        "allow if { subject_allow_ok; target_allow_ok; "
        "not subject_deny_ok; not target_deny_ok }" in rego
    )


# --- per-scope AND intersection + deny-overrides semantics ---


def _outbound_and_model() -> AgentPolicyModel:
    """Pins per-scope-AND + deny-overrides. The user (subject gate) reaches {A, C, D}; the agent
    reaches {B, C, D} on target T (capability gate); and D is denied for the user (subject deny).
    So only C is allowed — A (user-only), B (agent-only) fail the AND, and D is deny-overridden."""
    user = _role("u-role")
    operator = _role("op-role")
    a, b, c, d = _scope("scope-a"), _scope("scope-b"), _scope("scope-c"), _scope("scope-d")
    return _model(
        agent_id="github-agent",
        agent_roles=[operator],
        subject_roles={"user1": [user]},
        # target_allow_scopes IS the capability gate: the agent reaches {B, C, D} on "T".
        target_allow_scopes={"T": [b, c, d]},
        # user (subject allow gate) reaches {A, C, D}.
        outbound_subject_allow_rules=[
            _rule(user, a),
            _rule(user, c),
            _rule(user, d),
        ],
        # user is barred from D (deny-overrides even though both allow gates grant it).
        outbound_subject_deny_rules=[_rule(user, d, RuleEffect.DENY)],
        # informational agent_role_scopes (not referenced by allow): operator reaches {B, C, D}.
        outbound_target_allow_rules=[
            _rule(operator, b),
            _rule(operator, c),
            _rule(operator, d),
        ],
    )


def test_outbound_per_scope_and_structural():
    """Structural: the gates read the same request scope from disjoint maps — subject allow grants
    {A, C, D}, capability allow grants {B, C, D} on T, subject deny bars {D} — so allow is their
    per-scope intersection minus the deny."""
    rego = generate_outbound_rego(_outbound_and_model())
    assert '"u-role": ["scope-a", "scope-c", "scope-d"]' in rego  # subject allow gate
    assert '"T": ["scope-b", "scope-c", "scope-d"]' in rego  # capability allow gate
    assert "input.function_name in subject_role_allow_scopes[role]" in rego
    assert "input.function_name in subject_role_deny_scopes[role]" in rego
    assert "input.function_name in target_allow_scopes[input.target]" in rego
    assert (
        "allow if { subject_allow_ok; target_allow_ok; "
        "not subject_deny_ok; not target_deny_ok }" in rego
    )


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize(
    "function_name, allowed",
    [
        ("scope-c", True),  # in BOTH allow gates, not denied -> allowed
        ("scope-a", False),  # user-only (not in the agent's capability gate) -> denied
        ("scope-b", False),  # agent-only (not in the user's subject gate) -> denied
        ("scope-d", False),  # in both allow gates BUT subject-denied -> deny-overrides
    ],
)
def test_outbound_per_scope_and_denies_mismatch(function_name: str, allowed: bool):
    """Behavioural: evaluate the generated ``allow`` with ``opa eval``. Only the scope in both allow
    gates and not denied (C) is allowed; user-only (A), agent-only (B), and the deny-overridden (D)
    are all denied — pinning the per-scope intersection AND deny-overrides."""
    rego = generate_outbound_rego(_outbound_and_model())
    _assert_opa_allow(
        rego,
        "data.authz.github_agent.outbound.allow",
        {"subject": "user1", "target": "T", "function_name": function_name},
        allowed,
    )


def _inbound_deny_model() -> AgentPolicyModel:
    """A subject that both allows and denies the audience scope — deny-overrides must bar it."""
    good = _role("good")
    banned = _role("banned")
    access = _scope("access")
    return _model(
        agent_id="github-agent",
        agent_scopes=[access],
        subject_roles={"ok-user": [good], "bad-user": [good, banned]},
        inbound_subject_allow_rules=[_rule(good, access)],
        inbound_subject_deny_rules=[_rule(banned, access, RuleEffect.DENY)],
    )


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize(
    "subject, allowed",
    [
        ("ok-user", True),  # holds only the allow role
        ("bad-user", False),  # holds a deny role -> deny-overrides
    ],
)
def test_inbound_deny_overrides_behavioural(subject: str, allowed: bool):
    rego = generate_inbound_rego(_inbound_deny_model())
    _assert_opa_allow(
        rego,
        "data.authz.github_agent.inbound.allow",
        {"subject": subject},
        allowed,
    )


def _inbound_source_deny_model() -> AgentPolicyModel:
    """A fully-allowed subject paired with a source that both allows and denies the audience scope.
    The colliding source ALLOW+DENY must resolve deny-overrides via the ``source_deny_ok`` gate,
    barring the request even though the subject and the source's allow role both pass."""
    good = _role("good")
    src_ok = _role("src-ok")
    src_bad = _role("src-bad")
    access = _scope("access")
    return _model(
        agent_id="github-agent",
        agent_scopes=[access],
        subject_roles={"user1": [good]},
        source_roles={"clean-src": [src_ok], "tainted-src": [src_ok, src_bad]},
        inbound_subject_allow_rules=[_rule(good, access)],
        inbound_source_allow_rules=[_rule(src_ok, access)],
        inbound_source_deny_rules=[_rule(src_bad, access, RuleEffect.DENY)],
    )


@pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")
@pytest.mark.parametrize(
    "source, allowed",
    [
        ("clean-src", True),  # source holds only the allow role -> passes
        ("tainted-src", False),  # source holds a colliding deny role -> source deny-overrides
    ],
)
def test_inbound_source_deny_overrides_behavioural(source: str, allowed: bool):
    """Behavioural: a denied SOURCE wins over a colliding source ALLOW (and an allowed subject),
    exercising the ``source_allow_ok`` / ``source_deny_ok`` split on the source dimension — a path
    the other behavioural deny tests (subject inbound / subject outbound) do not cover."""
    rego = generate_inbound_rego(_inbound_source_deny_model())
    _assert_opa_allow(
        rego,
        "data.authz.github_agent.inbound.allow",
        {"subject": "user1", "source": source},
        allowed,
    )


def _assert_opa_allow(rego: str, query: str, input_doc: dict, expected: bool) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "policy.rego"
        path.write_text(rego)
        cmd = [
            shutil.which("opa"), "eval", "-f", "json", "-d", str(path),
            "--stdin-input", query,
        ]
        out = subprocess.run(
            cmd,
            input=json.dumps(input_doc),
            capture_output=True, text=True, check=True,
        ).stdout
        result = json.loads(out)["result"][0]["expressions"][0]["value"]
    assert result is expected, f"input={input_doc!r}"

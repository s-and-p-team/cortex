package access

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// rl builds a rule as the resolver would, from the text in a settings file.
func rl(d Decision, raw string) Rule {
	tool, pattern := parseRule(raw)
	return Rule{Decision: d, Raw: raw, Tool: tool, Pattern: pattern, Source: User, File: "/h/.claude/settings.json"}
}

// pol is a policy with these rules in exactly this order. Resolve sorts them deny, ask, allow;
// the matcher must not depend on that, so tests hand them over in whatever order they like.
func pol(rs ...Rule) Policy { return Policy{Rules: rs} }

func call(tool string) Call { return Call{Tool: tool, Input: map[string]any{}} }

func wantVerdict(t *testing.T, got Result, want Verdict) {
	t.Helper()
	if got.Verdict != want {
		t.Fatalf("verdict = %v, want %v\nresult: %+v", got.Verdict, want, got)
	}
}

func hasCaveat(r Result, sub string) bool {
	for _, c := range r.Caveats {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

// Tool-name matching, from the permissions docs ("Match all uses of a tool", "Tool name
// wildcards", "MCP", "Read and Edit"). Every row is a bare rule or a name glob; specifiers are
// the later tasks'.
func TestMatch_ToolNames(t *testing.T) {
	cases := []struct {
		name   string
		rule   Rule
		tool   string
		want   Verdict
		caveat string // a substring a caveat must contain, when set
	}{
		{"bare tool allow", rl(Allow, "Bash"), "Bash", VerdictAllow, ""},
		{"bare tool deny", rl(Deny, "Read"), "Read", VerdictDeny, ""},
		{"bare tool ask", rl(Ask, "WebFetch"), "WebFetch", VerdictAsk, ""},
		{"Bash(*) is the bare tool", rl(Allow, "Bash(*)"), "Bash", VerdictAllow, ""},
		{"another tool does not match", rl(Deny, "Read"), "Bash", VerdictNone, ""},
		{"names are case-sensitive", rl(Deny, "bash"), "Bash", VerdictNone, ""},
		{"a prefix of the name is not the name", rl(Deny, "Bas"), "Bash", VerdictNone, ""},

		// deny and ask accept globs in the tool-name position; the pattern matches the full name
		{"deny * matches every tool", rl(Deny, "*"), "Bash", VerdictDeny, ""},
		{"ask * matches every tool", rl(Ask, "*"), "Read", VerdictAsk, ""},
		{"deny mcp__* matches an MCP tool", rl(Deny, "mcp__*"), "mcp__srv__tool", VerdictDeny, ""},
		{"deny mcp__* does not match Bash", rl(Deny, "mcp__*"), "Bash", VerdictNone, ""},
		{"deny B* matches Bash", rl(Deny, "B*"), "Bash", VerdictDeny, ""},
		{"deny glob must match the whole name", rl(Deny, "B*h*x"), "Bash", VerdictNone, ""},
		{"deny mcp__github__get_* matches a get_ tool", rl(Deny, "mcp__github__get_*"), "mcp__github__get_issue", VerdictDeny, ""},
		{"deny mcp__github__get_* does not match create_", rl(Deny, "mcp__github__get_*"), "mcp__github__create_issue", VerdictNone, ""},

		// allow accepts a glob only after a literal mcp__<server>__ prefix; the rest are skipped
		{"allow * is skipped", rl(Allow, "*"), "Bash", VerdictNone, ""},
		{"allow B* is skipped", rl(Allow, "B*"), "Bash", VerdictNone, ""},
		{"allow mcp__* is skipped", rl(Allow, "mcp__*"), "mcp__srv__tool", VerdictNone, ""},
		{"allow glob in the server segment is skipped", rl(Allow, "mcp__gith*__x"), "mcp__github__x", VerdictNone, ""},
		{"allow mcp__srv__* matches the server's tools", rl(Allow, "mcp__srv__*"), "mcp__srv__tool", VerdictAllow, ""},
		{"allow mcp__srv__* does not match another server", rl(Allow, "mcp__srv__*"), "mcp__other__tool", VerdictNone, ""},
		{"allow mcp__github__get_* matches get_", rl(Allow, "mcp__github__get_*"), "mcp__github__get_issue", VerdictAllow, ""},
		{"allow mcp__github__get_* does not match create_", rl(Allow, "mcp__github__get_*"), "mcp__github__create_issue", VerdictNone, ""},
		{"allow with an empty server segment is skipped", rl(Allow, "mcp____*"), "mcp____x", VerdictNone, ""},

		// mcp__<server> matches any tool of that server
		{"bare server deny", rl(Deny, "mcp__srv"), "mcp__srv__tool", VerdictDeny, ""},
		{"bare server ask", rl(Ask, "mcp__srv"), "mcp__srv__tool", VerdictAsk, ""},
		{"bare server allow", rl(Allow, "mcp__srv"), "mcp__srv__tool", VerdictAllow, ""},
		{"bare server is not a prefix match on the name", rl(Deny, "mcp__srv"), "mcp__srv2__tool", VerdictNone, ""},
		{"exact MCP tool", rl(Allow, "mcp__srv__tool"), "mcp__srv__tool", VerdictAllow, ""},
		{"a different tool of the same server", rl(Allow, "mcp__srv__tool"), "mcp__srv__other", VerdictNone, ""},
		// Claude Code skips any mcp__ rule that has parentheses
		{"an mcp__ rule with parentheses is skipped", rl(Deny, "mcp__srv__tool(x)"), "mcp__srv__tool", VerdictNone, ""},

		// A server name containing __ makes the server of mcp__a__b__c ambiguous: the docs say a
		// deny or ask covers it, and an allow does not, so the allow cannot be evaluated.
		{"deny covers a server with __ in its name", rl(Deny, "mcp__reports"), "mcp__reports__v2__t", VerdictDeny, ""},
		{"allow on an ambiguous server name is not evaluated", rl(Allow, "mcp__reports"), "mcp__reports__v2__t", VerdictNone, "mcp__reports"},
		{"the full wildcard form names the server exactly", rl(Allow, "mcp__reports__v2__*"), "mcp__reports__v2__t", VerdictAllow, ""},

		// Edit rules apply to every built-in tool that edits files
		{"Edit deny covers Write", rl(Deny, "Edit"), "Write", VerdictDeny, ""},
		{"Edit deny covers NotebookEdit", rl(Deny, "Edit"), "NotebookEdit", VerdictDeny, ""},
		{"Edit deny covers MultiEdit", rl(Deny, "Edit"), "MultiEdit", VerdictDeny, ""},
		{"Edit allow covers Write", rl(Allow, "Edit"), "Write", VerdictAllow, ""},
		{"Write does not cover Edit", rl(Deny, "Write"), "Edit", VerdictNone, ""},
		// Read deny/ask rules are applied to Grep and Glob on a best-effort basis, never allows
		{"Read deny covers Grep", rl(Deny, "Read"), "Grep", VerdictDeny, "best-effort"},
		{"Read ask covers Glob", rl(Ask, "Read"), "Glob", VerdictAsk, "best-effort"},
		{"Read allow does not cover Grep", rl(Allow, "Read"), "Grep", VerdictNone, ""},
		{"Grep does not cover Read", rl(Deny, "Grep"), "Read", VerdictNone, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := pol(c.rule).Match(call(c.tool), MatchContext{})
			wantVerdict(t, got, c.want)
			if c.caveat != "" && !hasCaveat(got, c.caveat) {
				t.Errorf("caveats = %q, want one containing %q", got.Caveats, c.caveat)
			}
			if c.want == VerdictDeny || c.want == VerdictAsk || c.want == VerdictAllow {
				if len(got.Rules) != 1 || got.Rules[0].Raw != c.rule.Raw {
					t.Errorf("Rules = %+v, want the deciding rule %q", got.Rules, c.rule.Raw)
				}
			}
		})
	}
}

// Write(path), Grep(path), Glob(path), NotebookEdit(path) and MultiEdit(path) are accepted by
// Claude Code but never match: only Edit(path) and Read(path) are checked. A user who wrote a
// Write(docs/**) deny believes docs is protected; it is not, and the result must say so.
func TestMatch_WriteGrepGlobPathRulesNeverMatch(t *testing.T) {
	for _, tool := range []string{"Write", "Grep", "Glob", "NotebookEdit", "MultiEdit"} {
		raw := tool + "(docs/**)"
		got := pol(rl(Deny, raw)).Match(Call{Tool: tool, Input: map[string]any{"file_path": "docs/a.md", "path": "docs"}}, MatchContext{})
		wantVerdict(t, got, VerdictNone)
		if len(got.Unevaluated) != 0 {
			t.Errorf("%s: a rule that never matches is evaluated (as not matching), not unknown: %+v", raw, got.Unevaluated)
		}
		if !hasCaveat(got, raw) || !hasCaveat(got, "Edit") && !hasCaveat(got, "Read") {
			t.Errorf("%s: caveats = %q, want it to name the rule and say which rule to write", raw, got.Caveats)
		}
	}
	// ...but a match-all form of the same tool works: the docs say "other than *".
	for _, raw := range []string{"Write(*)", "Grep(*)", "Glob(*)", "NotebookEdit(*)"} {
		tool, _, _ := strings.Cut(raw, "(")
		wantVerdict(t, pol(rl(Deny, raw)).Match(call(tool), MatchContext{}), VerdictDeny)
	}
}

func TestMatch_OrderIsDenyThenAskThenAllowRegardlessOfLayerOrSliceOrder(t *testing.T) {
	allowLocal := rl(Allow, "Bash")
	allowLocal.Source = Local
	askProject := rl(Ask, "Bash")
	askProject.Source = Project
	denyUser := rl(Deny, "Bash")
	denyUser.Source = User

	for _, order := range [][]Rule{
		{allowLocal, askProject, denyUser}, {denyUser, askProject, allowLocal}, {askProject, allowLocal, denyUser},
	} {
		got := pol(order...).Match(call("Bash"), MatchContext{})
		wantVerdict(t, got, VerdictDeny)
		if got.Rules[0].Source != User {
			t.Errorf("deciding rule is from %v, want the user-layer deny", got.Rules[0].Source)
		}
	}
	wantVerdict(t, pol(allowLocal, askProject).Match(call("Bash"), MatchContext{}), VerdictAsk)
	wantVerdict(t, pol(askProject, allowLocal).Match(call("Bash"), MatchContext{}), VerdictAsk)
}

func TestMatch_EveryMatchingRuleOfTheWinningDecisionIsReported(t *testing.T) {
	a, b := rl(Deny, "Bash"), rl(Deny, "*")
	got := pol(a, b, rl(Allow, "Bash")).Match(call("Bash"), MatchContext{})
	wantVerdict(t, got, VerdictDeny)
	if len(got.Rules) != 2 {
		t.Errorf("Rules = %+v, want both denies and not the allow", got.Rules)
	}
}

func TestMatch_IgnoredRulesAreSkipped(t *testing.T) {
	deny := rl(Deny, "Bash")
	deny.Ignored = "ignored: allowManagedPermissionRulesOnly is set in managed settings"
	got := pol(deny, rl(Allow, "Bash")).Match(call("Bash"), MatchContext{})
	wantVerdict(t, got, VerdictAllow) // the ignored deny neither denies nor makes the answer unknown
	if len(got.Unevaluated) != 0 {
		t.Errorf("an ignored rule is not unevaluated: %+v", got.Unevaluated)
	}
}

func TestMatch_AProjectAllowThatNeedsTrustSaysSo(t *testing.T) {
	r := rl(Allow, "Bash")
	r.Source, r.NeedsTrust = Project, true
	got := pol(r).Match(call("Bash"), MatchContext{})
	wantVerdict(t, got, VerdictAllow)
	if !hasCaveat(got, "trust") {
		t.Errorf("caveats = %q, want the workspace-trust condition", got.Caveats)
	}
	// ...unless another matching allow does not depend on trust.
	other := rl(Allow, "Bash")
	other.Source = User
	if got := pol(r, other).Match(call("Bash"), MatchContext{}); hasCaveat(got, "trust") {
		t.Errorf("an allow that needs no trust also matches, so the caveat is noise: %q", got.Caveats)
	}
}

// A rule this matcher cannot evaluate (here a specifier on a tool it knows nothing about) must
// never let a LOWER decision be reported past it: an unevaluated deny might be the deny.
func TestMatch_AnUnevaluableRuleNeverLetsALowerDecisionThrough(t *testing.T) {
	unk := func(d Decision) Rule { return rl(d, "Custom(whatever)") }
	cases := []struct {
		name  string
		rules []Rule
		want  Verdict
	}{
		{"unevaluable deny + matching allow", []Rule{unk(Deny), rl(Allow, "Custom")}, VerdictUnknown},
		{"unevaluable deny + matching ask", []Rule{unk(Deny), rl(Ask, "Custom")}, VerdictUnknown},
		{"unevaluable deny alone", []Rule{unk(Deny)}, VerdictUnknown},
		{"unevaluable ask + matching allow", []Rule{unk(Ask), rl(Allow, "Custom")}, VerdictUnknown},
		{"unevaluable ask alone", []Rule{unk(Ask)}, VerdictUnknown},
		// a higher decision that DID match makes the unevaluable lower ones irrelevant
		{"matching deny + unevaluable deny", []Rule{unk(Deny), rl(Deny, "Custom")}, VerdictDeny},
		{"matching deny + unevaluable ask", []Rule{unk(Ask), rl(Deny, "Custom")}, VerdictDeny},
		{"matching ask + unevaluable ask", []Rule{unk(Ask), rl(Ask, "Custom")}, VerdictAsk},
		{"matching ask + unevaluable allow", []Rule{unk(Allow), rl(Ask, "Custom")}, VerdictAsk},
		{"matching allow + unevaluable allow", []Rule{unk(Allow), rl(Allow, "Custom")}, VerdictAllow},
		// an unevaluable allow could only ever have allowed: not an allow, not a prompt
		{"unevaluable allow alone", []Rule{unk(Allow)}, VerdictNone},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := pol(c.rules...).Match(call("Custom"), MatchContext{})
			wantVerdict(t, got, c.want)
			wantUnk := false
			for _, r := range c.rules {
				wantUnk = wantUnk || r.Pattern != ""
			}
			if got.Verdict == VerdictUnknown && len(got.Unevaluated) == 0 {
				t.Error("Unknown without saying which rule could not be evaluated")
			}
			if c.want == VerdictNone && (len(got.Unevaluated) != 1 || len(got.Caveats) == 0) {
				t.Errorf("a None past an unevaluated allow must name it and carry a caveat: %+v", got)
			}
		})
	}
}

func TestMatch_NoRulesAtAllIsNoneNotAllow(t *testing.T) {
	for _, p := range []Policy{{}, pol(), pol(rl(Allow, "Read"))} {
		got := p.Match(call("Bash"), MatchContext{})
		wantVerdict(t, got, VerdictNone)
		if len(got.Rules) != 0 {
			t.Errorf("Rules = %+v for a verdict of none", got.Rules)
		}
	}
}

func TestMatch_ResultJSONUsesNamesAndNeverNull(t *testing.T) {
	b, err := json.Marshal(pol().Match(call("Bash"), MatchContext{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"verdict":"none"`, `"rules":[]`, `"unevaluated":[]`, `"caveats":[]`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("JSON lacks %s: %s", want, b)
		}
	}
}

func TestVerdict_Names(t *testing.T) {
	want := map[Verdict]string{VerdictNone: "none", VerdictDeny: "deny", VerdictAsk: "ask",
		VerdictAllow: "allow", VerdictPartial: "partial", VerdictUnknown: "unknown"}
	for v, s := range want {
		if v.String() != s {
			t.Errorf("%d.String() = %q, want %q", v, v.String(), s)
		}
	}
}

// --- CallFromJSON ---------------------------------------------------------------------------

func TestCallFromJSON(t *testing.T) {
	c, err := CallFromJSON("Bash", `{"command":"ls -la","timeout":5000,"run_in_background":true}`)
	if err != nil {
		t.Fatal(err)
	}
	if c.Tool != "Bash" || c.Input["command"] != "ls -la" {
		t.Errorf("Call = %+v", c)
	}
	// Numbers keep their literal text: a parameter rule compares what Claude sent, and a float64
	// would turn 12345678901234567890 into 1.2345678901234567e19.
	c, err = CallFromJSON("Bash", `{"timeout":12345678901234567890}`)
	if err != nil {
		t.Fatal(err)
	}
	if n, ok := c.Input["timeout"].(json.Number); !ok || n.String() != "12345678901234567890" {
		t.Errorf("timeout = %#v, want the literal json.Number", c.Input["timeout"])
	}
	for _, empty := range []string{"", "  ", "null", "{}"} {
		c, err := CallFromJSON("TaskStop", empty)
		if err != nil || c.Input == nil || len(c.Input) != 0 {
			t.Errorf("CallFromJSON(%q) = %+v, %v; want a call with an empty, non-nil Input", empty, c, err)
		}
	}
}

func TestCallFromJSON_RefusesWhatItCannotUse(t *testing.T) {
	for name, args := range map[string]string{
		"array":     `[1,2]`,
		"string":    `"x"`,
		"number":    `5`,
		"truncated": `{"command":"ls`,
		"trailing":  `{"a":1} {"b":2}`,
		"too deep":  strings.Repeat(`{"a":`, 100000) + `1` + strings.Repeat(`}`, 100000),
		"not json":  `command=ls`,
	} {
		if _, err := CallFromJSON("Bash", args); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestCallFromJSON_RefusesAnOversizeInputWithATypedError(t *testing.T) {
	huge := `{"command":"` + strings.Repeat("a", 2<<20) + `"}`
	_, err := CallFromJSON("Bash", huge)
	if !errors.Is(err, ErrInputTooLarge) {
		t.Errorf("err = %v, want ErrInputTooLarge", err)
	}
}

// The matcher is fed arbitrary tool input and rule text from a cloned repository.
func TestMatch_ToleratesAbsurdInput(t *testing.T) {
	stars := strings.Repeat("*", 10000)
	rules := pol(rl(Deny, stars), rl(Allow, "mcp__srv__"+stars), rl(Ask, stars+"x"+stars))
	for _, tool := range []string{"", "Bash", strings.Repeat("a", 100000), "mcp__srv__" + strings.Repeat("b", 100000)} {
		_ = rules.Match(Call{Tool: tool}, MatchContext{})
	}
	var nilInput Call
	_ = pol(rl(Deny, "Bash")).Match(nilInput, MatchContext{})
}

// The depth guard must be what refuses a deeply nested input, not whatever limit the JSON
// decoder happens to have: the guard runs before decoding, so a hostile row costs one scan.
func TestCallFromJSON_TheDepthGuardIsOurOwn(t *testing.T) {
	ok := strings.Repeat(`{"a":`, maxCallInputDepth) + `1` + strings.Repeat(`}`, maxCallInputDepth)
	if _, err := CallFromJSON("Bash", ok); err != nil {
		t.Errorf("nesting exactly at the limit was refused: %v", err)
	}
	over := strings.Repeat(`{"a":`, maxCallInputDepth+1) + `1` + strings.Repeat(`}`, maxCallInputDepth+1)
	_, err := CallFromJSON("Bash", over)
	if err == nil || !strings.Contains(err.Error(), "nested deeper") {
		t.Errorf("err = %v, want our own 'nested deeper' refusal", err)
	}
	// Brackets inside strings are not nesting.
	if _, err := CallFromJSON("Bash", `{"command":"`+strings.Repeat(`[{`, 1000)+`"}`); err != nil {
		t.Errorf("brackets inside a string counted as nesting: %v", err)
	}
	if _, err := CallFromJSON("Bash", `{"command":"a\"[[[[`+strings.Repeat(`[`, 500)+`"}`); err != nil {
		t.Errorf("an escaped quote ended the string early: %v", err)
	}
}

// The trust caveat appears for an allow that depends on trust, and only for that.
func TestMatch_TrustCaveatIsPrecise(t *testing.T) {
	needs := rl(Allow, "Bash")
	needs.Source, needs.NeedsTrust = Project, true
	got := pol(needs).Match(call("Bash"), MatchContext{})
	if !hasCaveat(got, "trusted") {
		t.Errorf("caveats = %q, want the trust condition", got.Caveats)
	}
	free := rl(Allow, "Bash")
	if got := pol(free).Match(call("Bash"), MatchContext{}); hasCaveat(got, "trusted") {
		t.Errorf("an allow with no trust condition carries the caveat: %q", got.Caveats)
	}
	// A deny/ask from the same project file applies at once; no trust caveat.
	deny := rl(Deny, "Bash")
	deny.Source = Project
	if got := pol(deny).Match(call("Bash"), MatchContext{}); hasCaveat(got, "trusted") {
		t.Errorf("a deny does not wait for trust: %q", got.Caveats)
	}
}

func TestVerdictAndDecisionAndLayerNames(t *testing.T) {
	for d, s := range map[Decision]string{Deny: "deny", Ask: "ask", Allow: "allow", Decision(9): "unknown"} {
		if d.String() != s {
			t.Errorf("Decision(%d) = %q, want %q", d, d.String(), s)
		}
	}
	for k, s := range map[LayerKind]string{Managed: "managed", CLI: "cli", Local: "local", Project: "project", User: "user", LayerKind(9): "unknown"} {
		if k.String() != s {
			t.Errorf("LayerKind(%d) = %q, want %q", k, k.String(), s)
		}
	}
	for v, s := range map[Severity]string{Low: "low", Medium: "medium", High: "high", Severity(9): "unknown"} {
		if v.String() != s {
			t.Errorf("Severity(%d) = %q, want %q", v, v.String(), s)
		}
	}
	if b, _ := Deny.MarshalText(); string(b) != "deny" {
		t.Errorf("Deny.MarshalText = %q", b)
	}
	if isEditTool("Read") || !isEditTool("MultiEdit") || !isEditTool("NotebookEdit") {
		t.Error("isEditTool mis-classifies a tool")
	}
}

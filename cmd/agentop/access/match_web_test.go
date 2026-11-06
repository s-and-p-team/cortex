package access

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func fetch(url string) Call {
	return Call{Tool: "WebFetch", Input: map[string]any{"url": url, "prompt": "p"}}
}

func domainRule(d Decision, domain string) Rule { return rl(d, "WebFetch(domain:"+domain+")") }

func matches(p Policy, c Call, d Decision) bool {
	return p.Match(c, MatchContext{}).Verdict == verdictOf(d)
}

// WebFetch domain rules (permissions, "WebFetch").
func TestWebFetch_DomainRules(t *testing.T) {
	cases := []struct {
		domain, url string
		want        bool
	}{
		// "domain:example.com matches requests to example.com only"
		{"example.com", "https://example.com/a", true},
		{"example.com", "https://example.com", true},
		{"example.com", "http://example.com:8080/x?y=1#z", true},
		{"example.com", "https://api.example.com/", false},
		{"example.com", "https://notexample.com/", false},
		{"example.com", "https://example.com.evil.net/", false},
		{"example.com", "https://evil.net/example.com", false},
		// case-insensitive, and one trailing dot is the same host
		{"Example.COM", "https://example.com/", true},
		{"example.com", "https://EXAMPLE.com/", true},
		{"example.com.", "https://example.com/", true},
		{"example.com", "https://example.com./", true},
		// "*.example.com matches any subdomain at any depth ... but not example.com itself"
		{"*.example.com", "https://api.example.com/", true},
		{"*.example.com", "https://a.b.example.com/", true},
		{"*.example.com", "https://example.com/", false},
		{"*.example.com", "https://evilexample.com/", false},
		{"*.example.com", "https://example.com.evil.net/", false},
		// "domain:* matches every domain"
		{"*", "https://anything.org/", true},
		{"*", "http://localhost/", true},
		// elsewhere "the wildcard matches only the text between two dots":
		// example.* matches example.org but not example.evil.com
		{"example.*", "https://example.org/", true},
		{"example.*", "https://example.evil.com/", false},
		{"example.*", "https://example.com/", true},
		{"api.*.com", "https://api.x.com/", true},
		{"api.*.com", "https://api.x.y.com/", false},
	}
	for _, c := range cases {
		got := matches(pol(domainRule(Deny, c.domain)), fetch(c.url), Deny)
		if got != c.want {
			t.Errorf("WebFetch(domain:%s) vs %s: matched=%v, want %v", c.domain, c.url, got, c.want)
		}
	}
}

// The hostname is what the URL says it is, not what a naive substring or split makes of it.
func TestWebFetch_HostnameExtractionResistsTricks(t *testing.T) {
	deny := pol(domainRule(Deny, "good.com"))
	for _, url := range []string{
		"https://good.com@evil.net/", // userinfo: the host is evil.net
		"https://good.com:pw@evil.net/",
		"https://evil.net#@good.com/",
		"https://evil.net\\@good.com/",
		"https://evil.net/?host=good.com",
		"https://evil.net/good.com",
		"https://evil.net:443/good.com",
	} {
		if matches(deny, fetch(url), Deny) {
			t.Errorf("%s was treated as a fetch of good.com", url)
		}
	}
	// ...and the genuine host is found whatever surrounds it
	for _, url := range []string{
		"https://user:pw@good.com/", "https://good.com:8443/p?q=1", "HTTPS://GOOD.COM/", "https://good.com/a b",
	} {
		if !matches(deny, fetch(url), Deny) {
			t.Errorf("%s was not recognised as a fetch of good.com", url)
		}
	}
}

func TestWebFetch_IPAndPortAndOddHosts(t *testing.T) {
	cases := []struct {
		domain, url string
		want        bool
	}{
		{"127.0.0.1", "http://127.0.0.1:8080/", true},
		{"127.0.0.1", "http://127.0.0.2/", false},
		{"[::1]", "http://[::1]:3000/", false}, // brackets are not part of the host Claude Code matches on
		{"::1", "http://[::1]:3000/", true},
		{"localhost", "http://localhost/", true},
		{"xn--nxasmq6b.com", "https://xn--nxasmq6b.com/", true},
	}
	for _, c := range cases {
		if got := matches(pol(domainRule(Deny, c.domain)), fetch(c.url), Deny); got != c.want {
			t.Errorf("domain:%s vs %s = %v, want %v", c.domain, c.url, got, c.want)
		}
	}
}

// A URL with no host cannot be matched; a deny or ask rule cannot be said NOT to apply.
func TestWebFetch_AnUnparseableURLIsUnknownForDenyAndAsk(t *testing.T) {
	for _, bad := range []string{"", "not a url", "example.com/path", "http://", "https:///x", "://x", "%%%", "\x00"} {
		for _, d := range []Decision{Deny, Ask} {
			got := pol(domainRule(d, "example.com")).Match(fetch(bad), MatchContext{})
			if got.Verdict != VerdictUnknown {
				t.Errorf("%v rule vs url %q: %v, want unknown", d, bad, got.Verdict)
			}
		}
		if got := pol(domainRule(Allow, "example.com")).Match(fetch(bad), MatchContext{}); got.Verdict == VerdictAllow {
			t.Errorf("an allow rule approved url %q", bad)
		}
	}
	// no url field at all
	for _, c := range []Call{{Tool: "WebFetch"}, {Tool: "WebFetch", Input: map[string]any{"url": 5}}} {
		if got := pol(domainRule(Deny, "example.com")).Match(c, MatchContext{}); got.Verdict != VerdictUnknown {
			t.Errorf("%+v: %v, want unknown", c.Input, got.Verdict)
		}
	}
}

// A bare WebFetch and WebFetch(domain:*) both cover every URL here (they differ only in the
// sandbox's domain list, which is not a rule outcome).
func TestWebFetch_BareAndStarCoverEverything(t *testing.T) {
	for _, r := range []string{"WebFetch", "WebFetch(domain:*)"} {
		for _, url := range []string{"https://a.com", "http://1.2.3.4/", "garbage"} {
			if got := pol(rl(Deny, r)).Match(fetch(url), MatchContext{}).Verdict; got != VerdictDeny && url != "garbage" {
				t.Errorf("%s vs %s = %v, want deny", r, url, got)
			}
		}
	}
	// a bare rule needs no parseable URL at all
	if got := pol(rl(Deny, "WebFetch")).Match(fetch("garbage"), MatchContext{}).Verdict; got != VerdictDeny {
		t.Errorf("bare WebFetch deny vs an unparseable URL: %v, want deny", got)
	}
}

func TestWebFetch_AWebFetchSpecifierThatIsNotADomainIsUnevaluable(t *testing.T) {
	got := pol(rl(Deny, "WebFetch(https://example.com/*)")).Match(fetch("https://example.com/a"), MatchContext{})
	if got.Verdict != VerdictUnknown {
		t.Errorf("a non-domain WebFetch specifier: %v, want unknown", got.Verdict)
	}
}

func TestWebFetch_HostileInputIsBounded(t *testing.T) {
	start := time.Now()
	long := "https://" + strings.Repeat("a", 500000) + ".com/"
	_ = pol(domainRule(Deny, "*.com")).Match(fetch(long), MatchContext{})
	_ = pol(domainRule(Deny, strings.Repeat("*.", 5000)+"com")).Match(fetch("https://a.b.c.com/"), MatchContext{})
	_ = pol(domainRule(Deny, strings.Repeat("a*", 5000)+"b")).Match(fetch("https://"+strings.Repeat("a", 5000)+".com/"), MatchContext{})
	_ = pol(domainRule(Deny, "x")).Match(fetch("https://"+strings.Repeat("a.", 100000)+"com/"), MatchContext{})
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("hostile WebFetch input took %v", d)
	}
}

// --- Agent, Skill --------------------------------------------------------------------------

func TestAgentAndSkillRules(t *testing.T) {
	agent := func(name string) Call {
		return Call{Tool: "Agent", Input: map[string]any{"subagent_type": name, "prompt": "p", "description": "d"}}
	}
	skill := func(name string) Call { return Call{Tool: "Skill", Input: map[string]any{"skill": name}} }

	for _, c := range []struct {
		rule string
		call Call
		want Verdict
	}{
		{"Agent(Explore)", agent("Explore"), VerdictDeny},
		{"Agent(Explore)", agent("Plan"), VerdictNone},
		{"Agent(Explore)", agent("explore"), VerdictNone}, // names are exact
		{"Agent(my-custom-agent)", agent("my-custom-agent"), VerdictDeny},
		{"Agent", agent("anything"), VerdictDeny},
		{"Skill(grilling)", skill("grilling"), VerdictDeny},
		{"Skill(grilling)", skill("other"), VerdictNone},
	} {
		got := pol(rl(Deny, c.rule)).Match(c.call, MatchContext{})
		if got.Verdict != c.want {
			t.Errorf("%s vs %v = %v, want %v", c.rule, c.call.Input, got.Verdict, c.want)
		}
	}
	// A Skill name can match under an alias this view does not know: say so.
	got := pol(rl(Deny, "Skill(grilling)")).Match(skill("other"), MatchContext{})
	if !hasCaveat(got, "alias") {
		t.Errorf("caveats = %q, want the alias limit named", got.Caveats)
	}
	// An Agent call with no subagent_type: a deny/ask on a named agent cannot be said not to apply.
	for _, d := range []Decision{Deny, Ask} {
		if got := pol(rl(d, "Agent(Explore)")).Match(Call{Tool: "Agent", Input: map[string]any{}}, MatchContext{}).Verdict; got != VerdictNone {
			// Claude Code runs the general-purpose agent when none is named: a rule for Explore does not apply.
			t.Errorf("%v Agent(Explore) vs a call naming no agent: %v, want none", d, got)
		}
	}
}

// --- Tool(param:value) ----------------------------------------------------------------------

func param(tool string, in map[string]any) Call { return Call{Tool: tool, Input: in} }

// The docs' own parameter table and rules (permissions, "Match by input parameter").
func TestParameterRules(t *testing.T) {
	cases := []struct {
		rule string
		call Call
		want Verdict
	}{
		{"Agent(model:opus)", param("Agent", map[string]any{"model": "opus"}), VerdictDeny},
		{"Agent(model:opus)", param("Agent", map[string]any{"model": "sonnet"}), VerdictNone},
		// "compared against the literal input Claude sends, before any normalization"
		{"Agent(model:opus)", param("Agent", map[string]any{"model": "claude-opus-5-5"}), VerdictNone},
		{"Agent(isolation:worktree)", param("Agent", map[string]any{"isolation": "worktree"}), VerdictDeny},
		{"Bash(run_in_background:true)", param("Bash", map[string]any{"command": "ls", "run_in_background": true}), VerdictDeny},
		{"Bash(run_in_background:true)", param("Bash", map[string]any{"command": "ls", "run_in_background": false}), VerdictNone},
		// "*" wildcard in the value
		{"Agent(isolation:*)", param("Agent", map[string]any{"isolation": "worktree"}), VerdictDeny},
		{"Agent(isolation:*)", param("Agent", map[string]any{"isolation": ""}), VerdictDeny},
		{"Agent(model:op*)", param("Agent", map[string]any{"model": "opus"}), VerdictDeny},
		// "A parameter the model omits is never matched, so Agent(model:*) doesn't match a call that leaves model unset"
		{"Agent(model:*)", param("Agent", map[string]any{}), VerdictNone},
		{"Agent(model:*)", param("Agent", map[string]any{"prompt": "x"}), VerdictNone},
		// whitespace around the colon is ignored
		{"Agent(model : opus)", param("Agent", map[string]any{"model": "opus"}), VerdictDeny},
		{"Agent(model: opus)", param("Agent", map[string]any{"model": "opus"}), VerdictDeny},
		{"Agent( model :opus )", param("Agent", map[string]any{"model": "opus"}), VerdictDeny},
		// numbers compare by their literal text
		{"Bash(timeout:5000)", param("Bash", map[string]any{"command": "x", "timeout": jsonNum("5000")}), VerdictDeny},
		{"Bash(timeout:5000)", param("Bash", map[string]any{"command": "x", "timeout": jsonNum("5001")}), VerdictNone},
	}
	for _, c := range cases {
		got := pol(rl(Deny, c.rule)).Match(c.call, MatchContext{})
		if got.Verdict != c.want {
			t.Errorf("%s vs %v = %v, want %v\n%+v", c.rule, c.call.Input, got.Verdict, c.want, got)
		}
	}
}

// "Deny and ask rules can match a top-level input parameter ... allow rules continue to use
// each tool's own specifier syntax": an allow of this form does nothing.
func TestParameterRules_AnAllowFormDoesNothing(t *testing.T) {
	got := pol(rl(Allow, "Agent(model:opus)")).Match(param("Agent", map[string]any{"model": "opus"}), MatchContext{})
	if got.Verdict == VerdictAllow {
		t.Error("an allow parameter rule approved a call")
	}
	// ask works like deny
	if got := pol(rl(Ask, "Agent(model:opus)")).Match(param("Agent", map[string]any{"model": "opus"}), MatchContext{}).Verdict; got != VerdictAsk {
		t.Errorf("ask parameter rule: %v, want ask", got)
	}
}

// "You can't match a tool's primary content field this way ... Claude Code ignores it."
func TestParameterRules_PrimaryContentFieldsAreIgnored(t *testing.T) {
	for _, c := range []struct {
		rule string
		call Call
	}{
		{"Bash(command:rm *)", param("Bash", map[string]any{"command": "rm -rf x"})},
		{"Read(file_path:/etc/passwd)", param("Read", map[string]any{"file_path": "/etc/passwd"})},
		{"Edit(file_path:/etc/passwd)", param("Edit", map[string]any{"file_path": "/etc/passwd"})},
		{"Grep(path:/etc)", param("Grep", map[string]any{"path": "/etc"})},
		{"Glob(path:/etc)", param("Glob", map[string]any{"path": "/etc"})},
		{"NotebookEdit(notebook_path:/x)", param("NotebookEdit", map[string]any{"notebook_path": "/x"})},
		{"WebFetch(url:https://a.com)", param("WebFetch", map[string]any{"url": "https://a.com"})},
	} {
		got := pol(rl(Deny, c.rule)).Match(c.call, MatchContext{})
		if got.Verdict == VerdictDeny {
			t.Errorf("%s matched: Claude Code ignores a parameter rule on a primary content field", c.rule)
		}
		if !hasCaveat(got, "ignores") {
			t.Errorf("%s: caveats = %q, want it said that Claude Code ignores this rule", c.rule, got.Caveats)
		}
	}
}

// "Fields nested inside an object or array are not matchable"; "Each rule names one parameter."
func TestParameterRules_OnlyTopLevelScalars(t *testing.T) {
	nested := param("Agent", map[string]any{"opts": map[string]any{"model": "opus"}, "list": []any{"opus"}})
	for _, r := range []string{"Agent(opts:opus)", "Agent(list:opus)", "Agent(opts.model:opus)"} {
		if got := pol(rl(Deny, r)).Match(nested, MatchContext{}); got.Verdict == VerdictDeny {
			t.Errorf("%s matched a nested or composite value", r)
		}
	}
	// two parameters in one rule are not one rule
	got := pol(rl(Deny, "Agent(model:opus,isolation:worktree)")).Match(param("Agent", map[string]any{"model": "opus", "isolation": "worktree"}), MatchContext{})
	if got.Verdict == VerdictDeny {
		t.Error("a combined parameter rule matched")
	}
}

// A "Tool(x:y)" is a parameter rule only when x is a field of this call or a documented
// parameter of the tool; otherwise it is the tool's own specifier. Bash(foo:bar) is a command
// pattern, and must still be matched as one.
func TestParameterRules_OtherwiseItIsTheToolsOwnSpecifier(t *testing.T) {
	if got := pol(rl(Deny, "Bash(git:status)")).Match(param("Bash", map[string]any{"command": "git:status"}), MatchContext{}); got.Verdict != VerdictDeny {
		t.Errorf("Bash(git:status) is a command pattern and should match the command 'git:status': %v", got.Verdict)
	}
	if got := pol(rl(Deny, "Bash(git:status)")).Match(param("Bash", map[string]any{"command": "git status"}), MatchContext{}); got.Verdict == VerdictDeny {
		t.Error("Bash(git:status) matched 'git status': the colon is literal")
	}
	// a documented parameter not present on this call is simply an omitted parameter
	if got := pol(rl(Deny, "Bash(run_in_background:true)")).Match(param("Bash", map[string]any{"command": "ls"}), MatchContext{}); got.Verdict != VerdictNone {
		t.Errorf("an omitted documented parameter: %v, want none", got.Verdict)
	}
}

func TestParameterRules_HostileValuesAreBounded(t *testing.T) {
	start := time.Now()
	long := strings.Repeat("a", 500000)
	_ = pol(rl(Deny, "Agent(model:"+strings.Repeat("a*", 5000)+"b)")).Match(param("Agent", map[string]any{"model": long}), MatchContext{})
	_ = pol(rl(Deny, "Agent(model:*)")).Match(param("Agent", map[string]any{"model": long}), MatchContext{})
	_ = pol(rl(Deny, "Agent(model:opus)")).Match(param("Agent", map[string]any{"model": nil, "x": []any{1}}), MatchContext{})
	if d := time.Since(start); d > time.Second {
		t.Errorf("hostile parameter values took %v", d)
	}
}

func jsonNum(s string) json.Number { return json.Number(s) }

// "*.example.com ... not example.com itself": the leading dot of the suffix is what excludes the
// apex, and this pins that the apex really is excluded in every spelling.
func TestWebFetch_TheApexIsNeverASubdomain(t *testing.T) {
	for _, url := range []string{"https://example.com/", "https://EXAMPLE.COM./", "http://example.com:81/x", "https://user@example.com/"} {
		if matches(pol(domainRule(Deny, "*.example.com")), fetch(url), Deny) {
			t.Errorf("*.example.com matched the apex in %s", url)
		}
	}
	// a second * inside the suffix is a shape the docs do not describe: not a subdomain match
	if matches(pol(domainRule(Deny, "*.*.com")), fetch("https://a.b.com/"), Deny) {
		t.Error("*.*.com was treated as a subdomain pattern")
	}
}

// Nested objects and arrays are not matchable, even when their text would fit the value.
func TestParameterRules_ACompositeValueNeverMatchesItsOwnTextForm(t *testing.T) {
	for name, v := range map[string]any{
		"object": map[string]any{"a": "b"}, "array": []any{"opus"}, "nil": nil,
	} {
		for _, val := range []string{"*", "map[a:b]", "[opus]", "<nil>", "{\"a\":\"b\"}", ""} {
			got := pol(rl(Deny, "Agent(p:"+val+")")).Match(Call{Tool: "Agent", Input: map[string]any{"p": v}}, MatchContext{})
			if got.Verdict == VerdictDeny {
				t.Errorf("a %s value matched Agent(p:%s)", name, val)
			}
		}
	}
}

// A number compares by the text Claude sent. 12345678901234567890 has no exact float64, and
// 1.0 is not 1: the rule is about the literal.
func TestParameterRules_NumbersCompareByTheirLiteralText(t *testing.T) {
	for _, c := range []struct {
		rule string
		num  string
		want bool
	}{
		{"Bash(timeout:12345678901234567890)", "12345678901234567890", true},
		{"Bash(timeout:12345678901234567891)", "12345678901234567890", false},
		{"Bash(timeout:1)", "1.0", false},
		{"Bash(timeout:1.0)", "1.0", true},
		{"Bash(timeout:1e3)", "1e3", true},
		{"Bash(timeout:1000)", "1e3", false},
		{"Bash(timeout:-5)", "-5", true},
	} {
		in := map[string]any{"command": "x", "timeout": jsonNum(c.num)}
		got := pol(rl(Deny, c.rule)).Match(Call{Tool: "Bash", Input: in}, MatchContext{}).Verdict == VerdictDeny
		if got != c.want {
			t.Errorf("%s vs %s: matched=%v, want %v", c.rule, c.num, got, c.want)
		}
	}
}

func TestAgentAndSkill_NamesAreExactNotPrefixes(t *testing.T) {
	agent := func(n string) Call { return Call{Tool: "Agent", Input: map[string]any{"subagent_type": n}} }
	for _, c := range []struct {
		rule, name string
		want       bool
	}{
		{"Agent(Explore)", "Explore", true}, {"Agent(Explore)", "ExploreMore", false}, {"Agent(Explore)", "Explor", false},
		{"Agent(Explore)", "xExplore", false}, {"Agent(Explore)", "", false},
	} {
		got := pol(rl(Deny, c.rule)).Match(agent(c.name), MatchContext{}).Verdict == VerdictDeny
		if got != c.want {
			t.Errorf("%s vs %q: matched=%v, want %v", c.rule, c.name, got, c.want)
		}
	}
	skill := func(n string) Call { return Call{Tool: "Skill", Input: map[string]any{"skill": n}} }
	if pol(rl(Deny, "Skill(grill)")).Match(skill("grilling"), MatchContext{}).Verdict == VerdictDeny {
		t.Error("Skill(grill) matched the skill 'grilling'")
	}
}

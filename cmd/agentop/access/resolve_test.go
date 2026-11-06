package access

import (
	"strings"
	"testing"
	"testing/fstest"
)

// mapfs builds a filesystem from absolute paths.
func mapfs(files map[string]string) fstest.MapFS {
	m := fstest.MapFS{}
	for p, d := range files {
		m[strings.TrimPrefix(p, "/")] = &fstest.MapFile{Data: []byte(d)}
	}
	return m
}

func input(files map[string]string) Input {
	return Input{Cwd: "/proj", Home: "/home", FS: mapfs(files), GOOS: "linux"}
}

func mustResolve(t *testing.T, in Input) Policy {
	t.Helper()
	p, err := Resolve(in)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return p
}

func layer(p Policy, k LayerKind) Layer {
	for _, l := range p.Layers {
		if l.Kind == k {
			return l
		}
	}
	return Layer{}
}

func rule(p Policy, d Decision, raw string, src LayerKind) *Rule {
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.Decision == d && r.Raw == raw && r.Source == src {
			return r
		}
	}
	return nil
}

const (
	userFile    = "/home/.claude/settings.json"
	projectFile = "/proj/.claude/settings.json"
	localFile   = "/proj/.claude/settings.local.json"
	managedBase = "/etc/claude-code/managed-settings.json"
)

func TestResolve_NilFSIsAnError(t *testing.T) {
	if _, err := Resolve(Input{}); err == nil {
		t.Fatal("Resolve with a nil FS returned no error")
	}
}

func TestResolve_NothingPresentIsFiveAbsentLayersAndNoError(t *testing.T) {
	p := mustResolve(t, input(nil))
	if len(p.Layers) != 5 {
		t.Fatalf("layers = %d, want 5", len(p.Layers))
	}
	for _, l := range p.Layers {
		if l.Present || l.Err != nil {
			t.Errorf("%v layer = present %v err %v, want absent and clean", l.Kind, l.Present, l.Err)
		}
	}
	if len(p.Rules) != 0 || p.Mode.Set || p.Sandbox.Set {
		t.Errorf("empty input produced rules %v mode %+v sandbox %+v", p.Rules, p.Mode, p.Sandbox)
	}
}

func TestResolve_EachLayerAloneKeepsItsSource(t *testing.T) {
	cases := []struct {
		file string
		kind LayerKind
	}{
		{userFile, User}, {projectFile, Project}, {localFile, Local}, {managedBase, Managed},
	}
	for _, c := range cases {
		p := mustResolve(t, input(map[string]string{c.file: `{"permissions":{"deny":["Read(./.env)"]}}`}))
		r := rule(p, Deny, "Read(./.env)", c.kind)
		if r == nil {
			t.Errorf("%v: rule not attributed to the layer; rules = %+v", c.kind, p.Rules)
			continue
		}
		if r.Tool != "Read" || r.Pattern != "./.env" || r.File != c.file {
			t.Errorf("%v: rule = %+v, want tool Read pattern ./.env file %s", c.kind, r, c.file)
		}
		if got := layer(p, c.kind).Counts; got.Deny != 1 || got.Allow != 0 || got.Ask != 0 {
			t.Errorf("%v: counts = %+v, want one deny", c.kind, got)
		}
	}
}

func TestResolve_DenyInUserShadowsAllowInLocal(t *testing.T) {
	p := mustResolve(t, input(map[string]string{
		userFile:  `{"permissions":{"deny":["Read(./.env)"]}}`,
		localFile: `{"permissions":{"allow":["Read(./.env)"]}}`,
	}))
	allow := rule(p, Allow, "Read(./.env)", Local)
	if allow == nil || allow.ShadowedBy == nil {
		t.Fatalf("local allow not shadowed: %+v", allow)
	}
	if allow.ShadowedBy.Decision != Deny || allow.ShadowedBy.Source != User {
		t.Errorf("shadowed by %+v, want the user deny", allow.ShadowedBy)
	}
	if d := rule(p, Deny, "Read(./.env)", User); d == nil || d.ShadowedBy != nil {
		t.Errorf("the deny itself must not be shadowed: %+v", d)
	}
}

func TestResolve_AskInProjectShadowsAllowInUser(t *testing.T) {
	p := mustResolve(t, input(map[string]string{
		projectFile: `{"permissions":{"ask":["Bash(git push *)"]}}`,
		userFile:    `{"permissions":{"allow":["Bash(git push *)"]}}`,
	}))
	allow := rule(p, Allow, "Bash(git push *)", User)
	if allow == nil || allow.ShadowedBy == nil || allow.ShadowedBy.Decision != Ask || allow.ShadowedBy.Source != Project {
		t.Fatalf("user allow = %+v, want shadowed by the project ask", allow)
	}
}

func TestResolve_BareToolDenyShadowsEveryRuleForThatTool(t *testing.T) {
	p := mustResolve(t, input(map[string]string{
		userFile: `{"permissions":{"deny":["Bash"],"allow":["Bash(git *)","Read(./x)"]}}`,
	}))
	if r := rule(p, Allow, "Bash(git *)", User); r == nil || r.ShadowedBy == nil {
		t.Errorf("Bash(git *) should be shadowed by a bare Bash deny: %+v", r)
	}
	if r := rule(p, Allow, "Read(./x)", User); r == nil || r.ShadowedBy != nil {
		t.Errorf("a Read rule must not be shadowed by a Bash deny: %+v", r)
	}
}

func TestResolve_BashStarIsTheBareTool(t *testing.T) {
	p := mustResolve(t, input(map[string]string{
		userFile: `{"permissions":{"deny":["Bash(*)"],"allow":["Bash"]}}`,
	}))
	if r := rule(p, Allow, "Bash", User); r == nil || r.ShadowedBy == nil {
		t.Errorf("bare Bash allow should be shadowed by Bash(*) deny: %+v", r)
	}
}

func TestResolve_LegacyColonStarEqualsTrailingSpaceStar(t *testing.T) {
	p := mustResolve(t, input(map[string]string{
		userFile: `{"permissions":{"ask":["Bash(ls:*)"],"allow":["Bash(ls *)"]}}`,
	}))
	if r := rule(p, Allow, "Bash(ls *)", User); r == nil || r.ShadowedBy == nil {
		t.Errorf("Bash(ls *) is the same rule as Bash(ls:*), so the ask shadows it: %+v", r)
	}
}

func TestResolve_NarrowerDenyDoesNotShadowAWiderAllow(t *testing.T) {
	// v1 shadows only on exact or match-all equivalence; it does not guess at
	// glob subsumption, and says nothing rather than something wrong.
	p := mustResolve(t, input(map[string]string{
		userFile: `{"permissions":{"deny":["Bash(git push *)"],"allow":["Bash(git *)"]}}`,
	}))
	if r := rule(p, Allow, "Bash(git *)", User); r == nil || r.ShadowedBy != nil {
		t.Errorf("Bash(git *) must not be reported shadowed by Bash(git push *): %+v", r)
	}
}

func TestResolve_RulesComeOutDenyAskAllow(t *testing.T) {
	p := mustResolve(t, input(map[string]string{
		userFile: `{"permissions":{"allow":["Read"],"ask":["Edit"],"deny":["Write"]}}`,
	}))
	var got []Decision
	for _, r := range p.Rules {
		got = append(got, r.Decision)
	}
	if len(got) != 3 || got[0] != Deny || got[1] != Ask || got[2] != Allow {
		t.Errorf("rule order = %v, want deny, ask, allow", got)
	}
}

func TestResolve_ManagedScalarWinsOverEveryLowerLayer(t *testing.T) {
	p := mustResolve(t, input(map[string]string{
		managedBase: `{"permissions":{"defaultMode":"plan"}}`,
		localFile:   `{"permissions":{"defaultMode":"acceptEdits"}}`,
		userFile:    `{"permissions":{"defaultMode":"default"}}`,
	}))
	if p.Mode.Value != "plan" || p.Mode.Layer != Managed || !p.Mode.Set {
		t.Errorf("mode = %+v, want plan from managed", p.Mode)
	}
}

func TestResolve_HigherLayerOverridesLowerScalar(t *testing.T) {
	p := mustResolve(t, input(map[string]string{
		localFile: `{"permissions":{"defaultMode":"acceptEdits"}}`,
		userFile:  `{"permissions":{"defaultMode":"default"}}`,
	}))
	if p.Mode.Value != "acceptEdits" || p.Mode.Layer != Local {
		t.Errorf("mode = %+v, want acceptEdits from local", p.Mode)
	}
}

func TestResolve_BypassAndAutoAreIgnoredFromProjectAndLocal(t *testing.T) {
	p := mustResolve(t, input(map[string]string{
		projectFile: `{"permissions":{"defaultMode":"bypassPermissions"}}`,
		localFile:   `{"permissions":{"defaultMode":"auto"}}`,
		userFile:    `{"permissions":{"defaultMode":"default"}}`,
	}))
	if p.Mode.Value != "default" || p.Mode.Layer != User {
		t.Errorf("mode = %+v, want the user's default, since project and local cannot set auto or bypass", p.Mode)
	}
	if len(p.Ignored) != 2 {
		t.Fatalf("ignored = %+v, want the project and local values reported", p.Ignored)
	}
	for _, ig := range p.Ignored {
		if ig.Key != "permissions.defaultMode" || ig.Reason == "" {
			t.Errorf("ignored entry %+v lacks key or reason", ig)
		}
	}
}

func TestResolve_BypassIsHonouredFromUserAndManaged(t *testing.T) {
	for _, file := range []string{userFile, managedBase} {
		p := mustResolve(t, input(map[string]string{file: `{"permissions":{"defaultMode":"bypassPermissions"}}`}))
		if p.Mode.Value != "bypassPermissions" || len(p.Ignored) != 0 {
			t.Errorf("%s: mode %+v ignored %+v, want bypass honoured", file, p.Mode, p.Ignored)
		}
	}
}

func TestResolve_SandboxEnabledTakesTheHighestLayerThatSetsIt(t *testing.T) {
	p := mustResolve(t, input(map[string]string{
		userFile:  `{"sandbox":{"enabled":true}}`,
		localFile: `{"sandbox":{"enabled":false}}`,
	}))
	if !p.Sandbox.Set || p.Sandbox.Value || p.Sandbox.Layer != Local {
		t.Errorf("sandbox = %+v, want disabled by local", p.Sandbox)
	}
	if p := mustResolve(t, input(map[string]string{userFile: `{}`})); p.Sandbox.Set {
		t.Errorf("sandbox = %+v, want unset when no layer mentions it", p.Sandbox)
	}
}

func TestResolve_LocalRootFileWinsOverTheLegacyCwdFile(t *testing.T) {
	in := input(map[string]string{
		"/repo/.claude/settings.local.json":     `{"permissions":{"defaultMode":"plan"}}`,
		"/repo/sub/.claude/settings.local.json": `{"permissions":{"defaultMode":"acceptEdits","deny":["Read(./a)"]}}`,
	})
	in.Cwd, in.GitRoot = "/repo/sub", "/repo"
	p := mustResolve(t, in)
	if p.Mode.Value != "plan" {
		t.Errorf("mode = %+v, want the root file's value where both set the key", p.Mode)
	}
	if rule(p, Deny, "Read(./a)", Local) == nil {
		t.Errorf("rules from the legacy file must still apply: %+v", p.Rules)
	}
}

func TestResolve_LaterManagedDropInOverridesTheBaseFile(t *testing.T) {
	// The docs give the merge order (base first, then drop-ins alphabetically)
	// and say nothing about which wins a conflicting scalar. Later-wins is the
	// drop-in convention and is assumed here; see doc.go.
	p := mustResolve(t, input(map[string]string{
		managedBase: `{"permissions":{"defaultMode":"default"}}`,
		"/etc/claude-code/managed-settings.d/10-a.json": `{"permissions":{"defaultMode":"plan"}}`,
		"/etc/claude-code/managed-settings.d/20-b.json": `{"permissions":{"defaultMode":"acceptEdits"}}`,
	}))
	if p.Mode.Value != "acceptEdits" {
		t.Errorf("mode = %+v, want the last drop-in's value", p.Mode)
	}
}

func TestResolve_MalformedLayerIsReportedAndTheRestStillResolve(t *testing.T) {
	p := mustResolve(t, input(map[string]string{
		projectFile: `{"permissions": {"deny": [`,
		userFile:    `{"permissions":{"deny":["Read(./.env)"]}}`,
	}))
	if l := layer(p, Project); l.Err == nil || !l.Present {
		t.Errorf("project layer = present %v err %v, want present with a parse error", l.Present, l.Err)
	}
	if rule(p, Deny, "Read(./.env)", User) == nil {
		t.Errorf("user rules lost because the project file was malformed: %+v", p.Rules)
	}
	if len(layer(p, Project).Files) == 0 || layer(p, Project).Files[0].Err == nil {
		t.Errorf("the error must also be on the file: %+v", layer(p, Project).Files)
	}
}

func TestResolve_WrongTypeForAKeyIsAParseErrorNotAPanic(t *testing.T) {
	p := mustResolve(t, input(map[string]string{userFile: `{"permissions":{"allow":"Bash"}}`}))
	if layer(p, User).Err == nil {
		t.Error("allow as a string should be reported as an error on the user layer")
	}
}

func TestResolve_AllowManagedPermissionRulesOnlyVoidsOtherLayersRules(t *testing.T) {
	p := mustResolve(t, input(map[string]string{
		managedBase: `{"allowManagedPermissionRulesOnly":true,"permissions":{"deny":["WebFetch"]}}`,
		userFile:    `{"permissions":{"allow":["Bash"],"deny":["Read(./x)"]}}`,
	}))
	if r := rule(p, Deny, "WebFetch", Managed); r == nil || r.Ignored != "" {
		t.Errorf("managed rule must stay in force: %+v", r)
	}
	for _, r := range []*Rule{rule(p, Allow, "Bash", User), rule(p, Deny, "Read(./x)", User)} {
		if r == nil || r.Ignored == "" {
			t.Errorf("user rule should be marked ignored by managed policy: %+v", r)
		}
	}
	// An ignored deny must not shadow anything.
	p = mustResolve(t, input(map[string]string{
		managedBase: `{"allowManagedPermissionRulesOnly":true}`,
		userFile:    `{"permissions":{"deny":["Bash"],"allow":["Bash"]}}`,
	}))
	if r := rule(p, Allow, "Bash", User); r == nil || r.ShadowedBy != nil {
		t.Errorf("an ignored deny cannot shadow: %+v", r)
	}
}

func TestResolve_ManagedOnlyFlagFromANonManagedLayerDoesNothing(t *testing.T) {
	p := mustResolve(t, input(map[string]string{
		userFile: `{"allowManagedPermissionRulesOnly":true,"permissions":{"allow":["Bash"]}}`,
	}))
	if r := rule(p, Allow, "Bash", User); r == nil || r.Ignored != "" {
		t.Errorf("the key is managed-scope only; a user file cannot void rules: %+v", r)
	}
}

func TestResolve_ProjectAllowRulesAndDirsNeedWorkspaceTrust(t *testing.T) {
	p := mustResolve(t, input(map[string]string{
		projectFile: `{"permissions":{"allow":["Bash(npm *)"],"deny":["Read(./s)"],"ask":["Edit"],"additionalDirectories":["../lib"]}}`,
		localFile:   `{"permissions":{"allow":["Bash(make *)"]}}`,
	}))
	if r := rule(p, Allow, "Bash(npm *)", Project); r == nil || !r.NeedsTrust {
		t.Errorf("project allow should need trust: %+v", r)
	}
	for _, r := range []*Rule{rule(p, Deny, "Read(./s)", Project), rule(p, Ask, "Edit", Project), rule(p, Allow, "Bash(make *)", Local)} {
		if r == nil || r.NeedsTrust {
			t.Errorf("only project allow rules wait for trust: %+v", r)
		}
	}
	if len(p.Dirs) != 1 || !p.Dirs[0].NeedsTrust {
		t.Errorf("project additionalDirectories should need trust: %+v", p.Dirs)
	}
}

func TestResolve_AdditionalDirectoriesMergeAndDeduplicateKeepingTheHighestSource(t *testing.T) {
	p := mustResolve(t, input(map[string]string{
		localFile: `{"permissions":{"additionalDirectories":["/data","/shared"]}}`,
		userFile:  `{"permissions":{"additionalDirectories":["/shared","/tools"]}}`,
	}))
	want := map[string]LayerKind{"/data": Local, "/shared": Local, "/tools": User}
	if len(p.Dirs) != len(want) {
		t.Fatalf("dirs = %+v, want %d entries", p.Dirs, len(want))
	}
	for _, d := range p.Dirs {
		if src, ok := want[d.Path]; !ok || src != d.Source {
			t.Errorf("dir %+v, want source %v", d, want[d.Path])
		}
	}
}

func TestResolve_HooksAreReportedByEventNameOnly(t *testing.T) {
	p := mustResolve(t, input(map[string]string{
		userFile: `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/secret/path.sh"}]}],"SessionStart":[]}}`,
	}))
	if len(p.Hooks) != 2 || p.Hooks[0].Event != "PreToolUse" || p.Hooks[1].Event != "SessionStart" {
		t.Errorf("hooks = %+v, want PreToolUse and SessionStart in name order", p.Hooks)
	}
	if p.Hooks[0].Source != User {
		t.Errorf("hook source = %v, want user", p.Hooks[0].Source)
	}
}

func TestResolve_InlineCLISettingsIsTheCLILayer(t *testing.T) {
	in := input(nil)
	in.CLISettings = `{"permissions":{"deny":["Read(./k)"]}}`
	p := mustResolve(t, in)
	if rule(p, Deny, "Read(./k)", CLI) == nil || !layer(p, CLI).Present {
		t.Errorf("inline --settings not resolved: layer %+v rules %+v", layer(p, CLI), p.Rules)
	}
}

func TestResolve_CLISettingsFileIsRead(t *testing.T) {
	in := input(map[string]string{"/tmp/s.json": `{"permissions":{"ask":["Edit"]}}`})
	in.CLISettings = "/tmp/s.json"
	if rule(mustResolve(t, in), Ask, "Edit", CLI) == nil {
		t.Error("a --settings file path was not read")
	}
}

func TestParseRule(t *testing.T) {
	cases := []struct{ raw, tool, pattern string }{
		{"Bash", "Bash", ""},
		{"Bash(npm run *)", "Bash", "npm run *"},
		{"Read(./.env)", "Read", "./.env"},
		{"WebFetch(domain:example.com)", "WebFetch", "domain:example.com"},
		{"mcp__srv__tool", "mcp__srv__tool", ""},
		{"Bash(echo (hi))", "Bash", "echo (hi)"}, // parentheses inside are literal
		{"Bash(", "Bash(", ""},                   // unterminated: kept whole, not guessed
	}
	for _, c := range cases {
		tool, pattern := parseRule(c.raw)
		if tool != c.tool || pattern != c.pattern {
			t.Errorf("parseRule(%q) = (%q, %q), want (%q, %q)", c.raw, tool, pattern, c.tool, c.pattern)
		}
	}
}

package access

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func flagCodes(p Policy) map[string]RiskFlag {
	out := map[string]RiskFlag{}
	for _, f := range p.Flags {
		out[f.Code] = f
	}
	return out
}

func TestFlags_BypassPermissionsAsTheEffectiveMode(t *testing.T) {
	p := mustResolve(t, input(map[string]string{userFile: `{"permissions":{"defaultMode":"bypassPermissions"}}`}))
	f, ok := flagCodes(p)["bypass-permissions"]
	if !ok || f.Severity != High {
		t.Errorf("flags = %+v, want a high bypass-permissions flag", p.Flags)
	}
}

func TestFlags_BareToolAndMatchAllAllowRules(t *testing.T) {
	for _, raw := range []string{"Bash", "Bash(*)", "Write", "Edit"} {
		p := mustResolve(t, input(map[string]string{userFile: `{"permissions":{"allow":["` + raw + `"]}}`}))
		if _, ok := flagCodes(p)["broad-allow"]; !ok {
			t.Errorf("allow %q: no broad-allow flag in %+v", raw, p.Flags)
		}
	}
	for _, raw := range []string{"Bash(git status)", "Read", "Glob", "Grep"} {
		p := mustResolve(t, input(map[string]string{userFile: `{"permissions":{"allow":["` + raw + `"]}}`}))
		if f, ok := flagCodes(p)["broad-allow"]; ok {
			t.Errorf("allow %q wrongly flagged: %+v", raw, f)
		}
	}
}

func TestFlags_ABroadAllowThatIsShadowedOrIgnoredIsNotFlagged(t *testing.T) {
	p := mustResolve(t, input(map[string]string{
		userFile: `{"permissions":{"allow":["Bash"],"deny":["Bash"]}}`,
	}))
	if _, ok := flagCodes(p)["broad-allow"]; ok {
		t.Errorf("a shadowed allow grants nothing, so it is not a risk: %+v", p.Flags)
	}
}

func TestFlags_SandboxNotEnabled(t *testing.T) {
	if _, ok := flagCodes(mustResolve(t, input(map[string]string{userFile: `{}`})))["sandbox-off"]; !ok {
		t.Error("an unset sandbox should be flagged: it is off by default")
	}
	p := mustResolve(t, input(map[string]string{userFile: `{"sandbox":{"enabled":false}}`}))
	if _, ok := flagCodes(p)["sandbox-off"]; !ok {
		t.Error("an explicit sandbox.enabled=false should be flagged")
	}
	p = mustResolve(t, input(map[string]string{userFile: `{"sandbox":{"enabled":true}}`}))
	if _, ok := flagCodes(p)["sandbox-off"]; ok {
		t.Error("an enabled sandbox must not be flagged")
	}
}

func TestFlags_WideAdditionalDirectories(t *testing.T) {
	for _, d := range []string{"/", "/home"} { // input() uses Home=/home
		p := mustResolve(t, input(map[string]string{userFile: `{"permissions":{"additionalDirectories":["` + d + `"]}}`}))
		if _, ok := flagCodes(p)["wide-directory"]; !ok {
			t.Errorf("additionalDirectories %q not flagged: %+v", d, p.Flags)
		}
	}
	in := input(map[string]string{userFile: `{"permissions":{"additionalDirectories":["/home/me/work"]}}`})
	if _, ok := flagCodes(mustResolve(t, in))["wide-directory"]; ok {
		t.Error("a specific directory must not be flagged")
	}
}

func TestFlags_BypassModeNotLockedOutWhereManagedFilesExist(t *testing.T) {
	p := mustResolve(t, input(map[string]string{managedBase: `{}`}))
	if _, ok := flagCodes(p)["bypass-not-disabled"]; !ok {
		t.Errorf("managed settings present without disableBypassPermissionsMode should be noted: %+v", p.Flags)
	}
	if _, ok := flagCodes(mustResolve(t, input(nil)))["bypass-not-disabled"]; ok {
		t.Error("with no managed layer there is nothing to lock it from, so no flag")
	}
}

func TestFlags_UnreadableOrMalformedLayersAreFlagged(t *testing.T) {
	p := mustResolve(t, input(map[string]string{managedBase: `{`}))
	f, ok := flagCodes(p)["layer-error"]
	if !ok || f.Severity != High {
		t.Errorf("a broken managed file stops Claude Code starting and must be a high flag: %+v", p.Flags)
	}
	p = mustResolve(t, input(map[string]string{userFile: `{`}))
	if f := flagCodes(p)["layer-error"]; f.Severity == High {
		t.Errorf("a broken user file is skipped by Claude Code, so not high: %+v", f)
	}
}

func TestFlags_AreOrderedBySeverityThenCode(t *testing.T) {
	p := mustResolve(t, input(map[string]string{
		userFile: `{"permissions":{"defaultMode":"bypassPermissions","allow":["Bash"]}}`,
	}))
	for i := 1; i < len(p.Flags); i++ {
		a, b := p.Flags[i-1], p.Flags[i]
		if a.Severity < b.Severity || (a.Severity == b.Severity && a.Code > b.Code) {
			t.Fatalf("flags out of order at %d: %+v then %+v", i, a, b)
		}
	}
}

const secretSettings = `{
  "env": {"ANTHROPIC_API_KEY": "sk-s3cret-value", "TOKEN_NAME": "tok-hunter2"},
  "apiKeyHelper": "/bin/get-key --secret hunter2",
  "permissions": {"allow": ["Bash(git status)"], "deny": ["Read(./.env)"]},
  "hooks": {"PreToolUse": [{"matcher":"Bash","hooks":[{"type":"command","command":"/opt/hunter2/check.sh"}]}]}
}`

func TestOutput_NeverContainsEnvOrOtherUnmodelledSettings(t *testing.T) {
	p := mustResolve(t, input(map[string]string{userFile: secretSettings}))
	js, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{p.Text(), string(js)} {
		for _, leak := range []string{"s3cret", "hunter2", "ANTHROPIC_API_KEY", "TOKEN_NAME", "apiKeyHelper", "get-key", "check.sh"} {
			if strings.Contains(out, leak) {
				t.Errorf("output leaks %q:\n%s", leak, out)
			}
		}
	}
}

func TestOutput_JSONIsByteIdenticalAcrossRunsAndRoundTrips(t *testing.T) {
	files := map[string]string{
		userFile:    `{"permissions":{"allow":["Read","Bash(git *)"],"deny":["Write"],"ask":["Edit"]},"sandbox":{"enabled":true}}`,
		projectFile: `{"permissions":{"allow":["Glob"],"additionalDirectories":["../lib"]}}`,
		localFile:   `{"permissions":{"deny":["Bash(rm *)"],"defaultMode":"acceptEdits"}}`,
	}
	var first []byte
	for i := 0; i < 20; i++ {
		b, err := json.Marshal(mustResolve(t, input(files)))
		if err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = b
		} else if !bytes.Equal(first, b) {
			t.Fatalf("run %d differs:\n%s\n%s", i, first, b)
		}
	}
	var back map[string]any
	if err := json.Unmarshal(first, &back); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	for _, k := range []string{"layers", "mode", "sandbox", "rules", "flags"} {
		if _, ok := back[k]; !ok {
			t.Errorf("JSON missing key %q: %s", k, first)
		}
	}
}

func TestOutput_JSONUsesNamesNotNumbersAndHasNoPointerCycles(t *testing.T) {
	p := mustResolve(t, input(map[string]string{
		userFile:  `{"permissions":{"deny":["Read(./.env)"]}}`,
		localFile: `{"permissions":{"allow":["Read(./.env)"]}}`,
	}))
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`"decision":"deny"`, `"decision":"allow"`, `"source":"user"`, `"source":"local"`, `"kind":"managed"`} {
		if !strings.Contains(s, want) {
			t.Errorf("JSON lacks %s:\n%s", want, s)
		}
	}
	if !strings.Contains(s, `"shadowedBy"`) {
		t.Errorf("the shadowed allow should say what shadows it:\n%s", s)
	}
}

func TestOutput_RulesInDecisionOrderThenToolThenPatternThenLayer(t *testing.T) {
	p := mustResolve(t, input(map[string]string{
		userFile:    `{"permissions":{"allow":["Read","Bash(b)","Bash(a)"],"deny":["Write"]}}`,
		projectFile: `{"permissions":{"allow":["Bash(a)"]}}`,
	}))
	var got []string
	for _, r := range p.Rules {
		got = append(got, r.Decision.String()+":"+r.Raw+":"+r.Source.String())
	}
	want := []string{"deny:Write:user", "allow:Bash(a):project", "allow:Bash(a):user", "allow:Bash(b):user", "allow:Read:user"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("order = %v\nwant    %v", got, want)
	}
}

func TestText_ListsTheLayersTheModeTheRulesAndTheFlags(t *testing.T) {
	p := mustResolve(t, input(map[string]string{
		userFile:  `{"permissions":{"defaultMode":"bypassPermissions","deny":["Read(./.env)"]}}`,
		localFile: `{"permissions":{"allow":["Bash(git *)"]}}`,
	}))
	out := p.Text()
	for _, want := range []string{
		"managed", "cli", "local", "project", "user", // five layers, in the output
		"/home/.claude/settings.json",
		"bypassPermissions", "(user)", // the mode and who decided it
		"Read(./.env)", "Bash(git *)",
		"bypass-permissions", // a flag
		"absent",             // an absent layer is said, not omitted
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Text() lacks %q:\n%s", want, out)
		}
	}
}

func TestText_SaysWhyAProjectLayerIsMissingWhenThereIsNoCwd(t *testing.T) {
	in := input(nil)
	in.Cwd = ""
	out := mustResolve(t, in).Text()
	if !strings.Contains(out, "no working directory") {
		t.Errorf("Text() should explain the missing project layers:\n%s", out)
	}
}

func TestText_ShowsShadowIgnoredAndTrustNotes(t *testing.T) {
	p := mustResolve(t, input(map[string]string{
		managedBase: `{"allowManagedPermissionRulesOnly":true}`,
		userFile:    `{"permissions":{"deny":["Bash"],"allow":["Bash"]}}`,
		projectFile: `{"permissions":{"allow":["Read"]}}`,
	}))
	out := p.Text()
	for _, want := range []string{"ignored", "allowManagedPermissionRulesOnly"} {
		if !strings.Contains(out, want) {
			t.Errorf("Text() lacks %q:\n%s", want, out)
		}
	}
	p = mustResolve(t, input(map[string]string{
		userFile:    `{"permissions":{"deny":["Bash"],"allow":["Bash"]}}`,
		projectFile: `{"permissions":{"allow":["Read"]}}`,
	}))
	out = p.Text()
	for _, want := range []string{"shadowed by", "workspace trust"} {
		if !strings.Contains(out, want) {
			t.Errorf("Text() lacks %q:\n%s", want, out)
		}
	}
}

func TestSessionMode_IsReportedBesideTheConfiguredOne(t *testing.T) {
	in := input(map[string]string{userFile: `{"permissions":{"defaultMode":"default"}}`})
	in.SessionMode = "acceptEdits"
	p := mustResolve(t, in)
	if p.SessionMode != "acceptEdits" {
		t.Errorf("SessionMode = %q, want acceptEdits", p.SessionMode)
	}
	js, _ := json.Marshal(p)
	if !strings.Contains(string(js), `"sessionMode":"acceptEdits"`) {
		t.Errorf("JSON lacks sessionMode: %s", js)
	}
	text := p.Text()
	for _, want := range []string{"default (user)", "acceptEdits", "this session"} {
		if !strings.Contains(text, want) {
			t.Errorf("Text() lacks %q:\n%s", want, text)
		}
	}
}

func TestSessionMode_AbsentWhenNotGiven(t *testing.T) {
	p := mustResolve(t, input(nil))
	js, _ := json.Marshal(p)
	if strings.Contains(string(js), "sessionMode") {
		t.Errorf("sessionMode written with no session: %s", js)
	}
	if strings.Contains(p.Text(), "this session") {
		t.Errorf("Text() mentions a session when there is none:\n%s", p.Text())
	}
}

func TestSessionMode_BypassIsFlaggedEvenWhenTheConfiguredModeIsNot(t *testing.T) {
	// Claude Code does not apply bypassPermissions from project or local settings, but a session
	// can still be started in it (--permission-mode, Shift+Tab). The transcript says so.
	in := input(map[string]string{userFile: `{"permissions":{"defaultMode":"default"}}`})
	in.SessionMode = "bypassPermissions"
	f, ok := flagCodes(mustResolve(t, in))["session-bypass"]
	if !ok || f.Severity != High {
		t.Errorf("a session that ended in bypassPermissions should carry a high flag: %+v", f)
	}
	in.SessionMode = "plan"
	if _, ok := flagCodes(mustResolve(t, in))["session-bypass"]; ok {
		t.Error("a plan-mode session must not be flagged")
	}
}

func TestNotes_AreCarriedIntoTheOutputAndNeverNull(t *testing.T) {
	p := mustResolve(t, input(nil))
	js, _ := json.Marshal(p)
	if !strings.Contains(string(js), `"notes":[]`) {
		t.Errorf("notes must be [] not null: %s", js)
	}
	p.Notes = []string{"session abc started in /w/x"}
	if !strings.Contains(p.Text(), "session abc started in /w/x") {
		t.Errorf("Text() lacks the note:\n%s", p.Text())
	}
}

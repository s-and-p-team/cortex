package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/rossoctl/cortex/cmd/agentop/access"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func writeAccessFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// accessFixture builds a home and a project, and returns the args that point
// runAccess at them. It never touches the real ~/.claude.
func accessFixture(t *testing.T) (project, configDir string, args []string) {
	t.Helper()
	root := t.TempDir()
	project = filepath.Join(root, "proj")
	configDir = filepath.Join(root, "claudehome")
	writeAccessFile(t, filepath.Join(configDir, "settings.json"),
		`{"env":{"SECRET":"hunter2"},"permissions":{"allow":["Bash(git status)"],"deny":["Read(./.env)"]}}`)
	writeAccessFile(t, filepath.Join(project, ".claude", "settings.json"),
		`{"permissions":{"ask":["Bash(git push *)"]}}`)
	return project, configDir, []string{"--cwd", project, "--config-dir", configDir}
}

// hasRule reports whether the JSON policy in out contains a rule with this raw
// text and source. It parses rather than searching the text, so the assertion
// does not depend on how the output is indented.
func hasRule(t *testing.T, out, raw, source string) bool {
	t.Helper()
	var p struct {
		Rules []struct {
			Raw    string `json:"raw"`
			Source string `json:"source"`
		} `json:"rules"`
	}
	if err := json.Unmarshal([]byte(out), &p); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, out)
	}
	for _, r := range p.Rules {
		if r.Raw == raw && r.Source == source {
			return true
		}
	}
	return false
}

func runAccessCapture(args ...string) (code int, stdout, stderr string) {
	var out, errb bytes.Buffer
	code = runAccess(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestRunAccess_TextListsLayersRulesAndNeverTheSecret(t *testing.T) {
	_, _, args := accessFixture(t)
	code, out, errs := runAccessCapture(args...)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errs)
	}
	for _, want := range []string{"LAYERS", "managed", "cli", "local", "project", "user", "Read(./.env)", "Bash(git push *)", "Bash(git status)"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "hunter2") || strings.Contains(out, "SECRET") {
		t.Errorf("output leaks the env block:\n%s", out)
	}
}

func TestRunAccess_JSONIsValidAndHasTheExpectedShape(t *testing.T) {
	_, _, args := accessFixture(t)
	code, out, errs := runAccessCapture(append(args, "--json")...)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errs)
	}
	var got struct {
		Layers []struct {
			Kind    string `json:"kind"`
			Present bool   `json:"present"`
		} `json:"layers"`
		Rules []struct {
			Decision string `json:"decision"`
			Raw      string `json:"raw"`
			Source   string `json:"source"`
		} `json:"rules"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, out)
	}
	if len(got.Layers) != 5 {
		t.Errorf("layers = %d, want 5", len(got.Layers))
	}
	if len(got.Rules) != 3 || got.Rules[0].Decision != "deny" || got.Rules[0].Raw != "Read(./.env)" || got.Rules[0].Source != "user" {
		t.Errorf("rules = %+v, want deny first, attributed to user", got.Rules)
	}
	if strings.Contains(out, "hunter2") {
		t.Errorf("JSON leaks the env block:\n%s", out)
	}
}

func TestRunAccess_ProjectLayerIsReadFromCwd(t *testing.T) {
	_, _, args := accessFixture(t)
	_, out, _ := runAccessCapture(append(args, "--json")...)
	if !hasRule(t, out, "Bash(git push *)", "project") {
		t.Errorf("the project's ask rule was not resolved:\n%s", out)
	}
}

func TestRunAccess_MissingCwdStillSucceedsWithAbsentProjectLayers(t *testing.T) {
	_, configDir, _ := accessFixture(t)
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	code, out, errs := runAccessCapture("--cwd", missing, "--config-dir", configDir)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errs)
	}
	if !strings.Contains(out, "absent") {
		t.Errorf("an absent layer should say so:\n%s", out)
	}
}

func TestRunAccess_RelativeCwdIsMadeAbsolute(t *testing.T) {
	project, configDir, _ := accessFixture(t)
	t.Chdir(filepath.Dir(project))
	code, out, errs := runAccessCapture("--cwd", "proj", "--config-dir", configDir, "--json")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errs)
	}
	if !hasRule(t, out, "Bash(git push *)", "project") {
		t.Errorf("a relative --cwd was not resolved against the working directory:\n%s", out)
	}
}

func TestRunAccess_DefaultCwdIsTheCurrentDirectory(t *testing.T) {
	project, configDir, _ := accessFixture(t)
	t.Chdir(project)
	code, out, _ := runAccessCapture("--config-dir", configDir, "--json")
	if code != 0 || !hasRule(t, out, "Bash(git push *)", "project") {
		t.Errorf("exit %d; default --cwd should be the current directory:\n%s", code, out)
	}
}

func TestRunAccess_ConfigDirFallsBackToTheEnvironment(t *testing.T) {
	_, configDir, _ := accessFixture(t)
	t.Setenv("CLAUDE_CONFIG_DIR", configDir)
	code, out, _ := runAccessCapture("--cwd", t.TempDir(), "--json")
	if code != 0 || !hasRule(t, out, "Read(./.env)", "user") {
		t.Errorf("exit %d; CLAUDE_CONFIG_DIR should locate the user settings:\n%s", code, out)
	}
}

func TestRunAccess_GitRootIsFoundForTheLocalFile(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	sub := filepath.Join(root, "pkg", "deep")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "-C", root, "init", "-q").CombinedOutput(); err != nil {
		t.Skipf("git init: %v %s", err, out)
	}
	writeAccessFile(t, filepath.Join(root, ".claude", "settings.local.json"), `{"permissions":{"deny":["Write"]}}`)
	_, configDir, _ := accessFixture(t)
	code, out, errs := runAccessCapture("--cwd", sub, "--config-dir", configDir, "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if !hasRule(t, out, "Write", "local") {
		t.Errorf("the git root's settings.local.json was not read for a subdirectory:\n%s", out)
	}
}

func TestRunAccess_UnknownFlagIsExit2WithUsage(t *testing.T) {
	code, _, errs := runAccessCapture("--bogus")
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if !strings.Contains(errs, "agentop access") {
		t.Errorf("usage not printed on a bad flag:\n%s", errs)
	}
}

func TestRunAccess_HelpIsExit0(t *testing.T) {
	code, _, errs := runAccessCapture("--help")
	if code != 0 || !strings.Contains(errs, "Usage") {
		t.Errorf("--help: exit %d, stderr %q", code, errs)
	}
}

func TestRunAccess_ExtraPositionalArgsAreRejected(t *testing.T) {
	code, _, errs := runAccessCapture("extra")
	if code != 2 || !strings.Contains(errs, "unexpected") {
		t.Errorf("exit %d stderr %q, want 2 and an explanation", code, errs)
	}
}

func TestRunAccess_UsageSaysWhatItCannotSee(t *testing.T) {
	_, _, errs := runAccessCapture("--help")
	for _, want := range []string{"as of now", "MDM", "workspace trust"} {
		if !strings.Contains(errs, want) {
			t.Errorf("--help should state the limit %q:\n%s", want, errs)
		}
	}
}

// --session ------------------------------------------------------------------------------

// sessionFixture writes a session-metadata.json under a fake HOME and returns the project and
// config dir the entry points at. Nothing reads the real ~/.cortex or ~/.claude.
func sessionFixture(t *testing.T, entries map[string]map[string]any) (project, configDir string) {
	t.Helper()
	root := t.TempDir()
	t.Setenv("HOME", filepath.Join(root, "home"))
	t.Setenv("USERPROFILE", filepath.Join(root, "home"))
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	project = filepath.Join(root, "proj")
	configDir = filepath.Join(root, "otherclaude")
	writeAccessFile(t, filepath.Join(configDir, "settings.json"), `{"permissions":{"deny":["Read(./.env)"]}}`)
	writeAccessFile(t, filepath.Join(project, ".claude", "settings.json"), `{"permissions":{"ask":["Bash(git push *)"]}}`)
	for _, e := range entries {
		for k, v := range e {
			if s, ok := v.(string); ok {
				s = strings.ReplaceAll(s, "@PROJECT@", project)
				s = strings.ReplaceAll(s, "@CONFIG@", configDir)
				e[k] = s
			}
		}
	}
	b, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	writeAccessFile(t, filepath.Join(root, "home", ".cortex", "session-metadata.json"), string(b))
	return project, configDir
}

func TestRunAccess_SessionResolvesFromItsRecordedDirectoryAndConfigDir(t *testing.T) {
	sessionFixture(t, map[string]map[string]any{
		"aaaa1111-0000-0000-0000-000000000001": {
			"title": "fix the thing", "agentType": "Claude Code",
			"cwd": "@PROJECT@", "agentConfigDir": "@CONFIG@", "permissionMode": "acceptEdits",
		},
	})
	code, out, errs := runAccessCapture("--session", "aaaa1111-0000-0000-0000-000000000001", "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if !hasRule(t, out, "Bash(git push *)", "project") {
		t.Errorf("the project's rule was not read from the session's cwd:\n%s", out)
	}
	if !hasRule(t, out, "Read(./.env)", "user") {
		t.Errorf("the user layer was not read from the session's agentConfigDir:\n%s", out)
	}
	if !strings.Contains(out, `"sessionMode": "acceptEdits"`) {
		t.Errorf("the session's recorded mode is missing:\n%s", out)
	}
}

func TestRunAccess_SessionAcceptsAUniquePrefix(t *testing.T) {
	sessionFixture(t, map[string]map[string]any{
		"aaaa1111-1": {"cwd": "@PROJECT@", "agentConfigDir": "@CONFIG@"},
		"bbbb2222-2": {"cwd": "@PROJECT@", "agentConfigDir": "@CONFIG@"},
	})
	if code, out, errs := runAccessCapture("--session", "aaaa", "--json"); code != 0 || !hasRule(t, out, "Bash(git push *)", "project") {
		t.Errorf("prefix: exit %d %s\n%s", code, errs, out)
	}
	code, _, errs := runAccessCapture("--session", "a")
	if code != 0 {
		t.Fatalf("a unique one-letter prefix should work, exit %d: %s", code, errs)
	}
}

func TestRunAccess_AnAmbiguousSessionPrefixListsTheCandidates(t *testing.T) {
	sessionFixture(t, map[string]map[string]any{
		"aaaa1111": {"title": "first", "cwd": "@PROJECT@"},
		"aaaa2222": {"title": "second", "cwd": "@PROJECT@"},
	})
	code, out, errs := runAccessCapture("--session", "aaaa")
	if code != 1 || out != "" {
		t.Errorf("exit %d stdout %q, want 1 and nothing printed", code, out)
	}
	for _, want := range []string{"aaaa1111", "aaaa2222", "matches 2"} {
		if !strings.Contains(errs, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errs)
		}
	}
}

func TestRunAccess_ATooManyCandidateListIsCapped(t *testing.T) {
	entries := map[string]map[string]any{}
	for i := 0; i < 40; i++ {
		entries[fmt.Sprintf("aaaa%04d", i)] = map[string]any{"cwd": "@PROJECT@"}
	}
	sessionFixture(t, entries)
	_, _, errs := runAccessCapture("--session", "aaaa")
	if n := strings.Count(errs, "aaaa0"); n > 12 {
		t.Errorf("listed %d candidates; a stderr full of ids helps nobody", n)
	}
	if !strings.Contains(errs, "matches 40") {
		t.Errorf("the count is the useful part:\n%s", errs)
	}
}

func TestRunAccess_ExactIdBeatsALongerPrefixMatch(t *testing.T) {
	sessionFixture(t, map[string]map[string]any{
		"abc":    {"cwd": "@PROJECT@", "agentConfigDir": "@CONFIG@"},
		"abcdef": {"cwd": "@PROJECT@"},
	})
	if code, _, errs := runAccessCapture("--session", "abc"); code != 0 {
		t.Errorf("an exact id is not ambiguous, exit %d: %s", code, errs)
	}
}

func TestRunAccess_UnknownSessionSaysHowToHarvest(t *testing.T) {
	sessionFixture(t, map[string]map[string]any{"aaaa": {"cwd": "@PROJECT@"}})
	code, out, errs := runAccessCapture("--session", "zzzz")
	if code != 1 || out != "" {
		t.Errorf("exit %d stdout %q, want 1 and nothing printed", code, out)
	}
	for _, want := range []string{"zzzz", "read-claude-sessions"} {
		if !strings.Contains(errs, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errs)
		}
	}
}

func TestRunAccess_NoMetadataFileIsTheSameAnswerNotACrash(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("USERPROFILE", root)
	code, _, errs := runAccessCapture("--session", "anything")
	if code != 1 || !strings.Contains(errs, "read-claude-sessions") {
		t.Errorf("exit %d stderr %q", code, errs)
	}
}

func TestRunAccess_ACorruptMetadataFileIsReportedNotSwallowed(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("USERPROFILE", root)
	writeAccessFile(t, filepath.Join(root, ".cortex", "session-metadata.json"), `{not json`)
	code, _, errs := runAccessCapture("--session", "anything")
	if code != 1 || !strings.Contains(errs, "session-metadata.json") {
		t.Errorf("exit %d stderr %q, want 1 and the file named", code, errs)
	}
}

func TestRunAccess_SessionWithoutADirectoryShowsUserAndManagedOnlyAndSaysWhy(t *testing.T) {
	_, configDir := sessionFixture(t, map[string]map[string]any{
		"aaaa": {"title": "no dir", "agentConfigDir": "@CONFIG@"},
	})
	_ = configDir
	// The directory the command happens to run in has a policy of its own. It must never be
	// shown as the session's: falling back to the current directory would present an
	// unrelated project's rules as this session's, with nothing to say so.
	elsewhere := t.TempDir()
	writeAccessFile(t, filepath.Join(elsewhere, ".claude", "settings.json"),
		`{"permissions":{"deny":["Bash(rm -rf *)"]}}`)
	t.Chdir(elsewhere)
	code, out, errs := runAccessCapture("--session", "aaaa")
	if code != 0 {
		t.Fatalf("a session with no directory is a degraded answer, not a failure; exit %d: %s", code, errs)
	}
	for _, want := range []string{"no working directory", "Read(./.env)"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	for _, leak := range []string{"Bash(git push *)", "Bash(rm -rf *)"} {
		if strings.Contains(out, leak) {
			t.Errorf("rule %q appeared for a session with no directory:\n%s", leak, out)
		}
	}
}

func TestRunAccess_SessionWhoseDirectoryIsGoneSaysSo(t *testing.T) {
	sessionFixture(t, map[string]map[string]any{
		"aaaa": {"cwd": "@PROJECT@/deleted-worktree", "agentConfigDir": "@CONFIG@"},
	})
	code, out, errs := runAccessCapture("--session", "aaaa")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if !strings.Contains(out, "no longer exists") {
		t.Errorf("a vanished directory should be noted:\n%s", out)
	}
}

func TestRunAccess_SessionOfAnotherAgentIsRefused(t *testing.T) {
	sessionFixture(t, map[string]map[string]any{
		"aaaa": {"agentType": "Codex", "cwd": "@PROJECT@"},
	})
	code, _, errs := runAccessCapture("--session", "aaaa")
	if code != 1 || !strings.Contains(errs, "Codex") {
		t.Errorf("exit %d stderr %q: another agent's settings model is not Claude Code's", code, errs)
	}
}

func TestRunAccess_ExplicitFlagsOverrideTheSessionsRecordedValues(t *testing.T) {
	_, _ = sessionFixture(t, map[string]map[string]any{
		"aaaa": {"cwd": "@PROJECT@", "agentConfigDir": "@CONFIG@"},
	})
	empty := t.TempDir()
	code, out, _ := runAccessCapture("--session", "aaaa", "--config-dir", empty, "--json")
	if code != 0 || hasRule(t, out, "Read(./.env)", "user") {
		t.Errorf("--config-dir should win over the entry's agentConfigDir (exit %d):\n%s", code, out)
	}
}

func TestRunAccess_SessionAndCwdAreMutuallyExclusive(t *testing.T) {
	code, _, errs := runAccessCapture("--session", "a", "--cwd", "/x")
	if code != 2 || !strings.Contains(errs, "--session") || !strings.Contains(errs, "--cwd") {
		t.Errorf("exit %d stderr %q, want 2 naming both flags", code, errs)
	}
}

func TestRunAccess_SessionNoteNamesTheSessionAndItsTitleInBothForms(t *testing.T) {
	sessionFixture(t, map[string]map[string]any{
		"aaaa1111": {"title": "fix the thing", "cwd": "@PROJECT@", "agentConfigDir": "@CONFIG@"},
	})
	_, out, _ := runAccessCapture("--session", "aaaa")
	if !strings.Contains(out, "aaaa1111") || !strings.Contains(out, "fix the thing") {
		t.Errorf("text output should say which session this is:\n%s", out)
	}
	_, js, _ := runAccessCapture("--session", "aaaa", "--json")
	var p struct {
		Notes []string `json:"notes"`
	}
	if err := json.Unmarshal([]byte(js), &p); err != nil || len(p.Notes) == 0 {
		t.Errorf("JSON notes = %v err %v, want the session described", p.Notes, err)
	}
}

func TestRunAccess_HelpDescribesSession(t *testing.T) {
	_, _, errs := runAccessCapture("--help")
	for _, want := range []string{"--session", "read-claude-sessions"} {
		if !strings.Contains(errs, want) {
			t.Errorf("--help lacks %q:\n%s", want, errs)
		}
	}
}

// --- --explain ---------------------------------------------------------------------------------

// explainFixture is a project whose rules cover each verdict.
func explainFixture(t *testing.T) (args []string) {
	t.Helper()
	root := t.TempDir()
	project := filepath.Join(root, "proj")
	cfg := filepath.Join(root, "claude")
	writeAccessFile(t, filepath.Join(cfg, "settings.json"),
		`{"permissions":{"deny":["Read(./.env)","Bash(rm *)"],"allow":["Bash(git status)","Bash(npm test *)"]}}`)
	writeAccessFile(t, filepath.Join(project, ".claude", "settings.json"),
		`{"permissions":{"ask":["Bash(git push *)","WebFetch(domain:example.com)"]}}`)
	return []string{"--cwd", project, "--config-dir", cfg}
}

func explain(t *testing.T, base []string, what string, extra ...string) (code int, out, errs string) {
	t.Helper()
	return runAccessCapture(append(append(append([]string{}, base...), "--explain", what), extra...)...)
}

func TestRunAccess_ExplainEachVerdict(t *testing.T) {
	base := explainFixture(t)
	for _, c := range []struct {
		what    string
		verdict string
		rule    string // the deciding rule, when there is one
	}{
		{"Read(./.env)", "deny", "Read(./.env)"},
		{"Bash(rm -rf build)", "deny", "Bash(rm *)"},
		{"Bash(git push origin main)", "ask", "Bash(git push *)"},
		{"WebFetch(domain:example.com)", "ask", "WebFetch(domain:example.com)"},
		{"Bash(git status)", "allow", "Bash(git status)"},
		{"Bash(git status && ls)", "partial", ""},
		{"Bash(ls -la)", "none", ""},
		{"Read(./README.md)", "none", ""},
	} {
		code, out, errs := explain(t, base, c.what)
		if code != 0 {
			t.Errorf("%s: exit %d: %s", c.what, code, errs)
			continue
		}
		if !strings.Contains(out, "VERDICT") || !strings.Contains(out, c.verdict) {
			t.Errorf("%s: output lacks the %q verdict:\n%s", c.what, c.verdict, out)
		}
		if c.rule != "" && !strings.Contains(out, c.rule) {
			t.Errorf("%s: output lacks the deciding rule %q:\n%s", c.what, c.rule, out)
		}
	}
}

// The explanation says WHERE the deciding rule came from, which is the point of asking.
func TestRunAccess_ExplainNamesTheLayerAndFile(t *testing.T) {
	base := explainFixture(t)
	_, out, _ := explain(t, base, "Bash(git push origin main)")
	if !strings.Contains(out, "project") || !strings.Contains(out, "settings.json") {
		t.Errorf("output should name the project layer and its file:\n%s", out)
	}
}

// "none" must say what it is not, or the reader takes it for "allowed".
func TestRunAccess_ExplainNoneSaysItIsNotAllowed(t *testing.T) {
	_, out, _ := explain(t, explainFixture(t), "Bash(ls -la)")
	for _, want := range []string{"no rule matches", "not", "mode"} {
		if !strings.Contains(out, want) {
			t.Errorf("a 'none' verdict should explain itself; lacks %q:\n%s", want, out)
		}
	}
}

func TestRunAccess_ExplainJSON(t *testing.T) {
	base := explainFixture(t)
	code, out, errs := explain(t, base, "Bash(git push origin main)", "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	var got struct {
		Match struct {
			Verdict string `json:"verdict"`
			Rules   []struct {
				Raw    string `json:"raw"`
				Source string `json:"source"`
			} `json:"rules"`
			Caveats []string `json:"caveats"`
		} `json:"match"`
		Layers []any `json:"layers"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, out)
	}
	if got.Match.Verdict != "ask" || len(got.Match.Rules) != 1 || got.Match.Rules[0].Source != "project" {
		t.Errorf("match = %+v", got.Match)
	}
	if len(got.Layers) != 5 {
		t.Errorf("the policy is still in the JSON: layers = %d", len(got.Layers))
	}
	// without --explain there is no match key
	_, plain, _ := runAccessCapture(append(base, "--json")...)
	if strings.Contains(plain, `"match"`) {
		t.Errorf("a match key without --explain:\n%.200s", plain)
	}
}

func TestRunAccess_ExplainAcceptsTheToolWithNoParentheses(t *testing.T) {
	base := explainFixture(t)
	code, out, _ := explain(t, base, "Bash")
	if code != 0 || !strings.Contains(out, "VERDICT") {
		t.Errorf("exit %d:\n%s", code, out)
	}
}

func TestRunAccess_ExplainToolSyntax(t *testing.T) {
	base := explainFixture(t)
	for _, c := range []struct {
		what string
		want string // a substring of the output
	}{
		{"Read(./.env)", "deny"},
		{"Edit(./.env)", "deny"},                   // a Read deny blocks Edit on the same path
		{"WebFetch(https://example.com/x)", "ask"}, // a URL is the primary field; the domain is derived
		{"Agent(Explore)", "none"},
		{"mcp__srv__tool", "none"},
	} {
		code, out, errs := explain(t, base, c.what)
		if code != 0 || !strings.Contains(out, c.want) {
			t.Errorf("%s: exit %d want %q:\n%s%s", c.what, code, c.want, out, errs)
		}
	}
}

func TestRunAccess_ExplainWithASession(t *testing.T) {
	sessionFixture(t, map[string]map[string]any{
		"aaaa1111": {"title": "t", "cwd": "@PROJECT@", "agentConfigDir": "@CONFIG@", "permissionMode": "acceptEdits"},
	})
	code, out, errs := runAccessCapture("--session", "aaaa", "--explain", "Bash(git push origin main)")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if !strings.Contains(out, "ask") || !strings.Contains(out, "Bash(git push *)") {
		t.Errorf("the session's project rules should decide:\n%s", out)
	}
}

func TestRunAccess_ExplainMalformedIsExit2WithUsage(t *testing.T) {
	base := explainFixture(t)
	// "Bash(a)(b)" is NOT here: the docs say parentheses inside a specifier are literal, so it is
	// the command `a)(b`. It is accepted, and TestRunAccess_ExplainParenthesesInsideAreLiteral
	// says what it means.
	for _, bad := range []string{"", "   ", "Bash(", "(x)", "Bash(a) trailing", "bad tool(x)", "Bash(x", "mcp__srv__tool(x)", strings.Repeat("a", 20000)} {
		code, out, errs := explain(t, base, bad)
		if code != 2 {
			t.Errorf("%q: exit %d, want 2 (stdout %q)", bad[:min(len(bad), 20)], code, out)
		}
		if !strings.Contains(errs, "--explain") {
			t.Errorf("%q: stderr lacks the usage:\n%.200s", bad[:min(len(bad), 20)], errs)
		}
	}
}

// What the user types is echoed back. A terminal escape in it must not reach the terminal.
func TestRunAccess_ExplainNeverEchoesControlBytes(t *testing.T) {
	base := explainFixture(t)
	evil := "Bash(echo \x1b]0;pwned\x07\x1b[2J hi)"
	_, out, errs := explain(t, base, evil)
	for _, s := range []string{out, errs} {
		for i := 0; i < len(s); i++ {
			if b := s[i]; (b < 0x20 && b != '\n') || b == 0x7f {
				t.Fatalf("output carries control byte %#x: %q", b, s)
			}
		}
		if strings.Contains(s, "pwned") {
			t.Errorf("the escape sequence's payload was echoed: %q", s)
		}
	}
}

func TestRunAccess_ExplainHelpDocumentsItAndWhatItCannotSay(t *testing.T) {
	_, _, errs := runAccessCapture("--help")
	for _, want := range []string{"--explain", "read-only", "mode", "none"} {
		if !strings.Contains(errs, want) {
			t.Errorf("--help lacks %q:\n%s", want, errs)
		}
	}
}

func TestRunAccess_ExplainParenthesesInsideAreLiteral(t *testing.T) {
	base := explainFixture(t)
	code, out, _ := explain(t, base, "Bash(echo (hi))")
	if code != 0 || !strings.Contains(out, "echo (hi)") {
		t.Errorf("exit %d: parentheses inside the specifier are literal:\n%s", code, out)
	}
}

func TestParseExplain(t *testing.T) {
	cases := []struct {
		in    string
		tool  string
		field string
		want  string
	}{
		{"Bash(git push origin main)", "Bash", "command", "git push origin main"},
		{"Bash( ls )", "Bash", "command", " ls "}, // the content is verbatim: a rule's whitespace matters
		{"Read(./.env)", "Read", "file_path", "./.env"},
		{"Edit(/etc/hosts)", "Edit", "file_path", "/etc/hosts"},
		{"NotebookEdit(a.ipynb)", "NotebookEdit", "notebook_path", "a.ipynb"},
		{"Grep(src)", "Grep", "path", "src"},
		{"WebFetch(https://example.com/a)", "WebFetch", "url", "https://example.com/a"},
		{"WebFetch(domain:example.com)", "WebFetch", "url", "https://example.com/"},
		{"Agent(Explore)", "Agent", "subagent_type", "Explore"},
		{"Skill(grilling)", "Skill", "skill", "grilling"},
		{"Bash(echo (hi))", "Bash", "command", "echo (hi)"},
		{"  Bash(ls)  ", "Bash", "command", "ls"},
	}
	for _, c := range cases {
		got, err := access.ParseExplain(c.in)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if got.Tool != c.tool || got.Input[c.field] != c.want {
			t.Errorf("%q = %+v, want tool %s %s=%q", c.in, got, c.tool, c.field, c.want)
		}
	}
	// a bare tool name has no input
	for _, tool := range []string{"Bash", "mcp__srv__tool", "Read"} {
		got, err := access.ParseExplain(tool)
		if err != nil || got.Tool != tool || len(got.Input) != 0 || got.Input == nil {
			t.Errorf("%q = %+v, %v; want the tool with an empty, non-nil input", tool, got, err)
		}
	}
}

// A caveat can carry text from the user's own call (a Bash command that is not analysable names
// its cause), so the NOTE line is cleaned as well as the CALL line.
func TestResultText_NeverEmitsControlBytesFromCaveatsOrRules(t *testing.T) {
	r := access.Result{
		Verdict:     access.VerdictPartial,
		Caveats:     []string{"note \x1b]0;pwned\x07 end", "second \x1b[2J"},
		Rules:       []access.Rule{{Decision: access.Allow, Raw: "Bash(a\x1b[0m)", Source: access.User, File: "/x\x1by"}},
		Unevaluated: []access.Rule{{Decision: access.Deny, Raw: "Bash(b\x07)", Source: access.Local, File: "/z\x00"}},
	}
	out := r.Text(access.Call{Tool: "Bash", Input: map[string]any{"command": "ls\x1b[2J"}})
	for i := 0; i < len(out); i++ {
		if b := out[i]; (b < 0x20 && b != '\n') || b == 0x7f {
			t.Fatalf("Text() carries control byte %#x: %q", b, out)
		}
	}
	if strings.Contains(out, "pwned") || strings.Contains(out, "[2J") {
		t.Errorf("an escape payload survived: %q", out)
	}
}

func TestParseExplain_RejectsWhatIsNotAToolName(t *testing.T) {
	for _, bad := range []string{
		"bad tool(x)", "a/b(x)", "a.b(x)", "Bash;ls(x)", "Bash\n(x)", "ba$h(x)", "Bash\x1b(x)",
		"bad tool", "a b", strings.Repeat("a", 201) + "(x)",
	} {
		if _, err := access.ParseExplain(bad); err == nil {
			t.Errorf("%q was accepted as a tool name", bad[:min(len(bad), 20)])
		}
	}
	for _, good := range []string{"Bash", "mcp__srv__tool", "my-tool", "T9", "a"} {
		if _, err := access.ParseExplain(good); err != nil {
			t.Errorf("%q was rejected: %v", good, err)
		}
	}
}

func TestParseExplain_TheLengthLimitIsExactAndMeasuredInTheWholeInput(t *testing.T) {
	// "Bash(" + content + ")" is 6 characters of syntax around the content.
	atLimit := "Bash(" + strings.Repeat("a", 12000-6) + ")"
	if len(atLimit) != 12000 {
		t.Fatalf("fixture is %d long", len(atLimit))
	}
	if _, err := access.ParseExplain(atLimit); err != nil {
		t.Errorf("an input exactly at the limit was refused: %v", err)
	}
	over := "Bash(" + strings.Repeat("a", 12000-5) + ")"
	if _, err := access.ParseExplain(over); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Errorf("err = %v, want a 'too long' refusal", err)
	}
}

// A tool this view has no primary argument for must not be turned into a call with an empty
// input: that would silently ask about "any call", and an MCP tool's arguments are its own.
func TestParseExplain_AToolWithNoKnownArgumentIsRefusedNotEmptied(t *testing.T) {
	for _, in := range []string{"mcp__srv__tool(x)", "CronCreate(x)", "TaskStop(1)", "Custom(whatever)"} {
		c, err := access.ParseExplain(in)
		if err == nil {
			t.Errorf("%q = %+v with no error: its argument was dropped without saying so", in, c)
		} else if !strings.Contains(err.Error(), "which argument") {
			t.Errorf("%q: err = %v, want it to say it does not know which argument", in, err)
		}
		if c.Tool != "" || len(c.Input) != 0 {
			t.Errorf("%q returned a partial call alongside the error: %+v", in, c)
		}
	}
}

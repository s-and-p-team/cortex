package main

import (
	"bytes"
	"encoding/json"
	"fmt"
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

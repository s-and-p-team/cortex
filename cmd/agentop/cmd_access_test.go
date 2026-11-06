package main

import (
	"bytes"
	"encoding/json"
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

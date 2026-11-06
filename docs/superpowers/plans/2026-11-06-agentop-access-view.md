# agentop Access View, Phase 1 (resolver + CLI) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `agentop access --cwd PATH [--json]` prints the effective Claude Code permission policy for a working directory: the five settings layers, the deciding layer for mode and sandbox, the merged allow/ask/deny rules with shadow markers, and risk flags.

**Architecture:** A new pure package `cmd/agentop/access` (peer of `toolscan/`, `money/`; imports nothing from `tui/`) exposes `Resolve(Input) (Policy, error)` over an injected `fs.FS`. A thin `cmd_access.go` wires flags, the real filesystem and output. No TUI, session-API or harvest change in this phase.

**Tech Stack:** Go 1.26.10, stdlib `encoding/json`, `io/fs`, `testing/fstest`; module `cmd/agentop`.

**Spec:** `docs/superpowers/specs/2026-11-06-agentop-access-view-design.md`

## Global Constraints

- Work only in the worktree `.claude/worktrees/access-view`, branch `feat/agentop-access-view`.
- Every commit: `git commit -s` (DCO) + `Assisted-By: Claude (Anthropic AI) <noreply@anthropic.com>`; never `Co-Authored-By`.
- Run Go per-module with `GOWORK=off` for `cmd/agentop`. Run `gofmt -l cmd/agentop` and `go vet` before pushing.
- Red-first: each test is written, run, and seen to fail before its implementation.
- Read-only: the resolver never writes and only opens the named settings files.
- **No Go toolchain was on PATH when this plan was written.** Install one (`go 1.26.10`) before Task 1; nothing below has been compiled or run.

## Task 0: Confirm the rules (blocks Task 2)

The precedence and pattern rules in the spec are a reading of Claude Code's documentation, not verified against its source.

- [ ] Re-read the current Claude Code docs for settings files, permissions, and managed settings. Record in `access/doc.go` the exact: layer order, which keys merge vs override, the managed-settings paths per OS, and the rule syntax forms.
- [ ] Where the docs are silent, test empirically with a scratch directory and `claude` and record the observed behavior in the same comment. Do not guess.
- [ ] If any rule differs from the spec, update the spec first, in the same PR.

## Review Focus

- **Malformed JSON in one layer** must set `Layer.Err` and contribute nothing; the other layers still resolve. Test in Task 2.
- **Missing files** are `Present: false`, never an error. Test in Task 2.
- **`env` values must never appear in `Policy`** or any output (settings files can hold secrets). Test in Task 3.
- **Deny beats ask beats allow across layers**, including a user-level deny against a local-level allow. Test in Task 2.
- **Managed scalars are not overridable** by any lower layer. Test in Task 2.
- **Rule order in output is deterministic** (decision, then tool, then pattern, then layer), since `--json` is a script interface. Test in Task 3.

---

### Task 1: Types and layer discovery

**Files:**
- Create: `cmd/agentop/access/types.go`, `cmd/agentop/access/layers.go`, `cmd/agentop/access/doc.go`
- Test: `cmd/agentop/access/layers_test.go`

**Interfaces:**
- Produces: `Input`, `Policy`, `Layer`, `LayerKind` (`Managed`, `CLI`, `Local`, `Project`, `User`), `Counts`; `func discoverLayers(in Input) []Layer` returning the five layers highest-first with `Path` filled and `Present` set from `in.FS`.

- [ ] **Step 1: Write the failing test**

```go
package access

import (
	"testing"
	"testing/fstest"
)

func TestDiscoverLayers_OrderAndPresence(t *testing.T) {
	fsys := fstest.MapFS{
		"proj/.claude/settings.json": {Data: []byte(`{}`)},
		"home/.claude/settings.json": {Data: []byte(`{}`)},
	}
	in := Input{Cwd: "proj", ConfigDir: "home/.claude", FS: fsys, GOOS: "darwin"}
	got := discoverLayers(in)
	wantKinds := []LayerKind{Managed, CLI, Local, Project, User}
	if len(got) != len(wantKinds) {
		t.Fatalf("got %d layers, want %d", len(got), len(wantKinds))
	}
	for i, k := range wantKinds {
		if got[i].Kind != k {
			t.Errorf("layer %d = %v, want %v", i, got[i].Kind, k)
		}
	}
	if got[3].Kind != Project || !got[3].Present {
		t.Errorf("project layer should be present: %+v", got[3])
	}
	if got[2].Present {
		t.Errorf("local layer should be absent: %+v", got[2])
	}
}
```

- [ ] **Step 2:** `cd cmd/agentop && GOWORK=off go test ./access/ -run TestDiscoverLayers` — expect FAIL (undefined).
- [ ] **Step 3:** Implement the types and `discoverLayers`. Managed path by `GOOS` from Task 0; `ConfigDir == ""` means `~/.claude` unless `CLAUDE_CONFIG_DIR`-style input is passed by the caller (the resolver itself reads no environment).
- [ ] **Step 4:** Run the test — expect PASS. `gofmt -l access`.
- [ ] **Step 5:** Commit: `feat(agentop): access layer discovery`.

---

### Task 2: Resolve — merge, precedence, shadowing

**Files:**
- Create: `cmd/agentop/access/resolve.go`, `cmd/agentop/access/settings.go` (JSON shape: only `permissions`, `sandbox`, `hooks`, `additionalDirectories`; everything else, including `env`, is dropped at decode)
- Test: `cmd/agentop/access/resolve_test.go`

**Interfaces:**
- Consumes: `discoverLayers` (Task 1).
- Produces: `func Resolve(in Input) (Policy, error)`. `error` is reserved for `Input` misuse (nil FS); layer problems live in `Layer.Err`.

- [ ] **Step 1: Write failing table-driven tests** covering, each as its own case with an in-memory `fstest.MapFS`:
  1. each layer alone yields its rules with `Source` set;
  2. user `deny: Read(./.env)` + local `allow: Read(./.env)` → deny wins, the allow has `ShadowedBy` set;
  3. project `ask` + user `allow` for the same tool pattern → ask wins;
  4. managed `defaultMode` + local `defaultMode` → `Mode.Layer == Managed`;
  5. malformed JSON in project → `Layer.Err != nil`, user rules still present;
  6. no `.claude/` anywhere → five layers, all `Present: false`, no error;
  7. `additionalDirectories` merge across layers, deduplicated, each with its source.
- [ ] **Step 2:** Run — expect FAIL.
- [ ] **Step 3:** Implement per the Task 0 rules. Keep rule comparison in one function (`sameMatch`) so the shadowing rule is in a single place.
- [ ] **Step 4:** Run — expect PASS; run the whole package.
- [ ] **Step 5:** Commit: `feat(agentop): resolve the effective permission policy`.

---

### Task 3: Output stability, secrets, risk flags

**Files:**
- Create: `cmd/agentop/access/flags.go`, `cmd/agentop/access/render.go`
- Test: `cmd/agentop/access/flags_test.go`, `cmd/agentop/access/render_test.go`

**Interfaces:**
- Produces: `Policy.Flags []RiskFlag` (set by `Resolve`); `func (p Policy) Text() string` and `json.Marshal(Policy)` with a stable field order and rule order.

- [ ] **Step 1: Failing tests:** `bypassPermissions` default mode flags; allow `Bash` (bare) and `Bash(*)` flag; sandbox disabled flags; `additionalDirectories` containing `/` or the home dir flags; a settings file with `"env": {"TOKEN": "s3cret"}` produces output that contains neither the key nor `s3cret` in either `Text()` or JSON; two runs over the same input produce byte-identical JSON.
- [ ] **Step 2:** Run — expect FAIL.
- [ ] **Step 3:** Implement flags and renderers. Sort rules by decision (deny, ask, allow), tool, pattern, layer.
- [ ] **Step 4:** Run — expect PASS.
- [ ] **Step 5:** Commit: `feat(agentop): risk flags and stable policy output`.

---

### Task 4: `agentop access` command

**Files:**
- Create: `cmd/agentop/cmd_access.go`
- Modify: `cmd/agentop/main.go:72` (add `"access"` to `dispatchableSubcommands`) and the dispatch switch near `main.go:127`; the usage text
- Test: `cmd/agentop/cmd_access_test.go`

**Interfaces:**
- Produces: `func runAccess(args []string, stdout, stderr io.Writer) int` with flags `--cwd` (default: current directory), `--config-dir` (default: `CLAUDE_CONFIG_DIR`, else `~/.claude`), `--json`. Exit 0 on success, 2 on bad flags, 1 on resolve failure. Same shape as `runPricing`.

- [ ] **Step 1: Failing tests** in the style of `cmd_pricing_test.go`: text output lists five layers and the rules; `--json` is valid JSON; an unknown flag returns 2 and prints usage; `--cwd` pointing at a missing directory still succeeds with project layers absent and says so.
- [ ] **Step 2:** Run — expect FAIL.
- [ ] **Step 3:** Implement using `os.DirFS("/")` for the real filesystem with absolute paths trimmed of the leading slash, and register the subcommand. Update the `--help` text and any test asserting the subcommand list.
- [ ] **Step 4:** Run the package tests, then the whole `cmd/agentop` module (`GOWORK=off go test ./...`).
- [ ] **Step 5:** Commit: `feat(agentop): add the access command`.

---

### Task 5: Docs and manual check

**Files:**
- Create: `docs/agentop-access.md` (what the command shows, the layer order with the caveat that it is "as of now", no cwd for remote sessions)
- Modify: `cmd/agentop/README.md` (one line listing the subcommand)

- [ ] Run `agentop access --cwd <a real project>` and compare against Claude Code's own `/permissions` output for the same directory. Any difference is a bug in the resolver or in Task 0's notes; fix before merging.
- [ ] `gofmt -l`, `go vet`, full `go test ./...` for `cmd/agentop`.
- [ ] Open the PR; description lists what was verified and what was not (Task 0 outcomes).

## Out of scope

Harvesting `Cwd`, `paneAccess`, the `RULE` column, `Policy.Match` and the detail-pane fold — phases 2–4 of the spec.

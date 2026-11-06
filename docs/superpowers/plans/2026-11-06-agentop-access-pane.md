# agentop Access Pane, Phase 3 (the `V` pane) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Pressing `V` on a session opens a pane showing that session's effective Claude Code permission policy: the layer stack, the configured and recorded mode, the rules in evaluation order with shadowed ones dimmed, and the risk flags. Every case where the answer cannot be given (remote session, no harvest entry, no directory, another agent) says so in words.

**Architecture:** The pane is a thin view over `access.Resolve`, which phases 1 and 2 built. A new `paneAccess` follows `paneTimeline`'s shape: opened with a session id and a return pane, loaded by a `tea.Cmd` with a request sequence number, drawn into a viewport. Building a resolver `Input` from a session moves out of `package main` into `access` so the command and the pane share it.

**Tech Stack:** Go 1.26.10, bubbletea/bubbles/lipgloss as already used by `cmd/agentop/tui`.

**Spec:** `docs/superpowers/specs/2026-11-06-agentop-access-view-design.md` (§4 TUI).
**Builds on:** `docs/superpowers/plans/2026-11-06-agentop-access-view.md` (phase 1) and the phase 2 commits `4ed615e7`, `275f5bfb`.

## Global Constraints

- Work only in the worktree `.claude/worktrees/access-view`, branch `feat/agentop-access-view`.
- Every commit: `git commit -s` + `Assisted-By: Claude (Anthropic AI) <noreply@anthropic.com>`; never `Co-Authored-By`.
- `source agentop/.tools/env.sh`; run per-module with `GOWORK=off` for `cmd/agentop`. Local-port tests and module downloads need the sandbox off. Run `gofmt -l <path>` and `go vet ./...`.
- Red-first: each test is written, run, and seen to fail before its implementation. After green, **mutate the implementation once per rule and confirm a test fails**; phases 1 and 2 found a weak test this way.
- **The root `cmd/agentop` package does not finish a full run** in this environment (a clean checkout also times out, on a different test each run). Run the packages you touch by name: `./tui/ ./access/` and `-run` selections in `.`.
- Read-only: the pane never writes any file.
- The pane must not panic on a zero-value `model`: `TestAgentsPane_StartupLeavesAnOperatorWhoHasMoved` builds bare models for every pane up to `lastPaneID`.

## Review Focus

- **Remote sessions must never read local files.** When the connection is not this machine's Cortex, the pane says "unavailable" and calls no resolver. Showing this laptop's policy for a cluster session is the worst failure available. Test in Task 3.
- **Settings text is untrusted** (a cloned repo's `.claude/settings.json`). Rule text, paths and error strings must be stripped of control and escape characters before they reach the terminal, in the pane **and in `Policy.Text()`**, which today prints them raw. Test in Tasks 1 and 4.
- **No fallback to the current directory** for a session with no recorded directory. Test in Task 3.
- **A stale reply never overwrites a newer one** (request sequence), and a reply for a session the reader has left is dropped. Test in Task 3.
- **Opening the pane never blocks the UI:** resolution runs in a `tea.Cmd`.
- **All pane invariants hold:** `lastPaneID`, `paneKeys`, `otherPaneOrder`, footer, search surface, help height budget. Task 5.

---

### Task 1: Share input-building, and stop `Text()` writing raw settings text

**Files:**
- Create: `cmd/agentop/access/local.go`, `cmd/agentop/access/sanitize.go`
- Modify: `cmd/agentop/cmd_access.go` (use the moved code), `cmd/agentop/access/render.go` (sanitize)
- Test: `cmd/agentop/access/local_test.go`, `cmd/agentop/access/sanitize_test.go`; keep `cmd_access_test.go` green

**Interfaces:**
- Produces: `access.LocalInput(cwd, configDir, cliSettings string, cwdUnknown bool) (Input, error)` (the body of `accessInput`, the only place that reads the environment), `access.GitRoot(dir string) string`, `access.DescribeSession(id, title, cwd string) string`, `access.Clean(s string) string`.
- `Resolve` stays pure; `local.go` is the one file in the package that touches `os`.

- [ ] **Step 1: Failing tests**
  - `Clean`: strips C0/C1 controls, ESC sequences (`\x1b[31m` → `[31m` is not acceptable: the whole sequence goes), bidi overrides, U+2028/2029, NUL; keeps ordinary Unicode and spaces; idempotent.
  - `Text()` given a project file whose rule is `"Bash(\u001b]0;pwned\u0007)"` and whose path is under a directory name containing `\x1b`: output contains no byte below 0x20 other than `\n`, and no `\x1b`.
  - `LocalInput` / `GitRoot` / `DescribeSession` move their existing tests from `cmd_access_test.go` (git root found; relative cwd made absolute; `CLAUDE_CONFIG_DIR` fallback; empty cwd with `cwdUnknown` stays empty).
- [ ] **Step 2:** `go test ./access/` — expect FAIL (undefined).
- [ ] **Step 3:** Move `accessInput`, `gitRoot` and `sessionRef.describe` into `access/local.go`; add `Clean`; apply it in `render.go` to every string that came from a file (rule raw text, paths, error text, hook event names, note lines, ignored reasons).
- [ ] **Step 4:** Run `./access/` and the `TestRunAccess` selection in `.` — expect PASS. Mutate: remove the `Clean` call on rule text; the injection test must fail.
- [ ] **Step 5:** Commit: `fix(agentop): sanitize settings text in access output; share input building`.

---

### Task 2: Pane state, key, and the target decision

**Files:**
- Create: `cmd/agentop/tui/access_pane.go`
- Modify: `cmd/agentop/tui/app.go` (`paneAccess` after `paneTimeline`, `lastPaneID = paneAccess`, model field `access accessState`), `cmd/agentop/tui/keys.go` (the `V` handler beside `T`)
- Test: `cmd/agentop/tui/access_pane_test.go`

**Interfaces:**
- Consumes: `m.selectedSess`, `m.selectedSessionID()`, `m.sessionsData[id]` (a `SessionMetadata` carrying `Cwd`, `PermissionMode`, `AgentType`, `AgentConfigDir`), `m.sessions`, `m.client`, `m.localEndpoint`, `sameEndpoint`.
- Produces: `type accessState struct { session string; returnPane paneID; reqSeq uint64; loading bool; policy *access.Policy; target accessTarget; vp viewport.Model; doc ...}` and
  `type accessTarget struct { Kind targetKind; Reason string; Input access.Input }` with kinds `targetOK`, `targetRemote`, `targetNoEntry`, `targetNoCwd`, `targetOtherAgent`, `targetNoClient`.
- `func (m *model) accessTargetFor(session string) accessTarget` — **pure** (no I/O), so the five degraded states are table-testable.

- [ ] **Step 1: Failing tests** (table-driven over `accessTargetFor`):
  - connected to this machine's Cortex (`sameEndpoint(client.Endpoint(), localEndpoint)`), entry with cwd → `targetOK`, `Input.Cwd` set, `SessionMode` from the entry, `ConfigDir` from the entry.
  - client endpoint is not the local one → `targetRemote`, reason names the endpoint, **`Input` is the zero value** (the resolver cannot be called with local paths by accident).
  - no `localEndpoint` known at all → `targetRemote` (unknown is not local).
  - no entry in `sessionsData` → `targetNoEntry`, reason says the harvest has not read this session and how to run it.
  - entry with `AgentType` "Codex" → `targetOtherAgent`.
  - entry without cwd → `targetNoCwd` **and** `Input` still usable for the user/managed layers, with `Cwd == ""`.
  - `V` on sessions/events/detail opens the pane with the right session and `returnPane`; `V` on namespaces/pods/pipeline/catalog/usage/agents does nothing; `V` while searching or in the column picker types a letter, not a pane switch (same gate as `T`).
- [ ] **Step 2:** `go test ./tui/ -run Access` — expect FAIL.
- [ ] **Step 3:** Implement. Reuse `access.LocalInput` and `access.DescribeSession`. Do **not** reimplement the remote test: use `sameEndpoint` as `localCortexTarget` does, and require `m.localEndpoint != ""` (never `localEndpointOr()`, whose fallback is the in-cluster address).
- [ ] **Step 4:** Run — expect PASS. Mutate: treat an empty `localEndpoint` as local; the remote test must fail.
- [ ] **Step 5:** Commit: `feat(agentop): add the access pane's state and V key`.

---

### Task 3: Load, refresh and stale replies

**Files:**
- Modify: `cmd/agentop/tui/access_pane.go`, `cmd/agentop/tui/app.go` (route `accessLoadedMsg` in `Update`)
- Test: `cmd/agentop/tui/access_pane_test.go`

**Interfaces:**
- Produces: `openAccess(session) tea.Cmd`, `fetchAccess() tea.Cmd`, `type accessLoadedMsg struct { req uint64; session string; policy access.Policy; err error }`, `handleAccessLoaded`.

- [ ] **Step 1: Failing tests:**
  - `openAccess` sets pane, `returnPane`, session, bumps `reqSeq`, and returns a non-nil cmd only for `targetOK` / `targetNoCwd` (degraded kinds resolve nothing and call no resolver; assert with an injected resolver func that records calls, **zero calls for remote / no-entry / other-agent**).
  - A reply with an old `req` is ignored; a reply for another session is dropped; a newer one replaces.
  - Re-opening the same session keeps the last policy on screen while refreshing (no blank flash); opening a different session clears it.
  - `r` re-resolves (the files may have changed); there is no timer: files change on a human timescale and the CLI says "as of now".
  - A resolver error becomes a visible line, not a blank pane.
  - The resolver is injected as a `model` field (`accessResolve func(access.Input) (access.Policy, error)`, default `access.Resolve`) so tests do not touch the real home directory.
- [ ] **Step 2–4:** Fail, implement, pass. Mutate: drop the `req` comparison; the stale-reply test must fail.
- [ ] **Step 5:** Commit: `feat(agentop): load the access policy off the UI goroutine`.

---

### Task 4: Rendering

**Files:**
- Create: `cmd/agentop/tui/access_render.go`
- Test: `cmd/agentop/tui/access_render_test.go`

**Interfaces:**
- Produces: `func accessLines(p access.Policy, t accessTarget, width int) []string` — pure, one string per line, styled with the existing `style*` vars. **A viewport of lines, not a table**: a table cell cannot carry ANSI (`TestSessionsRows_CarryNoANSIUnderAForcedColourProfile`), and dimming a shadowed rule needs it.

Layout, top to bottom (each section omitted only when empty, never silently):

```
session 0834b33b (Greeting to Oleg)  ·  started in /Users/me/proj
LAYERS (highest first)
  managed  /Library/…/managed-settings.json   absent        file sources only
  cli      –
  local    /Users/me/.claude/settings.local.json   present   allow 49  ask 0  deny 0
  project  …/.claude/settings.json              absent
  user     ~/.claude/settings.json               present   allow 8  ask 0  deny 4
MODE  configured: default (user)    this session: auto
SANDBOX on (user)    HOOKS PreToolUse (user)    DIRS 1
FLAGS  ! high bypass-permissions …
RULES (deny → ask → allow; first match wins)
  deny   Read(.env)                 user
  allow  Bash(git *)                local      shadowed by ask Bash(git push *) (project)   <dim>
```

- [ ] **Step 1: Failing tests:**
  - Every layer appears even when absent; a layer with an error shows the error; the managed `Note` is shown.
  - Rules appear deny, ask, allow; a shadowed rule's line contains "shadowed by" and carries the dim style under a forced colour profile; an `Ignored` rule says why; `NeedsTrust` is marked.
  - Configured and session modes are both shown when they differ, and the label does not call the configured one "the mode".
  - Flags are listed high first; a `session-bypass` flag renders even when no file sets bypass.
  - Each degraded `accessTarget` kind renders its reason in words and **no rules, no layers** for remote / no-entry / other-agent; `targetNoCwd` renders user + managed layers and the explanation.
  - **Width:** at 60, 80 and 200 columns no line exceeds the width (measured with `lipgloss.Width`, ANSI-aware); long paths and rule text are truncated in the middle or tail with `…`, never wrapped into the next section; a rule longer than the width stays on one line.
  - **Injection:** a rule, path and error containing ESC, BEL, NUL, bidi overrides and `\n` render with none of those bytes (run `access.Clean` at the boundary, once, not per call site).
  - **Large input:** 5,000 rules renders in bounded time and the viewport scrolls; assert line count and that the render completes under a generous bound.
- [ ] **Step 2–4:** Fail, implement, pass; mutate (skip `Clean` on rule text; skip the shadow dim) and confirm a failure each.
- [ ] **Step 5:** Commit: `feat(agentop): render the access policy`.

---

### Task 5: Wire the pane into the TUI's invariants

**Files:**
- Modify: `cmd/agentop/tui/app.go` (`View` case, `title`), `cmd/agentop/tui/keys.go` (scroll / `r` / `esc` handling; `esc` returns to `returnPane`), `cmd/agentop/tui/footer.go` (hint line), `cmd/agentop/tui/help_overlay.go` (`paneKeys[paneAccess]`, `otherPaneOrder`, the global `V` row), `cmd/agentop/tui/search_surfaces.go` (`docSurface` over the pane's viewport)
- Modify tests: `cmd/agentop/tui/help_overlay_test.go` (`helpNoScrollHeight`)

- [ ] **Step 1: Failing tests** — most already exist and fire the moment `lastPaneID` moves:
  - `TestHelpPurpose_EveryPaneHasOne`, `TestHelpBody_EveryPaneSectionSpellsOutEveryDescription`, the footer-on-every-pane test, `TestSearch_SlashOpensOnEveryPane`, `TestAgentsPane_StartupLeavesAnOperatorWhoHasMoved` (a **zero-value** model must render and update on `paneAccess`).
  - New: `V` appears in the global keys with a description; no other pane binds `V`; `esc` from the pane returns to the pane it was opened from, including when that was `paneDetail`; scroll keys move the viewport; `/` searches the rendered lines.
  - **Help height:** adding a pane to the overlay lengthens it. `helpNoScrollHeight` is currently 117 and its own comment records that raising it makes every reader of every other pane scroll. Keep the new entry to one purpose line, three bindings and no note. If the budget test still demands a raise, **raise it by the smallest amount and say so in the commit message**; do not trim another pane's text to compensate.
- [ ] **Step 2–4:** Fail, implement, pass.
- [ ] **Step 5:** Commit: `feat(agentop): add the access pane to the viewer`.

---

### Task 6: Docs and a real run

**Files:**
- Modify: `cmd/agentop/README.md` (a `### Access` entry under Panes, `V` in the keybindings table), `docs/agentop-access.md` (the pane, and the sanitization note), the spec (phase 3 status)

- [ ] Build the binary and run the viewer against a real harvested session. Verify by eye, in a real terminal: the layer stack matches `agentop access --session <id>` line for line; `V` from sessions, events and detail all open it; `esc` returns; `r` picks up an edit to a settings file; a Kubernetes (`--kubernetes`) session shows "unavailable", not this machine's rules. **The sandbox blocks the TUI, so this step is the user's; list exactly what to check.**
- [ ] Full run of `./tui/ ./access/`, `gofmt -l`, `go vet ./...`.

## Out of scope

Matching a tool call to a rule, the `RULE` column and the detail-pane fold (phase 4); granted-vs-used and mid-session change detection (phase 5).

## Open questions

- **Key.** `V` is free (`$ A C G P S T X` are taken). It is a proposal; the only cost of changing it is `keys.go`, `help_overlay.go` and the tests that name it.
- **Auto-refresh.** The plan has none (open + `r`). A policy that changed under a live session is phase 5's detection; a timer here would hide that.
- **Harvest not yet run.** `sessionsData` fills from the file at startup and from a background harvest after. A session opened before the harvest reaches it shows "not harvested yet"; consider re-resolving when `sessionsData` changes. Decide after seeing it live.

# agentop Access Matching, Phase 4 (which rule applies to a tool call) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** For a tool call in a session, say which permission rule applies to it and what that rule does: `agentop access --session ID --explain 'Bash(git push origin main)'`, a `RULE` column on the events table, and an "Access" block on a tool-call event's detail. The answer is always a statement about *rules*; it never claims what Claude Code finally did.

**Architecture:** A pure matcher in `cmd/agentop/access` (`Policy.Match(call, ctx) Result`), split by tool family: Bash command text, file paths (Read/Edit), WebFetch domains, MCP/Agent/Skill names, and `Tool(param:value)` rules. Tool calls come from the session events already on screen (`Inference.ToolCalls`: name + JSON arguments), so no transcript is read. The TUI computes verdicts lazily from a policy it resolves once per session.

**Tech Stack:** Go 1.26.10, stdlib only in `access` (the matcher adds no dependency; gitignore-style globbing is implemented for the subset below, not imported).

**Spec:** `docs/superpowers/specs/2026-11-06-agentop-access-view-design.md` (§3).
**Builds on:** phases 1–3 (`91ab8d93` … `6183f4a1`).

## What a match is, and is not

Verified against code.claude.com/docs/en/permissions on 2026-11-06. Claude Code evaluates deny, then ask, then allow, first match wins. These also decide an outcome and are **not rules**, so the matcher cannot know them:

- the built-in **read-only command set** (`ls`, `cat`, `grep`, read-only `git`, … "not configurable") runs without a prompt in every mode;
- the **permission mode** (`acceptEdits` auto-accepts edits in the working directory; `dontAsk` auto-denies prompts; `bypassPermissions` skips them; `auto` runs a classifier);
- **hooks** (a blocking hook beats an allow rule; a hook "allow" never beats a deny or ask rule);
- the **sandbox** (`autoAllowBashIfSandboxed`), **workspace trust**, **symlinks**, **managed `allow*Only` locks**.

So the verdict vocabulary is deliberately small and honest:

| Verdict | Meaning |
|---|---|
| `deny` | a deny rule matches. Claude Code refuses the call; no hook or mode overrides a deny rule. |
| `ask` | an ask rule matches and no deny does. Claude Code prompts, even if an allow rule also matches. |
| `allow` | allow rules cover **the whole call** (every subcommand, for Bash) and no deny/ask matches. |
| `partial` | Bash only: some subcommands are covered by allow rules and others are not. The rest depend on the read-only set, the mode and the classifier. |
| `none` | no rule matches. The outcome depends on everything in the list above. **This is not "allowed" and not "prompts".** |
| `unknown` | a rule that could outrank the result cannot be evaluated here (unsupported pattern syntax, unparseable command). Never report a lower decision past an unevaluated higher one. |

## Global Constraints

- Work only in the worktree `.claude/worktrees/access-view`, branch `feat/agentop-access-view`.
- Every commit: `git commit -s` + `Assisted-By: Claude (Anthropic AI) <noreply@anthropic.com>`; never `Co-Authored-By`.
- `source agentop/.tools/env.sh`; `GOWORK=off` for `cmd/agentop`; sandbox off for module downloads and local ports. Run `gofmt -l`, `go vet ./...`. Run `./access/ ./tui/` and `-run` selections in `.`; the root package does not finish a full run here.
- Red-first, then **mutate the implementation once per rule and confirm a test fails** (phases 2 and 3 each found weak tests this way).
- **Fixtures come from the docs' own tables** (Bash wildcard table, "what a Bash rule doesn't match", WebFetch domains, path-anchor examples), quoted in the test with the doc section. There is no independent oracle: transcripts record a decision for 981 of 2,108 calls, name a rule for only 5, and record nothing for read-only commands.
- **Never guess.** Where the docs are silent or the syntax is outside the supported subset, return `unknown` with the rule named. A wrong confident answer is the worst outcome.
- The matcher is **pure**: no I/O, no environment. Tool arguments are untrusted JSON (size, depth, type); rule text is untrusted (a cloned repo).

## Review Focus

- **`deny`/`ask` apply to *any* Bash subcommand** (including inside `$(…)`, subshells and loop bodies); `allow` needs **every** subcommand. Test in Task 2.
- **An unevaluable higher-priority rule makes the answer `unknown`**, never a lower decision. Test in Task 1.
- **Anchors differ by rule source** (`/p` is cwd in project/local settings, the config dir in user settings). A user-settings rule must not match a project file. Test in Task 3.
- **Deny/ask single-segment directory rules match at any depth; allow rules do not.** Test in Task 3.
- **`Bash(command:…)` and `Read(file_path:…)` rules are ignored by Claude Code** and must not match. Test in Task 4.
- **Hostile input:** a 1 MB `command`, deeply nested `$(…)`, unbalanced quotes, a pattern with 10,000 `*`. The matcher is linear or bounded and never hangs. Test in Task 2/3.
- **The `RULE` cell and the detail block never print raw tool arguments or rule text** without `access.Clean`.

---

### Task 1: Matcher skeleton: result types, tool-name matching, ordering, unknown propagation

**Files:**
- Create: `cmd/agentop/access/match.go`, `cmd/agentop/access/match_names.go`
- Test: `cmd/agentop/access/match_test.go`

**Interfaces:**
- Produces: `type Call struct{ Tool string; Input map[string]any }`, `type MatchContext struct{ Cwd, Home, ConfigDir string }`, `type Verdict int` (`VerdictNone`, `VerdictDeny`, `VerdictAsk`, `VerdictAllow`, `VerdictPartial`, `VerdictUnknown`), `type Result struct{ Verdict Verdict; Rules []Rule; Unevaluated []Rule; Caveats []string }`, `func (p Policy) Match(c Call, ctx MatchContext) Result`, `func CallFromJSON(tool, args string) (Call, error)` (bounded decode).
- `Rules` are copies of the rules that decided the verdict; `Unevaluated` are the rules that could not be evaluated.

Tool-name rules (docs, "Match all uses of a tool", "Tool name wildcards", "MCP"):
- bare `Tool` matches every use; `Bash(*)` ≡ `Bash`; names are case-sensitive.
- deny/ask accept globs in the tool-name position (`*`, `mcp__*`); allow accepts a glob only after a literal `mcp__<server>__` prefix; an unanchored allow glob "is skipped".
- `mcp__server` matches any tool of that server (deny/ask); `mcp__server__*`; `mcp__server__tool`. A rule with parentheses on an `mcp__` tool is skipped by Claude Code.
- Tool equivalences: `Edit` rules apply to Write/NotebookEdit/MultiEdit calls; `Read(path)` rules apply to Grep/Glob calls; `Write(path)`, `Grep(path)`, `Glob(path)` rules with a path other than `*` **never match**; the bare tool names do. A `Read` deny also blocks Edit/Write on the same path.

- [ ] **Step 1: Failing tests:** each bullet above as a table row; plus ordering (deny beats ask beats allow across layers), `Ignored` rules skipped, and propagation: an unevaluable deny + a matching allow → `VerdictUnknown` with the deny in `Unevaluated`; an unevaluable *allow* + nothing else → `VerdictNone` with a caveat (it could only have *allowed*, so it cannot raise the answer).
- [ ] **Step 2:** `go test ./access/ -run Match` — FAIL (undefined).
- [ ] **Step 3:** Implement. One `evaluate(rule, call, ctx) (matched, evaluable bool, caveat string)` dispatching on tool family; Task 1 implements only name-level matching (bare rules) and returns `evaluable=false` for any specifier it does not yet handle, which is what makes later tasks additive.
- [ ] **Step 4:** pass; **mutate** (swap deny/ask order; drop the Unevaluated propagation; let an unanchored allow glob match) and confirm each fails.
- [ ] **Step 5:** Commit: `feat(agentop): match a tool call against rule tool names`.

---

### Task 2: Bash

**Files:**
- Create: `cmd/agentop/access/match_bash.go`, `cmd/agentop/access/shell.go`
- Test: `cmd/agentop/access/match_bash_test.go`, `cmd/agentop/access/shell_test.go`

Rules (docs, "Wildcard patterns", "Compound commands", "Wrappers", "What a Bash rule doesn't match"):
- `*` matches any text including spaces, anywhere. No `*` ⇒ exact command. A trailing ` *` also matches the bare command (`Bash(ls *)` matches `ls`, not `lsof`); `Bash(ls*)` matches `lsof`. `:*` ≡ trailing ` *`, only at the end of a pattern; elsewhere `:` is literal.
- Command separators `&&`, `||`, `;`, `|`, `|&`, `&`, newline, respecting quotes. **deny/ask match if any subcommand matches**, including inside `$(…)`, backticks, subshells `( … )` and control-flow bodies. **allow requires every subcommand** to match an allow rule.
- A trailing `&&`/`||` with nothing after it ⇒ unparseable: not split, so an allow rule does not approve it.
- Wrappers stripped before matching: `timeout`, `time`, `nice`, `nohup`, `stdbuf`, `command`, `builtin`, `noglob`, and flagless `xargs`. A leading env assignment is stripped for deny/ask (any variable) but **an allow rule matches past only "known-safe" variables, a list the docs do not give: treat a leading assignment as blocking allow-matching** (caveat).
- Not matched, by design: `/usr/bin/curl` against `Bash(curl *)`, `sh -c '…'`, `git -C . push`. The result carries the docs' caveat ("a Bash rule is not a security boundary") whenever a deny/ask rule did **not** match but the command mentions the denied program by another route (`sh -c`, a path, or a differing option order). Keep that detection narrow and tested.
- Over 10,000 characters ⇒ `unknown` (Claude Code always prompts and does not analyse it).

- [ ] **Step 1: Failing tests:**
  - the docs' wildcard table verbatim (`Bash(npm run build)`, `npm run *`, `git log * main`, `git * main`, `* --version`, `ls *` vs `lsof`, `ls*`, `* --help *`);
  - the "doesn't match" table verbatim (rule `Bash(curl *)` vs `/usr/bin/curl …`, `sh -c 'curl …'`; `Bash(git push *)` vs `git -C . push …`, `git -c … push`, `git 'push' origin main`);
  - compounds: `safe-cmd && other-cmd` against `Bash(safe-cmd *)` ⇒ `partial`; `cd /tmp && git clean -f` against ask `Bash(git clean *)` ⇒ `ask`; `echo "$(git clean -f)"` ⇒ `ask`; `for f in a b; do git clean -f; done` ⇒ `ask`; `npm test &&` ⇒ allow rule does **not** approve;
  - wrappers: `timeout 30 npm test` and `nohup npm test` against `Bash(npm test *)`; `FOO=bar rm -rf tmp/` against deny `Bash(rm *)` ⇒ `deny`, but the same command against an *allow* `Bash(rm *)` ⇒ not allowed; `xargs grep x` vs `xargs -n1 grep x`;
  - the shell splitter on its own: quotes, escapes, `$(…)` nesting, `\`…\``, heredoc-free input, unbalanced quote ⇒ unparseable (not a panic), 1 MB command, 10,000 nested `$(`, a rule with 10,000 `*` (bounded time).
- [ ] **Step 2–4:** fail, implement a small hand-written tokenizer (no regexp backtracking on user rule text: compile wildcard patterns to a linear matcher), pass; mutate (deny matches only the first subcommand; allow needs only one subcommand; strip assignments for allow; `lsof` matches `ls *`; unbalanced quote treated as split) and confirm each fails.
- [ ] **Step 5:** Commit: `feat(agentop): match Bash commands against permission rules`.

---

### Task 3: File paths (Read, Edit, Write, Grep, Glob, NotebookEdit)

**Files:**
- Create: `cmd/agentop/access/match_path.go`
- Test: `cmd/agentop/access/match_path_test.go`

Rules (docs, "Read and Edit", "How path patterns match"):
- Anchors: `//p` absolute; `~/p` home; `/p` anchors at the **settings source**: project/local ⇒ cwd, user ⇒ the config dir (`~/.claude`), `--settings` file ⇒ that file's directory, managed/session ⇒ cwd; `p` and `./p` ⇒ cwd.
- A rule only matches files **under its anchor**. gitignore syntax: `*` within a segment, `**` across directories, `?`; a bare filename (`.env`) matches at any depth under the anchor; a trailing `/**` matches everything beneath.
- A single-segment directory pattern (`secrets/**`) matches at **any depth for deny/ask** and **only at the anchor for allow**.
- A call's path is `file_path` / `path` / `notebook_path`; relative paths resolve against cwd. Paths are cleaned (`..`), never read from disk.
- **Unsupported ⇒ `unknown`:** `!` negation, `[…]` classes, backslash escapes. Say "symlinks are not resolved" as a caveat on every path match.
- `Write/Grep/Glob/NotebookEdit(path)` rules with a path other than `*` never match (Task 1's equivalences apply the Read/Edit rules instead).

- [ ] **Step 1: Failing tests:** the docs' two tables verbatim (`Read(.env)` vs `Read(**/.env)`; `Edit(src/**)` as allow/deny/ask vs `src/app.ts` and `vendor/pkg/src/lib.js`; `Edit(/src/**)`; `Edit(**/src/**)`); each anchor row by rule source (a user-settings `Read(/secrets/**)` matches `~/.claude/secrets/x` and **not** `<cwd>/secrets/x`); `//`, `~/`; outside-anchor file; `..` traversal; cwd unknown (empty) ⇒ relative and cwd-anchored rules are `unknown`, not guessed; `[`, `!`, `\` ⇒ unknown; a pattern of 10,000 `*` and a 100,000-character path in bounded time.
- [ ] **Step 2–4:** fail, implement a segment-wise glob with memoised `**` (linear in pattern × path segments), pass; mutate (allow matches at any depth; `/p` anchors at cwd for user rules; ignore the anchor bound) and confirm each fails.
- [ ] **Step 5:** Commit: `feat(agentop): match file paths against Read and Edit rules`.

---

### Task 4: WebFetch, MCP, Agent, Skill, `Tool(param:value)`

**Files:**
- Create: `cmd/agentop/access/match_web.go`, `cmd/agentop/access/match_params.go`
- Test: `cmd/agentop/access/match_web_test.go`, `cmd/agentop/access/match_params_test.go`

Rules (docs, "WebFetch", "MCP", "Agent", "Match by input parameter"):
- `WebFetch(domain:host)`: hostname of `url`, case-insensitive, one trailing `.` stripped from both; `domain:example.com` exact; `domain:*.example.com` any subdomain depth, **not** the apex; `domain:*` every domain; elsewhere `*` is exactly one label (`domain:example.*` matches `example.org`, not `example.evil.com`). Bare `WebFetch` ≠ `WebFetch(domain:*)` only for sandbox purposes: both match here.
- `Agent(Name)` ⇒ `subagent_type`; `Skill(name)` ⇒ `skill` exact (aliases not known: caveat).
- `Tool(param:value)`, **deny/ask only**: a direct top-level scalar field; `*` wildcard in the value; exact otherwise; compared with the literal input; an omitted parameter never matches; whitespace around `:` ignored. Allow rules of this form do nothing. `command`, `file_path`, `path`, `notebook_path`, `url` are **not matchable** this way and Claude Code ignores such a rule.
- A `Tool(x:y)` is a parameter rule only when `x` is a field of this call's input or a documented parameter of the tool (`Bash`: `run_in_background`, `dangerouslyDisableSandbox`, `timeout`; `Agent`: `model`, `isolation`, `subagent_type`, `run_in_background`); otherwise it is the tool's own specifier (`Bash(foo:bar)` is a command pattern).

- [ ] **Step 1–4:** tests from the docs tables (WebFetch rows, MCP name rows incl. `mcp__reports__v2__*`, the three parameter rows, the "primary field is not matchable" row), hostile URLs (`https://evil.com@good.com/`, userinfo, port, IDN, IPv6, no scheme, 1 MB), mutate (apex matched by `*.`; `example.*` crossing dots; param rule on allow; omitted param matches; `command:` honoured).
- [ ] **Step 5:** Commit: `feat(agentop): match WebFetch, MCP, subagent and parameter rules`.

---

### Task 5: `agentop access --explain`

**Files:**
- Modify: `cmd/agentop/cmd_access.go`
- Test: `cmd/agentop/cmd_access_test.go`

- [ ] `--explain 'Tool(content)'` takes the same syntax as a rule (`Bash(git push origin main)`, `Read(./.env)`, `WebFetch(domain:example.com)` meaning a fetch of `https://example.com/`), builds a `Call` from the primary content field, and prints the verdict, the deciding rule with its file and layer, the unevaluated rules, and the caveats. Works with `--cwd` or `--session`; `--json` includes `match`.
- [ ] Tests: each verdict end to end through `runAccess`; a malformed `--explain` is exit 2 with usage; with `--session` the cwd/config dir come from the session; the output never contains raw control bytes from the call text.
- [ ] Commit: `feat(agentop): explain which rule applies to a tool call`.

---

### Task 6: The `RULE` column and the detail block

**Files:**
- Create: `cmd/agentop/tui/access_rule_col.go`
- Modify: `cmd/agentop/tui/events_columns.go` (`colRule`, **off by default**), `cmd/agentop/tui/app.go` (`Update` wrapper, model fields), `cmd/agentop/tui/detail_pane.go` (the block), `cmd/agentop/tui/help_overlay.go`
- Test: `cmd/agentop/tui/access_rule_col_test.go`

- [ ] A response event's `Inference.ToolCalls` are the calls; the cell shows the strongest verdict among them (`deny` > `ask` > `unknown` > `partial` > `allow` > `none`) and a count when more than one (`ask ×2`); non-tool rows are blank; a target that cannot resolve shows `n/a`. Verdicts are cached per (session, seq, policy generation); a cell function does no I/O and no resolution.
- [ ] The session's policy is resolved once when the column is on and a session is open (`ensureRulePolicy`, run after every `Update`, keyed by session, with the same request-number discipline as the pane), and again on `r` in the access pane.
- [ ] The detail block lists each call: tool, the primary argument (cleaned and clipped), verdict, deciding rule + layer + file, caveats. Shown only for events with tool calls and only when a policy is available.
- [ ] Tests: every pane invariant still holds (column picker lists it with a description, off by default, `TestEventColumns*`); cell for each verdict; blank for non-tool rows; `n/a` for a remote session; no resolver call from a cell function; the cache is invalidated when the policy changes; a 5,000-row table renders within a bound; hostile tool arguments never reach the screen raw.
- [ ] Commit: `feat(agentop): show the applicable rule in the events table and detail`.

---

### Task 7: Validate against real data, docs, wrap up

- [ ] **One-off validation (not committed):** run the matcher over every tool call in the local transcripts against the real settings and report: how many calls get each verdict; every `deny` or `ask` verdict checked against that call's recorded decision (a `deny`/`ask` match whose recorded decision is `accept/config` is a bug in the matcher or a mode/hook effect and must be explained); the 5 `bashMiss:no-rule-match` records must come out `none` or `partial`. State the result, including that this is a sanity check and not a proof.
- [ ] `docs/agentop-access.md`, `cmd/agentop/README.md` (the RULE column, `--explain`, the verdict table and "what a match is not"), spec status.
- [ ] `gofmt`, `go vet ./...`, `go test -race ./access/ ./tui/` and the `-run` selections in `.`.

## Out of scope

Recorded-decision display (granted vs used), policy-change detection, other agents (phase 5). Read/Edit rules applied to files named inside Bash commands (`cat`, `sed`, redirections) are not evaluated; the result says so when such rules exist.

## Open questions

- Whether `deny` rules still apply in `bypassPermissions` mode is not stated plainly in the page read; the result says "a deny rule matches", not "blocked", and the mode is shown beside it.
- The list of "known-safe" environment variables an allow rule may match past is not documented, so allow-matching refuses any leading assignment.
- Symlink resolution needs a filesystem the matcher does not have; it is reported as a caveat.

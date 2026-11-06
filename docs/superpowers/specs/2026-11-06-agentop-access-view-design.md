# agentop Access view — design

Date: 2026-11-06
Issue: (to be filed)
Branch: `feat/agentop-access-view` (worktree `.claude/worktrees/access-view`)
Target: `cmd/agentop`, plus `core/` where noted

## Problem

agentop shows what Cortex did to each event (the ACTION column: `allow`,
`deny`, `modify`, `observe`, `skip`, plus the rendered `—` and `tunnel`) and
which plugin acted. It does not show what the *agent itself* is configured to
be allowed to do: Claude Code's permission mode, allow/ask/deny rules,
sandbox, hooks, extra directories. So an operator looking at a session can see
that a tool call happened, but not whether it was pre-approved, prompted for,
or what rule decided it.

Two different things are being conflated by the absence:

- **Enforced at runtime** (Cortex pipeline): already in the session API, in
  `invocations[].action` / `reason` per event.
- **Configured in the agent** (Claude Code settings files): not in proxy
  traffic at all. Only readable from disk, and only meaningful once the
  session's working directory is known.

## Goals

- For a selected Claude Code session, show the **effective permission policy**:
  the merged allow/ask/deny rules, mode, sandbox, hooks and extra directories,
  each with the file it came from.
- Show **which layer decided** each scalar (mode, sandbox) and **which rules are
  shadowed** by a higher-priority one.
- On the events table, show whether a tool call matches a deny/ask/allow rule,
  next to the existing ACTION column.
- Flag risky grants (`bypassPermissions`, `Bash(*)`, sandbox off, wide
  `additionalDirectories`).
- The resolver is a **pure function** with no TUI or network dependency, so it
  is testable on its own and reusable from a CLI.

## Non-goals

- **Editing** permissions. The view is read-only.
- **Enforcing** anything. Cortex plugins enforce; this view explains.
- Agents other than Claude Code in v1 (Bob, Codex, opencode, Pi have different
  models). The resolver interface must not preclude them.
- Reconstructing the policy *as it was* at session start. v1 resolves from the
  files as they are now and says so (see Open questions).
- Predicting Claude Code's decision for an arbitrary call with certainty — the
  match is an approximation (see Risks).

## Facts established from the code (as of main `c24e5e27`)

- The session API does **not** expose a session's working directory or
  permission mode (`docs/session-api.md` has neither).
- The only place agentop learns a cwd is the Claude Code transcript harvest
  (`core/observe/claude/harvest.go`), and there it is used as a **title
  fallback**: normalized, clipped to `MaxCwdLen` (1024 runes, tail kept) and
  stored in `SessionMetadata.Title`. It is not stored as its own field.
- `SessionMetadata` already records `AgentConfigDir` per entry, so the
  config dir the transcript came from is known.
- Key `A` (agents pane) and `X` are already bound. Free capitals must be
  confirmed against `tui/keys.go` before choosing one.
- Per-event action vocabulary and the ACTION column live in
  `docs/session-api.md` and `tui/events_columns.go` (`colAction`).

## Design

### 1. Session context: cwd (and optionally mode)

The resolver needs `cwd`. Add a dedicated field to the harvested metadata
rather than parsing it back out of `Title`:

- `claude.SessionMetadata` gains `Cwd string` (`json:"cwd,omitempty"`), set in
  the harvester from the same transcript field it already reads, **unclipped
  title-style normalization is not applied** — only a sane cap and the same
  control-character stripping, since this is a path used for file lookups.
- The harvester may also record the session's permission mode if the transcript
  carries it (to be verified; see Open questions). If not, mode comes from the
  resolved settings.

No session-API change in v1. Sessions with no harvested `cwd` (non-Claude
agents, remote/Kubernetes sessions, harvest skipped via
`-skip-claude-metadata`) show the **user and managed layers only**, with an
explicit "project layers unavailable: no working directory for this session".

### 2. Resolver (new package)

New package `cmd/agentop/access` (peer of `toolscan/`, `money/`; no imports
from `tui/`).

```go
type Input struct {
    Cwd       string
    ConfigDir string   // AgentConfigDir; "" => ~/.claude
    Flags     Flags    // optional CLI-flag overrides, usually zero in v1
    FS        fs.FS    // injected for tests; real FS in production
    GOOS      string   // selects the managed-settings path
}

type Policy struct {
    Layers  []Layer          // highest precedence first
    Mode    Scalar[string]   // value + deciding Layer
    Sandbox Scalar[bool]
    Rules   []Rule           // merged, ordered deny, ask, allow
    Dirs    []Sourced[string]
    Hooks   []Sourced[Hook]
    Flags   []RiskFlag
}

type Layer struct {
    Kind    LayerKind  // Managed, CLI, Local, Project, User
    Path    string
    Present bool
    Err     error      // unreadable or malformed; layer is reported, not fatal
    Counts  Counts     // allow/ask/deny
}

type Rule struct {
    Decision  Decision   // Deny, Ask, Allow
    Tool      string     // "Bash", "Read", "mcp__srv__tool"
    Pattern   string     // raw pattern text
    Source    LayerKind
    ShadowedBy *Rule     // non-nil when a higher decision for the same match wins
}

func Resolve(in Input) (Policy, error)
```

Resolution rules (to be confirmed against current Claude Code docs — see
Risks):

- Layer order, highest first: managed (`/Library/Application
  Support/ClaudeCode/managed-settings.json` plus `managed-settings.d/*.json` on
  macOS; platform paths for Linux), CLI flags, `<cwd>/.claude/settings.local.json`,
  `<cwd>/.claude/settings.json`, `<ConfigDir>/settings.json`.
- Rule lists (`permissions.allow|ask|deny`, `additionalDirectories`) **merge**
  across layers. Among merged rules, deny beats ask beats allow regardless of
  layer.
- Scalars (`permissions.defaultMode`, sandbox enabled) take the highest layer
  that sets them. Managed values are not overridable.
- A missing file is `Present: false`, not an error. A malformed file sets
  `Layer.Err` and contributes nothing; the rest still resolves.
- Read-only: never writes, never follows a path outside the named files.

Risk flags are computed in the resolver: `bypassPermissions`, an allow rule
whose pattern is `*` or whose tool is bare (`Bash`), `sandbox` off, an
`additionalDirectories` entry that is `/` or `$HOME`, and a deny that a lower
layer's allow can never override (informational).

### 3. Matching a tool call to rules

```go
func (p Policy) Match(call ToolCall) MatchResult   // winning rule + all matched
```

`ToolCall{Tool, Input}` is derived from the event's parsed tool-use block (the
existing parsed tool calls shown in the detail pane). Matching implements the
documented rule syntax: tool name, `Tool(prefix:*)` / glob forms, `mcp__`
prefixes, `domain:` for WebFetch. Anything it cannot parse returns
`Unmatched`, never a guess. The UI labels results as **"matched rule"**, not
"decision", because hooks, sandbox, and mode can still change the outcome.

### 4. TUI

Reuse existing structures; add, don't restructure.

- **New pane `paneAccess`**, opened from a key chosen after checking
  `keys.go` for conflicts (proposal: `V`, "view policy"; `A` and `X` are taken).
  Opens on the selected session, like `T` does for the timeline. Added to
  `help_overlay.go` with a one-line description.
- **Layout, top to bottom:** header (session, agent, cwd) → layer stack (five
  rows: kind, path, present, allow/ask/deny counts) → scalars line (mode,
  sandbox, hooks, with deciding layer) → rules table (decision, tool, pattern,
  source, shadow marker) → risk strip.
- **Rules table** reuses the table component and search used by the events pane;
  sort by decision then specificity; shadowed rows dimmed with "overridden by
  <layer>".
- **Events table:** a new optional column `colRule` (`RULE`), off by default,
  showing `deny|ask|allow` plus source initial for the matched rule of that
  event's tool call, blank for non-tool events. Added through `eventColumn`
  like `colAction`, so the column picker, sizing and search already work.
- **Detail pane:** for a tool-call event, an "Access" fold listing every
  matched rule, the winner and why (the "explain this call" view).
- **Degraded states** are explicit text, never a blank pane: no cwd, non-Claude
  agent, unreadable layer, remote session.

### 5. CLI

`agentop access [--session ID | --cwd PATH] [--json]` prints the same `Policy`
as text or JSON. This is the same resolver, gives scripts and tests a handle,
and makes the pane debuggable without the TUI.

### 6. Data flow

```
transcript harvest ──► SessionMetadata.Cwd ─┐
settings files (5 layers) ───────────────────┼─► access.Resolve ─► Policy ─┬─► paneAccess
session API events (tool calls, ACTION) ─────┴─► Policy.Match ───────────┬─┴─► RULE column, detail fold
                                                                          └─► agentop access (CLI)
```

## Phasing

Each phase is independently shippable.

1. **Resolver + CLI.** `cmd/agentop/access`, `agentop access --cwd`, golden
   tests over fixture settings trees. No TUI change. Proves the hierarchy logic.
2. **Harvest `Cwd`** field and `--session` lookup. Degraded-state text.
3. **`paneAccess`:** layer stack, scalars, rules table, risk strip.
4. **Matching:** `Policy.Match`, `RULE` column, detail-pane fold.
5. **Later:** granted-vs-used report, policy-change detection mid-session,
   other agents.

(The earlier deck's "badges first" ordering is dropped: the ACTION column
already shows Cortex outcomes, so the real first deliverable is the resolver.)

## Testing

- **Resolver:** table-driven tests on an in-memory `fs.FS`. Cases: each layer
  alone; all five; deny-in-user vs allow-in-local; managed scalar not
  overridable; malformed JSON in one layer; missing `.claude/`; symlinked
  config dir; managed drop-in ordering; `CLAUDE_CONFIG_DIR` set.
- **Matcher:** fixtures for `Bash(git push:*)`, `Bash(npm run *)`,
  `Read(./.env)`, `mcp__server__tool`, `WebFetch(domain:x.com)`, unparsable
  pattern → `Unmatched`.
- **TUI:** follow the existing `*_test.go` patterns in `cmd/agentop/tui`
  (`detail_pane_test.go`, `events_columns_test.go`): column selection, degraded
  states, key binding conflicts (a test asserting the chosen key is unique).
- **Characterization of external format:** one test that reads a checked-in
  sample of each settings shape, so a Claude Code format change shows up as a
  visible diff.
- **Harvest:** extend `core/observe/claude` tests for the new `Cwd` field,
  including a 20,000-rune value and control characters (the existing title
  path already has such a regression test).

## Risks and open questions

- **The precedence and match rules are my reading of Claude Code's docs, not
  something verified against its source.** Phase 1 must start by re-reading
  the current permissions and settings docs and fixing the rules above. The
  matcher is the most likely place to be subtly wrong; hence "matched rule"
  wording and `Unmatched` over guessing.
- **Policy at session start is unknowable.** Files can change mid-session and
  "always allow" clicks write to `settings.local.json`. v1 resolves current
  files and labels the view "as of now". Snapshot-and-diff is phase 5.
- **Remote / Kubernetes sessions:** the files are on another machine. v1 shows
  "unavailable"; do not read local files for a remote session — that would show
  the wrong policy confidently.
- **Does the transcript carry permission mode?** If yes, record it; if not,
  mode shown is the configured default only. To check in phase 2.
- **Key choice:** `V` is a proposal; confirm free.
- **Privacy:** settings files can contain secrets in `env` blocks. The pane
  must show only `permissions`, `sandbox`, `hooks` (command names), and
  directories — never `env` values. Add a test.
- **Another agent's settings path** (Bob, Codex) differs; the resolver takes
  the layer list as data so a second implementation can reuse the types.

## Out of scope for the first PR

Phases 3–5. Phase 1 alone is a reviewable, testable PR and unblocks the rest.

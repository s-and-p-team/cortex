# `agentop access` — the Claude Code permission policy for a directory

`agentop access` prints what Claude Code is configured to allow, ask about and
deny in a working directory, and which settings file each rule came from. It
answers "why was this call allowed, or refused?" without opening the viewer.

```sh
agentop access                  # the current directory
agentop access --cwd ~/src/app  # another directory
agentop access --session 0834b33b  # a Claude Code session: its id or a unique prefix
agentop access --json           # the same, for scripts
```

Flags: `--cwd`, `--session`, `--config-dir` (default `$CLAUDE_CONFIG_DIR`, else
`~/.claude`), `--settings` (the `--settings` value a session was started with: a path
or inline JSON), `--json`.

## For a session

`--session` looks the session up in `~/.cortex/session-metadata.json`, which
`agentop observe` and `agentop experimental read-claude-sessions` fill from Claude
Code's transcripts, and resolves the policy from what the transcript recorded:

- **The directory the session started in.** Not the last one: a transcript's cwd
  follows a `cd` in a Bash command, while Claude Code reads project settings from the
  starting directory. A session that used `/cd` is still reported at its start.
- **The config directory** the transcript was read from, so a relocated
  `CLAUDE_CONFIG_DIR` is honoured.
- **The permission mode it was last recorded in**, shown on its own `session` line
  beside the configured `mode`. They differ whenever a mode was chosen at launch or
  switched with Shift+Tab. A session that ended in `bypassPermissions` is flagged
  even when no settings file configures it.

A prefix that matches several sessions lists them instead of guessing. A session with
no recorded directory still shows the user and managed layers and says the project
ones are missing; it never falls back to the directory you ran the command in.
`--session` cannot be combined with `--cwd`; `--config-dir` overrides the recorded
one. Sessions run by another agent are refused.

An entry harvested before these fields existed is re-read once, automatically, the
next time the harvest runs.

## What it shows

- **Layers**, highest precedence first: managed, `--settings`, project local
  (`.claude/settings.local.json`), shared project (`.claude/settings.json`), user.
  Each is listed with its path and whether it exists, even when absent.
- **Settings**: the default mode and `sandbox.enabled`, each with the layer that
  decided it; additional directories; hook events (names only).
- **Rules** in the order Claude Code checks them: deny, then ask, then allow. The
  first match wins, regardless of layer or specificity. A rule that another rule
  makes unreachable says `shadowed by …`.
- **Flags**: `bypassPermissions` as the default mode, an unrestricted allow of
  `Bash`, `Write`, `Edit` or `WebFetch`, the sandbox off, a directory grant of `/`
  or the home directory, managed settings that leave bypass mode open, and a
  settings file that cannot be parsed.

## How the layers combine

Rule lists (`allow`, `ask`, `deny`, `additionalDirectories`) merge across layers,
so a user-level deny blocks a project-level allow. Scalars take the highest layer
that sets them. Three exceptions the output reports rather than hides:

- A `defaultMode` of `auto` or `bypassPermissions` does not take effect from
  project or local settings. It is listed under `ignored`, not shown as the mode.
- With `allowManagedPermissionRulesOnly` in managed settings, rules from every
  other layer are marked `ignored`.
- Project `allow` rules and `additionalDirectories` apply only after the folder
  is trusted. They are marked `applies only after workspace trust`.

The local file lives at the git repository root when a session starts in a
subdirectory (Claude Code v2.1.211 and later); a copy left in the starting
directory by an older version is read too, and rules from both apply.

## What it cannot see

- **It reads the files as they are now**, not as they were when a session
  started. A rule added with "Yes, and don't ask again" shows up at once.
- **Managed policy delivered by MDM, the registry or the claude.ai console** is
  not a file. Only `managed-settings.json` and `managed-settings.d/` are read, and
  the managed layer says so.
- **Launch flags other than `--settings`** (`--allowedTools`, `--add-dir`) are not on
  disk. The mode a session ran in is recovered from its transcript; the rest are not.
- **Workspace trust** is not in any settings file.
- **Remote sessions.** The command reads this machine's files. A session that ran in
  a cluster has no entry here, and a local session whose directory has since been
  deleted is noted as such.

Without `--explain` the output says which rules exist and which shadow each other. With it,
which of them applies to one call.

## Secrets

Only `permissions`, `sandbox.enabled` and the names of hook events are read from a
settings file. Everything else, including the `env` block and hook commands, is
dropped when the file is decoded, so it cannot appear in either output form. A test
asserts this.

## JSON

`--json` emits `layers`, `mode`, `sandbox`, `rules`, `dirs`, `hooks`, `ignored` and
`flags`, plus `sessionMode` and `notes` (which session the answer is for). Names are strings (`"decision": "deny"`, `"source": "user"`), empty lists
are `[]` and never `null`, and the output is byte-identical across runs for the same
files: rules are ordered by decision, tool, pattern and layer. A shadowed rule
carries `shadowedBy` with the decision, text and layer of the rule that shadows it.

## Which rule applies to a tool call

`--explain` takes a call written the way a rule is and says which rule applies:

```sh
agentop access --explain 'Bash(git push origin main)'
agentop access --session 0834b33b --explain 'Read(./.env)'
agentop access --explain 'WebFetch(domain:example.com)' --json
```

The answer is one of six verdicts, and it is a statement about **rules**, not about what
happened:

| Verdict | Meaning |
|---|---|
| `deny` | a deny rule matches. Claude Code refuses the call; no hook or mode lifts a deny rule. |
| `ask` | an ask rule matches and no deny does. Claude Code prompts, even if an allow rule also matches. |
| `allow` | allow rules cover the whole call (every subcommand, for Bash) and no deny or ask matches. |
| `partial` | Bash only: some subcommands are covered by allow rules and some are not. |
| `none` | no rule matches. **This is not "allowed" and not "prompts".** |
| `unknown` | a rule that could outrank the result cannot be evaluated here, so no lower decision is reported past it. |

`none` is the one to read twice. The built-in read-only command set (`ls`, `cat`, read-only
`git`, ...), the permission mode, the auto-mode classifier, hooks and the sandbox decide what
happens when no rule matches, and none of them is a rule. The deciding rule is shown with the
layer and file it came from, and every condition on the answer is listed as a `NOTE`.

What is matched, following the permissions docs: tool names and globs, `mcp__server__tool`,
Bash command text split into subcommands (compounds, `$( )`, subshells, loops, wrappers such as
`timeout` and `nohup`, leading assignments), Read and Edit paths with the four anchors, WebFetch
domains, `Agent(name)`, `Skill(name)`, and `Tool(param:value)` rules.

**Files named inside a Bash command.** Claude Code applies `Read(...)` and `Edit(...)` deny and
ask rules to the files that file commands name inside Bash (`cat`, `head`, `sed`, `tee`, ...) and
to redirection targets. It does not list which commands count, and a recorded session shows
`grep` does: two commands were refused by `Read(.env)` and `Read(.env.*)` that a rule-by-rule
reading calls unmatched. So any literal word of a Bash command, and any redirection target, is
treated as a possible file. When a Read or Edit deny or ask rule covers one, the verdict is
`unknown`, with the rule listed, and not `none`. The cost is a few `unknown`s for commands that
merely mention a guarded name (`echo .env`); the alternative is calling a refused command
"no rule matches". Words built from `$VAR`, globs or substitutions are not expanded, and the
note says so.

What it will not guess at: `!` negation, `[...]` classes and backslash escapes in path
patterns; a command it cannot split (unterminated quote, dangling `&&`, over 10,000
characters); symlinks; a Skill's aliases; and the `/path` anchor of a `--settings` file. Each
makes the rule `unknown` or adds a note rather than a wrong answer.

## In the viewer

`V` opens the same answer in `agentop observe`, over the selected session. It is drawn
as scrolling lines rather than a table so a shadowed rule can be dimmed. The pane
shows nothing, and says why, for a session on another machine (including a
port-forward to a pod), one the harvest has not read yet, or one another agent ran.
A session with no recorded directory shows the user and managed layers only. See the
`Access` entry in [`cmd/agentop/README.md`](../cmd/agentop/README.md).

### The RULE column and the ACCESS block

In the events pane, the column picker (`c`) offers a **RULE** column, off by default. For a
response in which the model asked for tools it shows the strongest verdict among the calls, with
a count (`deny`, `ask ×2`). It is blank on every other row, `…` while the calls are being
fetched, and `n/a` for a session whose policy cannot be shown here.

The events list is fetched without message bodies (`view=summary`), which drops the tool calls.
So the column fetches each tool-call *response* in full, four at a time, only while it is on. A
response is small (median 433 bytes, 95th percentile 3.9 KB across 2,219 real tool-call turns),
and the detail pane already makes the same request per row. Opening the detail of such a
response shows an **ACCESS** block: each call, the rule that applies, and the notes.

Design: [`superpowers/specs/2026-11-06-agentop-access-view-design.md`](superpowers/specs/2026-11-06-agentop-access-view-design.md).

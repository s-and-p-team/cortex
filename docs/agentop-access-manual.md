# agentop access — user manual

How to build the access-control features, run them, and see each one.

**What they do.** For a Claude Code session or a directory, agentop shows what the agent is
configured to be allowed to do: the permission rules from every settings file, merged, with the
file each came from. It can also say which rule applies to one specific tool call.

**What they do not do.** They read settings files. They do not change a setting, block anything,
or watch a live session's decisions. The answer is about *rules*, not about what happened (see
[Reading a verdict](#reading-a-verdict)).

Contents: [Install](#install) · [Quick start](#quick-start) · [Features](#features) ·
[Reading a verdict](#reading-a-verdict) · [Limits](#what-it-cannot-see) · [Troubleshooting](#troubleshooting)

---

## Install

You need Go 1.26 (the repo's `go.mod` says 1.26.10) and a checkout of the `cortex` repo on the
branch `feat/agentop-access-view`.

```sh
cd <your cortex checkout>/cmd/agentop
GOWORK=off go build -o ~/agentop-dev .
```

That produces one binary, `~/agentop-dev`. Use it by that name; your installed `agentop` is
untouched.

> **Do not** run `make dev-install`, `agentop setup --restart` or `agentop service restart` to
> try this. Per the repo's `CLAUDE.md` they replace the one running Cortex proxy and cut every
> session attached to it. The `go build` above affects nothing that is running.

Check it:

```sh
~/agentop-dev --version          # agentop dev
~/agentop-dev access --help      # the access command's usage
```

### What needs Cortex running

| Feature | Needs the Cortex proxy running? |
|---|---|
| `agentop access` and `--explain` (a directory) | No |
| `agentop access --session` | No, but needs the session metadata file (below) |
| The viewer: `V` pane, RULE column, ACCESS block | **Yes**: `agentop observe` reads the session API on `127.0.0.1:47601` |

### One-time step for sessions

`--session` and the viewer's `V` pane find a session's directory in
`~/.cortex/session-metadata.json`. A file written by an older agentop has no directories, so
refresh it once:

```sh
~/agentop-dev experimental read-claude-sessions --merge
```

This reads Claude Code's transcripts under `~/.claude/projects/` and rewrites
`~/.cortex/session-metadata.json`. That file is a cache. The new fields are optional, so older
agentop versions keep reading it. `agentop observe` also does this by itself in the background.

---

## Quick start

```sh
cd ~/some/project
~/agentop-dev access                                        # the policy for this directory
~/agentop-dev access --explain 'Bash(git push origin main)' # which rule applies to a call
~/agentop-dev observe                                       # the viewer, then press V
```

---

## Features

### 1. The policy for a directory — `agentop access`

```sh
~/agentop-dev access                       # the current directory
~/agentop-dev access --cwd ~/Work/Claude   # another directory
~/agentop-dev access --json                # the same, for scripts
```

Example (a project with a shared settings file, and a user file):

```
LAYERS (highest precedence first)
  managed /Library/Application Support/ClaudeCode/managed-settings.json  absent
            file sources only; MDM and console-delivered policy cannot be read
  cli     -  absent
            only --settings is modelled; other flags are not recoverable from disk
  local   /tmp/demo/proj/.claude/settings.local.json  absent
  project /tmp/demo/proj/.claude/settings.json  present  allow 1 / ask 1 / deny 0
  user    /tmp/demo/home/.claude/settings.json  present  allow 2 / ask 0 / deny 2

SETTINGS
  mode     not set in any layer (Claude Code's built-in default applies)
  sandbox  on (user)

RULES (checked deny, then ask, then allow; first match wins)
  deny  Bash(rm *)                         user
  deny  Read(./.env)                       user
  ask   Bash(git push *)                   project
  allow Bash(git status)                   project  (applies only after workspace trust)
  allow Bash(git status)                   user
  allow Bash(npm test *)                   user
```

How to read it:

- **Layers** are listed highest precedence first: managed, `--settings`, project local
  (`.claude/settings.local.json`), shared project (`.claude/settings.json`), user. Every layer is
  shown even when absent, with its path and how many rules it adds. A file that fails to parse
  shows its error and contributes nothing.
- **Rules** are in the order Claude Code checks them: deny, then ask, then allow; the first match
  wins, whatever layer it came from. A rule that another rule makes unreachable says
  `shadowed by …`; one Claude Code disregards says why; a project `allow` says
  `applies only after workspace trust`.
- **Settings** show the configured mode and the sandbox, each with the layer that decided it.
- A **FLAGS** section appears when something deserves a second look: `bypassPermissions`, an
  unrestricted allow of `Bash`, `Write`, `Edit` or `WebFetch`, the sandbox off, a directory grant
  of `/` or your home, managed settings that leave bypass mode open, or an unreadable file.

Where the files are read from:

| Layer | File |
|---|---|
| managed | macOS `/Library/Application Support/ClaudeCode/managed-settings.json` and `managed-settings.d/*.json`; Linux `/etc/claude-code/` |
| `--settings` | the value you pass with `--settings` (a path or inline JSON) |
| project local | `.claude/settings.local.json`, at the **git repository root** when you are in a subdirectory |
| shared project | `.claude/settings.json` in the directory itself |
| user | `settings.json` in `$CLAUDE_CONFIG_DIR`, else `~/.claude` |

Flags: `--cwd PATH`, `--session ID`, `--explain 'Tool(content)'`, `--config-dir DIR`,
`--settings VALUE`, `--json`.

### 2. The policy for a session — `agentop access --session`

```sh
~/agentop-dev access --session 0834b33b          # an id, or a unique prefix of one
```

Same output as above, resolved for the directory the session **started** in and the config
directory its transcript came from, with the session named at the top:

```
session 0834b33b-… (Greeting to Oleg) started in /Users/omerb/Work/Claude/agentop
```

and one extra line under SETTINGS:

```
  mode     not set in any layer (Claude Code's built-in default applies)
  session  auto (the mode recorded for this session; "mode" above is the configured default for new ones)
```

The two modes differ whenever a mode was chosen at launch or switched with Shift+Tab. A session
that ended in `bypassPermissions` gets a high-severity flag even when no settings file sets it.

Things to know:

- A prefix that matches several sessions **lists them** instead of guessing.
- A session with **no recorded directory** shows the user and managed layers and says the project
  ones are missing. It never falls back to the directory you ran the command in.
- A session another agent ran (Codex, Bob, …) is refused: only Claude Code's settings model is
  understood.
- `--session` cannot be combined with `--cwd`; `--config-dir` overrides the recorded one.
- If the session's directory has since been deleted, the output says so.

### 3. Which rule applies to a call — `--explain`

Write the call the way a rule is written:

```sh
~/agentop-dev access --explain 'Bash(git push origin main)'
~/agentop-dev access --explain 'Read(./.env)'
~/agentop-dev access --explain 'WebFetch(domain:example.com)'
~/agentop-dev access --session 0834b33b --explain 'Bash(rm -rf build)'
~/agentop-dev access --explain 'Bash(ls)' --json      # adds a "match" object
```

Real output, against the example policy above:

```
$ agentop access --explain 'Bash(git push origin main)'
CALL     Bash(git push origin main)
VERDICT  ask
         an ask rule matches and no deny rule does. Claude Code prompts, even when an allow rule also matches.
RULE     ask Bash(git push *)  (project settings: /tmp/demo/proj/.claude/settings.json)

$ agentop access --explain 'Bash(rm -rf build)'
CALL     Bash(rm -rf build)
VERDICT  deny
         a deny rule matches. Claude Code refuses the call; no hook or mode lifts a deny rule.
RULE     deny Bash(rm *)  (user settings: /tmp/demo/home/.claude/settings.json)

$ agentop access --explain 'Bash(git status && ls)'
CALL     Bash(git status && ls)
VERDICT  partial
         some subcommands are covered by allow rules and some are not (see below).
RULE     allow Bash(git status)  (project settings: …)
RULE     allow Bash(git status)  (user settings: …)
NOTE     1 of 2 subcommands are covered by allow rules; not covered: "ls". Whether those run is
         decided by the read-only command set, the permission mode and the classifier, none of
         which are rules

$ agentop access --explain 'Bash(ls -la)'
CALL     Bash(ls -la)
VERDICT  none
         no rule matches. That is not "allowed" and not "prompts": the built-in read-only command set,
         the permission mode, the classifier, hooks and the sandbox decide it, and none of them is a rule.

$ agentop access --explain 'Read(./.env)'
CALL     Read(./.env)
VERDICT  deny
         a deny rule matches. Claude Code refuses the call; no hook or mode lifts a deny rule.
RULE     deny Read(./.env)  (user settings: /tmp/demo/home/.claude/settings.json)
NOTE     symlinks are not resolved: Claude Code also checks the file a symlink points to, which this
         view cannot see
```

What you can ask about:

| You write | It is matched as |
|---|---|
| `Bash(command)` / `PowerShell(command)` | a shell command, split into subcommands |
| `Read(path)`, `Edit(path)`, `Write(path)`, `MultiEdit(path)` | a file path |
| `NotebookEdit(path)`, `Grep(path)`, `Glob(path)` | a file path |
| `WebFetch(https://…)` or `WebFetch(domain:host)` | a URL's hostname |
| `Agent(name)`, `Skill(name)` | a subagent type, a skill name |
| `Tool` (no parentheses) | any call to that tool |

A malformed `--explain` (empty, an unclosed parenthesis, a name that is not a tool, more than
12,000 characters, or a tool whose argument this view cannot name such as `mcp__srv__tool(x)`)
exits with status 2 and the usage.

### 4. The viewer — `agentop observe`

Needs the Cortex proxy running. Start it, then:

```sh
~/agentop-dev observe
```

#### The Access pane — press `V`

On the **sessions** list (the highlighted row), the **events** list or an event's **detail**,
press **`V`**. The pane shows, as scrolling lines:

- the five settings layers, each with its path and rule counts;
- the configured mode and the mode this session was recorded in;
- the sandbox, hook events and extra directories;
- risk flags, worst first;
- every rule in evaluation order, with the layer it came from; shadowed rules are dimmed and say
  what shadows them.

Keys in the pane:

| Key | Does |
|---|---|
| `↑` `↓` `j` `k`, page keys | scroll |
| `g` / `G` | top / bottom |
| `/` | search the lines (then `n` / `N`) |
| `r` | read the settings files again |
| `esc` (or `←`, `h`) | back to where you pressed `V` |
| `?` | the key help, which lists `V` in its jump section |

`V` does nothing inside the pane itself; `esc` first if you want to open it for another session.

The pane never shows a policy it cannot stand behind. It says why, in words, and shows nothing, for:

| Case | Why |
|---|---|
| a session on another machine, including a port-forward to a pod (`--kubernetes`) | its settings files are not here; this machine's would be the wrong answer |
| a session the harvest has not read yet | `r` checks again once it has |
| a session another agent ran | only Claude Code's settings model is understood |
| a session with no recorded directory | the user and managed layers are shown, and the project ones are said to be missing |

There is no auto-refresh. The files are read when you open the pane and when you press `r`.

#### The RULE column

In the events pane press **`c`** (the column picker), move to **RULE** and press space (or `x`)
to tick it, then `esc`. It is off by default.

For a response in which the model asked for tools, the cell shows the strongest verdict among the
calls: `deny`, `ask`, `unknown`, `partial`, `allow` or `none`, with a count when there are several
(`deny ×3`). It is blank on every other row. A `…` means the calls are still being fetched, and
`n/a` means this session's policy cannot be shown here (the same cases as the pane).

Why it is opt-in: the events list is fetched without message bodies, which drops the tool calls.
So with the column on, agentop fetches each tool-call *response* in full, four at a time. These
are small (median 433 bytes), and the detail pane already makes the same request.

#### The ACCESS block

Turn the **RULE** column on first (the block uses the policy the column resolves; pressing `V`
does not provide it). Then open the **detail** of a response that made tool calls. A block at the
top lists each call, its verdict, the deciding rule and its layer, and the notes:

```
ACCESS  which rule applies to each call (not what happened: the mode, hooks and the read-only set also decide)
  Bash git push origin main  → ask  ask Bash(git push *) (project)
```

---

## Reading a verdict

Every verdict is a statement about the **rules**. It is never a claim about what Claude Code
finally did.

| Verdict | Meaning |
|---|---|
| `deny` | a deny rule matches. Claude Code refuses the call; no hook or mode lifts a deny rule. |
| `ask` | an ask rule matches and no deny does. Claude Code prompts, even if an allow rule also matches. |
| `allow` | allow rules cover the whole call (every subcommand, for Bash) and no deny or ask matches. |
| `partial` | Bash only: some subcommands are covered by allow rules and some are not. |
| `none` | no rule matches. **This is not "allowed" and not "prompts".** |
| `unknown` | a rule that could outrank the result cannot be evaluated here, so no lower decision is reported past it. |

**`none` is the one to read twice.** When no rule matches, the outcome is decided by things that
are not rules: the built-in read-only command set (`ls`, `cat`, read-only `git`, …), the
permission mode, the auto-mode classifier, hooks and the sandbox.

**`unknown`** means the matcher stopped short of guessing. Typical causes, each named in a `NOTE`:

- a Bash command it cannot split (unterminated quote, dangling `&&`, more than 10,000 characters);
- a path rule using `!` negation, `[…]` classes or backslash escapes;
- a path rule it cannot locate (no working directory or home known);
- a Bash command that names a file a `Read` or `Edit` deny/ask rule covers. Claude Code applies
  those rules to the files named by the commands it recognises inside Bash (`cat`, `sed`, `tee`,
  and in practice `grep`), and does not list them. In real transcripts this refused two commands
  that "no rule matches" would have wrongly passed.

---

## What it cannot see

- **Files as they are now, not as they were.** A rule added with "Yes, and don't ask again" shows
  up at once; a rule removed after a session started is gone from the answer.
- **Managed policy delivered by MDM, the registry or the claude.ai console.** Only
  `managed-settings.json` and `managed-settings.d/` are files.
- **Launch flags** other than `--settings` (`--allowedTools`, `--add-dir`). The *mode* a session
  ran in is recovered from its transcript; the rest are not on disk.
- **Workspace trust.** Project `allow` rules apply only after the folder is trusted; that state is
  not in any settings file, so such rules are marked, not judged.
- **`/cd`.** A session that used `/cd` reads its project files from the new directory; a
  transcript cannot tell that from a `cd` inside a command, so the session is reported at its
  starting directory.
- **Hooks' commands and `env` values.** Hooks are listed by event name only, and `env` is never
  read, so a secret in a settings file cannot reach any output.
- **Symlinks, Skill aliases, and a `--settings` file's `/path` anchor.**
- **Sessions on another machine.** Run `agentop access` on the machine where the session ran.

---

## Troubleshooting

**`agentop access --session X` says there is no session.**
The session is not in `~/.cortex/session-metadata.json` yet. Run
`~/agentop-dev experimental read-claude-sessions --merge`, or open `agentop observe` and wait for
the background harvest.

**`"abc" matches 12 sessions; use more of the id`**
Use more characters. The first eight of a session id are almost always enough.

**The `V` pane says the session "has not been read from a Claude Code transcript yet".**
Same cause as the first item. Once the harvest reaches it, press `r` in the pane.

**The `V` pane says the session is "not on this machine's Cortex".**
You are connected to something other than the local Cortex (for example `--kubernetes` or a
port-forward). Its settings files are not here. This is deliberate: showing this machine's
settings for it would be a confident wrong answer.

**The RULE column shows `…` for a long time.**
The calls are fetched four at a time, newest first. A very long session takes a while to fill in.
If the proxy is slow or unreachable the cells stay `…`.

**A command I know Claude Code refused shows `none`.**
That is the case to report. Run `--explain` on it, and send the command, the verdict and the
settings files. `none` should not be possible for a command Claude Code refused because of a
rule; the rule-based reasons for a refusal are the ones this view is meant to catch.

**The tests.** From `cmd/agentop`: `GOWORK=off go test ./access/ ./tui/`. The root package does
not finish a full run in every environment (it also hangs on a clean checkout); run the access
tests by name: `go test -run 'TestRunAccess|TestParseExplain|TestResultText' .`.

---

## Where to read more

- Reference: [`docs/agentop-access.md`](agentop-access.md)
- Design: [`docs/superpowers/specs/2026-11-06-agentop-access-view-design.md`](superpowers/specs/2026-11-06-agentop-access-view-design.md)
- Viewer panes and keys: [`cmd/agentop/README.md`](../cmd/agentop/README.md), the *Access* entry
- Claude Code's own documentation of the rules: <https://code.claude.com/docs/en/permissions>
  and <https://code.claude.com/docs/en/settings>

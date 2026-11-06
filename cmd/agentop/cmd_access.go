package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/rossoctl/cortex/cmd/agentop/access"
	"github.com/rossoctl/cortex/core/observe/claude"
)

// runAccess prints the Claude Code permission policy that applies to a working
// directory: the settings layers, the rules merged across them with the file
// each came from, and what looks risky.
//
// It is the resolver with a flag parser around it, kept as a command so the
// policy can be read and diffed without opening the viewer. Everything it knows
// comes from settings files on this machine, as they are now. It cannot see
// managed policy delivered by MDM or the claude.ai console, the per-session
// flags a running session was started with, or whether a folder has been
// trusted; the usage says so.
func runAccess(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("agentop access", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cwd := fs.String("cwd", "", "working directory to resolve the policy for (default: the current directory)")
	sessionID := fs.String("session", "", "resolve for a harvested Claude Code session: its id or a unique prefix of it")
	configDir := fs.String("config-dir", "", "Claude Code config directory holding the user settings.json (default: $CLAUDE_CONFIG_DIR, else ~/.claude)")
	cliSettings := fs.String("settings", "", "the --settings value the session was started with: a file path or inline JSON")
	asJSON := fs.Bool("json", false, "emit the policy as JSON")
	fs.Usage = func() {
		fmt.Fprint(stderr, `agentop access — show the Claude Code permission policy for a directory

Usage:
  agentop access                      the policy for the current directory
  agentop access --cwd PATH           the policy for another directory
  agentop access --session ID         the policy for a Claude Code session, from the
                                      directory and config dir it ran in
  agentop access --json               the same, as JSON

Layers, highest precedence first: managed, --settings, project local
(.claude/settings.local.json, kept at the git root), shared project
(.claude/settings.json) and user (settings.json in the config directory).
Permission rule lists merge across layers; a deny anywhere beats an ask, and an
ask beats an allow. Scalars such as the mode take the highest layer that sets them.

--session looks the session up in ~/.cortex/session-metadata.json, which
"agentop observe" and "agentop experimental read-claude-sessions" fill from
Claude Code's transcripts. It uses the directory the session STARTED in and the
permission mode it was last recorded in. A session with no recorded directory
still shows the user and managed layers, and says why the project ones are
missing. --cwd and --config-dir override what the session recorded; --cwd cannot
be combined with --session.

What this cannot see:
  - It reads the files as they are now ("as of now"), not as they were when a
    session started. A rule added with "don't ask again" appears here at once.
  - Managed policy delivered by MDM, the registry or the claude.ai console is not
    a file. Only managed-settings.json and managed-settings.d/ are read.
  - Flags a session was started with, other than --settings, are not on disk. For
    --session the recorded mode stands in for --permission-mode, but a session that
    used /cd reads its project files from the new directory, which a transcript does
    not distinguish from a cd in a command.
  - Project allow rules apply only after the folder is trusted (workspace trust);
    that state is not in any settings file, so such rules are marked, not judged.
  - Hooks are listed by event name only, and env values are never read.

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "agentop access: unexpected argument %q\n\n", fs.Arg(0))
		fs.Usage()
		return 2
	}

	if *sessionID != "" && *cwd != "" {
		fmt.Fprint(stderr, "agentop access: --session and --cwd are alternatives: a session already names its directory\n\n")
		fs.Usage()
		return 2
	}

	var sess *sessionRef
	if *sessionID != "" {
		var err error
		if sess, err = lookupSession(*sessionID); err != nil {
			fmt.Fprintf(stderr, "agentop access: %v\n", err)
			return 1
		}
		*cwd = sess.cwd
		if *configDir == "" {
			*configDir = sess.configDir
		}
	}

	in, err := access.LocalInput(*cwd, *configDir, *cliSettings, sess != nil)
	if err != nil {
		fmt.Fprintf(stderr, "agentop access: %v\n", err)
		return 1
	}
	if sess != nil {
		in.SessionMode = sess.mode
		in.Notes = append(in.Notes, access.DescribeSession(sess.id, sess.title, sess.cwd))
		if sess.cwd != "" {
			if _, err := os.Stat(sess.cwd); err != nil {
				in.Notes = append(in.Notes, "that directory no longer exists, so its project files are gone or moved")
			}
		}
	}
	policy, err := access.Resolve(in)
	if err != nil {
		fmt.Fprintf(stderr, "agentop access: %v\n", err)
		return 1
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(policy); err != nil {
			fmt.Fprintf(stderr, "agentop access: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprint(stdout, policy.Text())
	return 0
}

// sessionRef is what the metadata file knows about one session, reduced to what the
// resolver needs.
type sessionRef struct {
	id, title, cwd, configDir, mode string
}

// maxSessionCandidates caps how many ids an ambiguity message lists.
const maxSessionCandidates = 8

// lookupSession finds a session in the harvested metadata by id or unique prefix.
//
// An exact id wins over a longer id it happens to prefix. The metadata file is the only
// place a session's directory is recorded (the session API does not carry it), and it exists
// only after a harvest, so its absence gets the remedy rather than a bare "not found".
func lookupSession(query string) (*sessionRef, error) {
	path, err := claude.SessionMetadataPath()
	if err != nil {
		return nil, err
	}
	meta, err := claude.ReadMetadata(path)
	if err != nil {
		return nil, fmt.Errorf("cannot use %s: %w\n  run `agentop experimental read-claude-sessions` to rebuild it", path, err)
	}

	id, m, ok := "", claude.SessionMetadata{}, false
	if e, exact := meta[query]; exact {
		id, m, ok = query, e, true
	} else {
		var matches []string
		for k := range meta {
			if strings.HasPrefix(k, query) {
				matches = append(matches, k)
			}
		}
		sort.Strings(matches)
		switch len(matches) {
		case 0:
		case 1:
			id, m, ok = matches[0], meta[matches[0]], true
		default:
			var b strings.Builder
			fmt.Fprintf(&b, "%q matches %d sessions; use more of the id:", query, len(matches))
			for i, k := range matches {
				if i == maxSessionCandidates {
					fmt.Fprintf(&b, "\n  … and %d more", len(matches)-i)
					break
				}
				fmt.Fprintf(&b, "\n  %s  %s", k, meta[k].Title)
			}
			return nil, errors.New(b.String())
		}
	}
	if !ok {
		return nil, fmt.Errorf("no session %q in %s\n  sessions appear there after `agentop observe` or `agentop experimental read-claude-sessions` has read their transcripts", query, path)
	}
	if m.AgentType != "" && m.AgentType != "Claude Code" {
		return nil, fmt.Errorf("session %s was run by %s; agentop access resolves Claude Code's settings model only", id, m.AgentType)
	}
	return &sessionRef{id: id, title: m.Title, cwd: m.Cwd, configDir: m.AgentConfigDir, mode: m.PermissionMode}, nil
}

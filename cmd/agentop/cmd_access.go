package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/rossoctl/cortex/cmd/agentop/access"
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
	configDir := fs.String("config-dir", "", "Claude Code config directory holding the user settings.json (default: $CLAUDE_CONFIG_DIR, else ~/.claude)")
	cliSettings := fs.String("settings", "", "the --settings value the session was started with: a file path or inline JSON")
	asJSON := fs.Bool("json", false, "emit the policy as JSON")
	fs.Usage = func() {
		fmt.Fprint(stderr, `agentop access — show the Claude Code permission policy for a directory

Usage:
  agentop access                      the policy for the current directory
  agentop access --cwd PATH           the policy for another directory
  agentop access --json               the same, as JSON

Layers, highest precedence first: managed, --settings, project local
(.claude/settings.local.json, kept at the git root), shared project
(.claude/settings.json) and user (settings.json in the config directory).
Permission rule lists merge across layers; a deny anywhere beats an ask, and an
ask beats an allow. Scalars such as the mode take the highest layer that sets them.

What this cannot see:
  - It reads the files as they are now ("as of now"), not as they were when a
    session started. A rule added with "don't ask again" appears here at once.
  - Managed policy delivered by MDM, the registry or the claude.ai console is not
    a file. Only managed-settings.json and managed-settings.d/ are read.
  - Flags a session was started with, other than --settings, are not on disk.
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

	in, err := accessInput(*cwd, *configDir, *cliSettings)
	if err != nil {
		fmt.Fprintf(stderr, "agentop access: %v\n", err)
		return 1
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

// accessInput turns flags and the environment into the resolver's Input. All
// environment and filesystem-layout lookups live here so the access package
// stays a pure function of what it is given.
func accessInput(cwd, configDir, cliSettings string) (access.Input, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return access.Input{}, fmt.Errorf("cannot find the home directory: %w", err)
	}
	if cwd == "" {
		if cwd, err = os.Getwd(); err != nil {
			return access.Input{}, fmt.Errorf("cannot find the current directory: %w", err)
		}
	}
	if cwd, err = filepath.Abs(cwd); err != nil {
		return access.Input{}, err
	}
	if configDir == "" {
		configDir = os.Getenv("CLAUDE_CONFIG_DIR")
	}
	if configDir != "" {
		if configDir, err = filepath.Abs(configDir); err != nil {
			return access.Input{}, err
		}
	}
	return access.Input{
		Cwd:         cwd,
		GitRoot:     gitRoot(cwd),
		Home:        home,
		ConfigDir:   configDir,
		CLISettings: cliSettings,
		FS:          os.DirFS("/"),
		GOOS:        runtime.GOOS,
	}, nil
}

// gitRoot walks up from dir looking for a ".git" entry, the same marker Claude
// Code's repository-root rule keys on, and returns the directory holding it, or
// "" outside a repository. It does not run git: a settings viewer should not
// depend on, or be slowed by, a subprocess, and it must not fail where git
// refuses an unowned repository.
func gitRoot(dir string) string {
	for {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

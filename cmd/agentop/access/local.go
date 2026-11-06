package access

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// LocalInput builds the Input for this machine: the real filesystem, the real home directory,
// and the platform. It is the only place in this package that reads the environment or the
// current directory, so Resolve itself stays a pure function of what it is given.
//
// An empty cwd means the current directory, unless cwdUnknown is set. cwdUnknown is for a
// caller that KNOWS the directory is unknown (a session whose transcript recorded none): there
// the project and local layers must stay unavailable, because falling back to the current
// directory would present an unrelated project's rules as that session's.
func LocalInput(cwd, configDir, cliSettings string, cwdUnknown bool) (Input, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Input{}, fmt.Errorf("cannot find the home directory: %w", err)
	}
	if cwd == "" && !cwdUnknown {
		if cwd, err = os.Getwd(); err != nil {
			return Input{}, fmt.Errorf("cannot find the current directory: %w", err)
		}
	}
	if cwd != "" {
		if cwd, err = filepath.Abs(cwd); err != nil {
			return Input{}, err
		}
	}
	if configDir == "" {
		configDir = os.Getenv("CLAUDE_CONFIG_DIR")
	}
	if configDir != "" {
		if configDir, err = filepath.Abs(configDir); err != nil {
			return Input{}, err
		}
	}
	root := ""
	if cwd != "" {
		root = GitRoot(cwd)
	}
	return Input{
		Cwd:         cwd,
		GitRoot:     root,
		Home:        home,
		ConfigDir:   configDir,
		CLISettings: cliSettings,
		FS:          os.DirFS("/"),
		GOOS:        runtime.GOOS,
	}, nil
}

// GitRoot walks up from dir looking for a ".git" entry, the marker Claude Code's
// repository-root rule keys on, and returns the directory holding it, or "" outside a
// repository. It does not run git: a settings viewer should not depend on, or be slowed by, a
// subprocess, and it must not fail where git refuses an unowned repository. A worktree's .git
// is a file rather than a directory; either marks the root.
func GitRoot(dir string) string {
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

// DescribeSession is the line saying which session an answer is for and what it was derived
// from. Its inputs come from a transcript, so they are cleaned.
func DescribeSession(id, title, cwd string) string {
	d := "session " + Clean(id)
	if t := Clean(title); t != "" {
		d += " (" + t + ")"
	}
	if cwd == "" {
		return d + ": no working directory recorded, so the project and local layers are not shown"
	}
	return d + " started in " + Clean(cwd)
}

package access

import (
	"errors"
	"io/fs"
	"path"
	"strings"
)

const (
	settingsFile      = "settings.json"
	localSettingsFile = "settings.local.json"
	managedFile       = "managed-settings.json"
	managedDropInDir  = "managed-settings.d"
)

// discoverLayers lists the five layers, highest precedence first, with each
// file's path and whether it exists. It reads nothing but file metadata and
// one directory listing.
func discoverLayers(in Input) []Layer {
	return []Layer{
		managedLayer(in),
		cliLayer(in),
		localLayer(in),
		projectLayer(in),
		userLayer(in),
	}
}

func managedDir(goos string) string {
	switch goos {
	case "darwin":
		return "/Library/Application Support/ClaudeCode"
	case "linux":
		return "/etc/claude-code"
	}
	return ""
}

func managedLayer(in Input) Layer {
	l := Layer{Kind: Managed, Note: "file sources only; MDM and console-delivered policy cannot be read"}
	dir := managedDir(in.GOOS)
	if dir == "" {
		l.Note = "managed settings are not read on " + in.GOOS
		return l
	}
	l.Path = path.Join(dir, managedFile)
	l.Files = append(l.Files, statFile(in.FS, l.Path))
	// Claude Code merges the base file first, then every *.json in the
	// drop-in directory in alphabetical order; hidden files and files that
	// do not end in .json are ignored.
	dropDir := path.Join(dir, managedDropInDir)
	if entries, err := fs.ReadDir(in.FS, rel(dropDir)); err == nil {
		for _, e := range entries { // ReadDir returns entries sorted by name
			n := e.Name()
			if e.IsDir() || strings.HasPrefix(n, ".") || !strings.HasSuffix(n, ".json") {
				continue
			}
			l.Files = append(l.Files, statFile(in.FS, path.Join(dropDir, n)))
		}
	}
	return finish(l)
}

func cliLayer(in Input) Layer {
	l := Layer{Kind: CLI, Note: "only --settings is modelled; other flags are not recoverable from disk"}
	if in.CLISettings == "" {
		return l
	}
	if strings.HasPrefix(strings.TrimSpace(in.CLISettings), "{") {
		l.Path = "(inline --settings)"
		l.Files = []File{{Path: l.Path, Present: true}}
		return finish(l)
	}
	l.Path = in.CLISettings
	l.Files = []File{statFile(in.FS, l.Path)}
	return finish(l)
}

func localLayer(in Input) Layer {
	l := Layer{Kind: Local}
	if in.Cwd == "" {
		l.Note = "no working directory for this session"
		return l
	}
	// Since v2.1.211 the file lives at the git root; it stays beside the
	// starting directory outside a repository or when the root is $HOME.
	primaryDir := in.Cwd
	if in.GitRoot != "" && in.GitRoot != in.Home {
		primaryDir = in.GitRoot
	}
	l.Path = path.Join(primaryDir, ".claude", localSettingsFile)
	l.Files = append(l.Files, statFile(in.FS, l.Path))
	// A file an older version left in the starting directory is still read,
	// and rules from both apply.
	if legacy := path.Join(in.Cwd, ".claude", localSettingsFile); legacy != l.Path {
		l.Files = append(l.Files, statFile(in.FS, legacy))
	}
	return finish(l)
}

func projectLayer(in Input) Layer {
	l := Layer{Kind: Project}
	if in.Cwd == "" {
		l.Note = "no working directory for this session"
		return l
	}
	// The shared file is read from the primary working directory only.
	l.Path = path.Join(in.Cwd, ".claude", settingsFile)
	l.Files = []File{statFile(in.FS, l.Path)}
	return finish(l)
}

func userLayer(in Input) Layer {
	l := Layer{Kind: User}
	dir := in.ConfigDir
	if dir == "" && in.Home != "" {
		dir = path.Join(in.Home, ".claude")
	}
	if dir == "" {
		l.Note = "no home or config directory"
		return l
	}
	l.Path = path.Join(dir, settingsFile)
	l.Files = []File{statFile(in.FS, l.Path)}
	return finish(l)
}

// finish sets Present and the first file error on the layer.
func finish(l Layer) Layer {
	for _, f := range l.Files {
		if f.Present {
			l.Present = true
		}
		if f.Err != nil && l.Err == nil {
			l.Err = f.Err
		}
	}
	return l
}

// rel turns an absolute path into the unrooted form fs.FS expects.
func rel(p string) string { return strings.TrimPrefix(path.Clean(p), "/") }

// statFile reports whether p exists as a regular file. A missing file is
// absent, not an error; any other failure is recorded on the File.
func statFile(fsys fs.FS, p string) File {
	f := File{Path: p}
	if fsys == nil {
		return f
	}
	info, err := fs.Stat(fsys, rel(p))
	switch {
	case err == nil && !info.IsDir():
		f.Present = true
	case err == nil:
		// A directory where a file belongs: treat as absent.
	case errors.Is(err, fs.ErrNotExist):
	default:
		f.Err = err
	}
	return f
}

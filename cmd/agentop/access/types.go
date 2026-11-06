package access

import "io/fs"

// LayerKind names a settings source, in the order it is listed (highest
// precedence first).
type LayerKind int

const (
	Managed LayerKind = iota
	CLI
	Local
	Project
	User
)

func (k LayerKind) String() string {
	switch k {
	case Managed:
		return "managed"
	case CLI:
		return "cli"
	case Local:
		return "local"
	case Project:
		return "project"
	case User:
		return "user"
	}
	return "unknown"
}

// Input is everything Resolve may read. It holds no environment lookups: the
// caller passes the values it wants honoured, so a test controls all of it.
type Input struct {
	// Cwd is the session's primary working directory, absolute. Empty means
	// unknown: the project and local layers are then reported unavailable.
	Cwd string
	// GitRoot is the git repository root containing Cwd, absolute, or empty
	// when Cwd is not in a repository. Claude Code keeps the local settings
	// file there.
	GitRoot string
	// Home is the user's home directory, absolute.
	Home string
	// ConfigDir is the directory holding the user settings.json
	// (CLAUDE_CONFIG_DIR). Empty means Home/.claude.
	ConfigDir string
	// CLISettings is the value of --settings: a file path or inline JSON.
	// Empty means the flag was not given.
	CLISettings string
	// FS is read-only access to the filesystem, rooted at "/": a path
	// "/a/b" is opened as "a/b".
	FS fs.FS
	// GOOS selects the managed-settings location: "darwin" or "linux".
	GOOS string
}

// File is one settings file inside a layer.
type File struct {
	Path    string
	Present bool
	// Err is set when the file exists but could not be read or parsed. A
	// missing file is not an error.
	Err error
}

// Counts is how many rules of each decision a layer contributes.
type Counts struct {
	Allow, Ask, Deny int
}

// Layer is one settings source and the files that make it up.
type Layer struct {
	Kind LayerKind
	// Path is the primary file's path, or "" when the layer has no path (no
	// cwd, or no --settings given).
	Path string
	// Files lists every file read for this layer, in merge order.
	Files []File
	// Present is true when at least one file in the layer exists.
	Present bool
	// Err is the first read or parse error among the layer's files.
	Err error
	// Note explains a limit of what can be known, e.g. "file sources only".
	Note   string
	Counts Counts
}

// Policy is the resolved result. Task 2 fills the rest of it.
type Policy struct {
	Layers []Layer
}

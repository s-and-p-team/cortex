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

// Decision is what a rule does. The order is evaluation order: Claude Code
// checks deny, then ask, then allow, and the first match wins.
type Decision int

const (
	Deny Decision = iota
	Ask
	Allow
)

func (d Decision) String() string {
	switch d {
	case Deny:
		return "deny"
	case Ask:
		return "ask"
	case Allow:
		return "allow"
	}
	return "unknown"
}

// Rule is one permission rule from one settings file.
type Rule struct {
	Decision Decision
	// Raw is the rule exactly as written, e.g. "Bash(git push *)".
	Raw string
	// Tool and Pattern are Raw split at its parentheses. Pattern is empty for
	// a bare tool name, which matches every use of the tool.
	Tool, Pattern string
	Source        LayerKind
	// File is the settings file the rule was read from.
	File string
	// ShadowedBy is the rule that makes this one unreachable: a deny over an
	// ask or allow, or an ask over an allow, for the same pattern or for the
	// whole tool. Nil when nothing is known to shadow it. v1 recognises only
	// identical patterns and match-all, never glob subsumption.
	ShadowedBy *Rule
	// Ignored is why Claude Code disregards the rule, or "".
	Ignored string
	// NeedsTrust is set on project allow rules, which apply only after the
	// user trusts the folder. Trust state is not in any settings file.
	NeedsTrust bool
}

// Scalar is a single-valued setting and the layer that decided it.
type Scalar[T any] struct {
	Value T
	Layer LayerKind
	Set   bool
}

// IgnoredSetting is a value present in a file that Claude Code does not honour
// from that layer, so it is reported rather than treated as effective.
type IgnoredSetting struct {
	Key, Value string
	Layer      LayerKind
	File       string
	Reason     string
}

// Dir is an additionalDirectories entry.
type Dir struct {
	Path   string
	Source LayerKind
	// NeedsTrust is set when every layer that grants the directory is the
	// shared project file.
	NeedsTrust bool
}

// Hook records that a layer registers hooks for an event. Commands are
// deliberately not recorded: they are paths and scripts, not policy.
type Hook struct {
	Event  string
	Source LayerKind
}

// Policy is the resolved result.
type Policy struct {
	Layers  []Layer
	Mode    Scalar[string]
	Sandbox Scalar[bool]
	// Rules is every rule from every layer, deny first, then ask, then allow,
	// highest layer first within each decision.
	Rules   []Rule
	Dirs    []Dir
	Hooks   []Hook
	Ignored []IgnoredSetting
}

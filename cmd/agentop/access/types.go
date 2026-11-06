package access

import (
	"encoding/json"
	"io/fs"
)

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
	// SessionMode is the permission mode the session was last recorded in (from its
	// transcript), or "". It is what the session actually ran under, which differs from the
	// configured default whenever a mode was chosen at launch or switched mid-session.
	SessionMode string
	// Notes are caller-supplied lines about where this input came from (for example which
	// session it was derived from), carried into the output unchanged.
	Notes []string
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

func (f File) MarshalJSON() ([]byte, error) {
	o := struct {
		Path    string `json:"path"`
		Present bool   `json:"present"`
		Error   string `json:"error,omitempty"`
	}{Path: f.Path, Present: f.Present}
	if f.Err != nil {
		o.Error = f.Err.Error()
	}
	return json.Marshal(o)
}

// Counts is how many rules of each decision a layer contributes.
type Counts struct {
	Allow int `json:"allow"`
	Ask   int `json:"ask"`
	Deny  int `json:"deny"`
}

// Layer is one settings source and the files that make it up.
type Layer struct {
	Kind LayerKind `json:"kind"`
	// Path is the primary file's path, or "" when the layer has no path (no
	// cwd, or no --settings given).
	Path string `json:"path,omitempty"`
	// Files lists every file read for this layer, in merge order.
	Files []File `json:"files"`
	// Present is true when at least one file in the layer exists.
	Present bool `json:"present"`
	// Err is the first read or parse error among the layer's files.
	Err error `json:"-"`
	// Note explains a limit of what can be known, e.g. "file sources only".
	Note   string `json:"note,omitempty"`
	Counts Counts `json:"counts"`
}

func (l Layer) MarshalJSON() ([]byte, error) {
	type plain Layer
	o := struct {
		plain
		Error string `json:"error,omitempty"`
	}{plain: plain(l)}
	if l.Err != nil {
		o.Error = l.Err.Error()
	}
	return json.Marshal(o)
}

func (k LayerKind) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// Decision is what a rule does. The order is evaluation order: Claude Code
// checks deny, then ask, then allow, and the first match wins.
type Decision int

const (
	Deny Decision = iota
	Ask
	Allow
)

func (d Decision) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

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
	Decision Decision `json:"decision"`
	// Raw is the rule exactly as written, e.g. "Bash(git push *)".
	Raw string `json:"raw"`
	// Tool and Pattern are Raw split at its parentheses. Pattern is empty for
	// a bare tool name, which matches every use of the tool.
	Tool    string    `json:"tool"`
	Pattern string    `json:"pattern,omitempty"`
	Source  LayerKind `json:"source"`
	// File is the settings file the rule was read from.
	File string `json:"file"`
	// ShadowedBy is the rule that makes this one unreachable: a deny over an
	// ask or allow, or an ask over an allow, for the same pattern or for the
	// whole tool. Nil when nothing is known to shadow it. v1 recognises only
	// identical patterns and match-all, never glob subsumption. In JSON it is
	// a short reference, not a nested rule.
	ShadowedBy *Rule `json:"-"`
	// Ignored is why Claude Code disregards the rule, or "".
	Ignored string `json:"ignored,omitempty"`
	// NeedsTrust is set on project allow rules, which apply only after the
	// user trusts the folder. Trust state is not in any settings file.
	NeedsTrust bool `json:"needsTrust,omitempty"`
}

type ruleRef struct {
	Decision Decision  `json:"decision"`
	Raw      string    `json:"raw"`
	Source   LayerKind `json:"source"`
}

func (r Rule) MarshalJSON() ([]byte, error) {
	type plain Rule
	o := struct {
		plain
		ShadowedBy *ruleRef `json:"shadowedBy,omitempty"`
	}{plain: plain(r)}
	if r.ShadowedBy != nil {
		o.ShadowedBy = &ruleRef{r.ShadowedBy.Decision, r.ShadowedBy.Raw, r.ShadowedBy.Source}
	}
	return json.Marshal(o)
}

// Scalar is a single-valued setting and the layer that decided it.
type Scalar[T any] struct {
	Value T         `json:"value"`
	Layer LayerKind `json:"layer"`
	Set   bool      `json:"set"`
}

// IgnoredSetting is a value present in a file that Claude Code does not honour
// from that layer, so it is reported rather than treated as effective.
type IgnoredSetting struct {
	Key    string    `json:"key"`
	Value  string    `json:"value"`
	Layer  LayerKind `json:"layer"`
	File   string    `json:"file"`
	Reason string    `json:"reason"`
}

// Dir is an additionalDirectories entry.
type Dir struct {
	Path   string    `json:"path"`
	Source LayerKind `json:"source"`
	// NeedsTrust is set when every layer that grants the directory is the
	// shared project file.
	NeedsTrust bool `json:"needsTrust,omitempty"`
}

// Hook records that a layer registers hooks for an event. Commands are
// deliberately not recorded: they are paths and scripts, not policy.
type Hook struct {
	Event  string    `json:"event"`
	Source LayerKind `json:"source"`
}

// Severity ranks a RiskFlag. The order is the sort order, lowest first.
type Severity int

const (
	Low Severity = iota
	Medium
	High
)

func (s Severity) String() string {
	switch s {
	case Low:
		return "low"
	case Medium:
		return "medium"
	case High:
		return "high"
	}
	return "unknown"
}

func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// RiskFlag is something an operator should look at. Code is stable and
// machine-readable; Detail is for people.
type RiskFlag struct {
	Code     string   `json:"code"`
	Severity Severity `json:"severity"`
	Detail   string   `json:"detail"`
}

// Policy is the resolved result.
type Policy struct {
	Layers []Layer        `json:"layers"`
	Mode   Scalar[string] `json:"mode"`
	// SessionMode is Input.SessionMode: the mode this session was recorded in, when known.
	SessionMode string `json:"sessionMode,omitempty"`
	// Notes is Input.Notes.
	Notes []string `json:"notes"`

	Sandbox Scalar[bool] `json:"sandbox"`
	// Rules is every rule from every layer, ordered by decision (deny, ask,
	// allow), then tool, pattern and layer.
	Rules   []Rule           `json:"rules"`
	Dirs    []Dir            `json:"dirs"`
	Hooks   []Hook           `json:"hooks"`
	Ignored []IgnoredSetting `json:"ignored"`
	// Flags is ordered by severity (high first), then code and detail.
	Flags []RiskFlag `json:"flags"`
}

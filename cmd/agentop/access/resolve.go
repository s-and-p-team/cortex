package access

import (
	"errors"
	"io/fs"
	"sort"
)

// Resolve reads the settings layers for in.Cwd and merges them into the
// effective policy. A layer that is missing is reported absent; one that is
// unreadable or malformed carries its error and contributes nothing, and the
// others still resolve. The returned error is only for a misuse of Input.
func Resolve(in Input) (Policy, error) {
	if in.FS == nil {
		return Policy{}, errors.New("access: Input.FS is nil")
	}
	p := Policy{Layers: discoverLayers(in)}

	// docs[i][j] is the decoded j'th file of layer i, or nil if it is absent
	// or failed to read or parse.
	docs := make([][]*settingsDoc, len(p.Layers))
	for i := range p.Layers {
		l := &p.Layers[i]
		docs[i] = make([]*settingsDoc, len(l.Files))
		for j := range l.Files {
			f := &l.Files[j]
			if !f.Present {
				continue
			}
			data, err := readSettings(in, f.Path)
			if err == nil {
				docs[i][j], err = decodeSettings(data)
			}
			if err != nil {
				f.Err = err
				if l.Err == nil {
					l.Err = err
				}
			}
		}
	}

	bypassDisabled := false
	managedOnly := false
	for _, d := range docs[layerIndex(p.Layers, Managed)] {
		if d != nil && d.AllowManagedPermissionRulesOnly {
			managedOnly = true
		}
	}

	for i := range p.Layers {
		l := &p.Layers[i]
		for _, j := range priority(l) {
			d := docs[i][j]
			if d == nil {
				continue
			}
			file := l.Files[j].Path
			addRules(&p, l, file, Deny, d.Permissions.Deny, managedOnly)
			addRules(&p, l, file, Ask, d.Permissions.Ask, managedOnly)
			addRules(&p, l, file, Allow, d.Permissions.Allow, managedOnly)
			addDirs(&p, l.Kind, d.Permissions.AdditionalDirectories)
			if d.Permissions.DisableBypassPermissionsMode == "disable" {
				bypassDisabled = true
			}
			for ev := range d.Hooks {
				p.Hooks = append(p.Hooks, Hook{Event: ev, Source: l.Kind})
			}
			if m := d.Permissions.DefaultMode; m != "" {
				switch {
				case (m == "auto" || m == "bypassPermissions") && (l.Kind == Project || l.Kind == Local):
					p.Ignored = append(p.Ignored, IgnoredSetting{
						Key: "permissions.defaultMode", Value: m, Layer: l.Kind, File: file,
						Reason: m + " does not take effect from project or local settings; set it in user or managed settings",
					})
				case !p.Mode.Set:
					p.Mode = Scalar[string]{Value: m, Layer: l.Kind, Set: true}
				}
			}
			if e := d.Sandbox.Enabled; e != nil && !p.Sandbox.Set {
				p.Sandbox = Scalar[bool]{Value: *e, Layer: l.Kind, Set: true}
			}
		}
	}

	sort.SliceStable(p.Rules, func(a, b int) bool {
		x, y := p.Rules[a], p.Rules[b]
		if x.Decision != y.Decision {
			return x.Decision < y.Decision
		}
		if x.Tool != y.Tool {
			return x.Tool < y.Tool
		}
		if x.Pattern != y.Pattern {
			return x.Pattern < y.Pattern
		}
		return x.Source < y.Source
	})
	sort.SliceStable(p.Hooks, func(a, b int) bool {
		if p.Hooks[a].Event != p.Hooks[b].Event {
			return p.Hooks[a].Event < p.Hooks[b].Event
		}
		return p.Hooks[a].Source < p.Hooks[b].Source
	})
	p.Hooks = dedupeHooks(p.Hooks)
	markShadowed(p.Rules)
	p.Flags = computeFlags(in, p, bypassDisabled)
	normalize(&p)
	return p, nil
}

func readSettings(in Input, path string) ([]byte, error) {
	if path == inlineSettingsPath {
		return []byte(in.CLISettings), nil
	}
	return fs.ReadFile(in.FS, rel(path))
}

func layerIndex(ls []Layer, k LayerKind) int {
	for i, l := range ls {
		if l.Kind == k {
			return i
		}
	}
	return -1
}

// priority lists a layer's file indexes, highest priority first. Managed
// drop-ins merge after the base file, so the last one wins a conflicting
// scalar (the docs give the merge order, not the tie-break; later-wins is the
// drop-in convention). In the local layer the git-root file is listed first
// and wins over the legacy copy in the starting directory.
func priority(l *Layer) []int {
	idx := make([]int, len(l.Files))
	for i := range idx {
		idx[i] = i
	}
	if l.Kind == Managed {
		for a, b := 0, len(idx)-1; a < b; a, b = a+1, b-1 {
			idx[a], idx[b] = idx[b], idx[a]
		}
	}
	return idx
}

func addRules(p *Policy, l *Layer, file string, d Decision, raws []string, managedOnly bool) {
	for _, raw := range raws {
		tool, pattern := parseRule(raw)
		r := Rule{Decision: d, Raw: raw, Tool: tool, Pattern: pattern, Source: l.Kind, File: file}
		if managedOnly && l.Kind != Managed {
			r.Ignored = "ignored: allowManagedPermissionRulesOnly is set in managed settings"
		}
		r.NeedsTrust = l.Kind == Project && d == Allow
		p.Rules = append(p.Rules, r)
		switch d {
		case Deny:
			l.Counts.Deny++
		case Ask:
			l.Counts.Ask++
		case Allow:
			l.Counts.Allow++
		}
	}
}

func addDirs(p *Policy, src LayerKind, dirs []string) {
	for _, path := range dirs {
		found := false
		for i := range p.Dirs {
			if p.Dirs[i].Path == path {
				found = true
				if src != Project {
					p.Dirs[i].NeedsTrust = false
				}
			}
		}
		if !found {
			p.Dirs = append(p.Dirs, Dir{Path: path, Source: src, NeedsTrust: src == Project})
		}
	}
}

// markShadowed sets ShadowedBy on every ask or allow rule that a higher
// decision makes unreachable. rules must already be ordered deny, ask, allow,
// so the first match is the highest decision from the highest layer. Ignored
// rules neither shadow nor are shadowed.
func markShadowed(rules []Rule) {
	for i := range rules {
		r := &rules[i]
		if r.Decision == Deny || r.Ignored != "" {
			continue
		}
		rt, rp := matchKey(r.Tool, r.Pattern)
		for j := range rules {
			s := &rules[j]
			if s.Decision >= r.Decision || s.Ignored != "" {
				continue
			}
			st, sp := matchKey(s.Tool, s.Pattern)
			if st == rt && (sp == "" || sp == rp) {
				r.ShadowedBy = s
				break
			}
		}
	}
}

func dedupeHooks(hs []Hook) []Hook {
	out := hs[:0]
	for i, h := range hs {
		if i > 0 && h == hs[i-1] {
			continue
		}
		out = append(out, h)
	}
	return out
}

// normalize turns nil slices into empty ones so JSON carries [] and never
// null: the output is an interface for scripts.
func normalize(p *Policy) {
	for i := range p.Layers {
		if p.Layers[i].Files == nil {
			p.Layers[i].Files = []File{}
		}
	}
	if p.Rules == nil {
		p.Rules = []Rule{}
	}
	if p.Dirs == nil {
		p.Dirs = []Dir{}
	}
	if p.Hooks == nil {
		p.Hooks = []Hook{}
	}
	if p.Ignored == nil {
		p.Ignored = []IgnoredSetting{}
	}
	if p.Flags == nil {
		p.Flags = []RiskFlag{}
	}
}

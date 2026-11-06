package access

import (
	"fmt"
	"path"
	"sort"
)

// broadTools are tools whose unrestricted allow lets the agent change the
// machine or reach the network without asking. Read-only tools (Read, Glob,
// Grep) are deliberately absent: allowing them everywhere is the normal setup.
var broadTools = map[string]Severity{
	"Bash":         High,
	"PowerShell":   High,
	"Write":        Medium,
	"Edit":         Medium,
	"NotebookEdit": Medium,
	"WebFetch":     Medium,
}

// computeFlags lists what an operator should look at. It reports facts about
// the configuration; it does not say whether any of it was used.
func computeFlags(in Input, p Policy, bypassDisabled bool) []RiskFlag {
	var fl []RiskFlag
	add := func(code string, sev Severity, format string, a ...any) {
		fl = append(fl, RiskFlag{Code: code, Severity: sev, Detail: fmt.Sprintf(format, a...)})
	}

	if p.Mode.Set && p.Mode.Value == "bypassPermissions" {
		add("bypass-permissions", High,
			"the default mode is bypassPermissions (set in %s settings): permission prompts are skipped", p.Mode.Layer)
	}

	// Configured and recorded modes are different facts: a session can be started in
	// bypassPermissions from the command line, which no settings file shows.
	if p.SessionMode == "bypassPermissions" {
		add("session-bypass", High,
			"this session was recorded in bypassPermissions mode: permission prompts were skipped")
	}

	for _, r := range p.Rules {
		if r.Decision != Allow || r.Ignored != "" || r.ShadowedBy != nil {
			continue
		}
		sev, ok := broadTools[r.Tool]
		if !ok {
			continue
		}
		if _, pat := matchKey(r.Tool, r.Pattern); pat != "" {
			continue
		}
		add("broad-allow", sev, "allow %s in %s settings permits every use of %s without asking", r.Raw, r.Source, r.Tool)
	}

	switch {
	case p.Sandbox.Set && !p.Sandbox.Value:
		add("sandbox-off", Medium, "sandbox.enabled is false in %s settings", p.Sandbox.Layer)
	case !p.Sandbox.Set:
		add("sandbox-off", Low, "sandbox.enabled is not set in any readable settings layer")
	}

	home := path.Clean(in.Home)
	for _, d := range p.Dirs {
		c := path.Clean(d.Path)
		if c == "/" || c == "~" || (in.Home != "" && c == home) {
			add("wide-directory", Medium, "additionalDirectories includes %s (%s settings), which gives file access to all of it", d.Path, d.Source)
		}
	}

	if managed := layerIndex(p.Layers, Managed); managed >= 0 && p.Layers[managed].Present && !bypassDisabled {
		add("bypass-not-disabled", Low,
			"managed settings are present but none sets permissions.disableBypassPermissionsMode to \"disable\"")
	}

	for _, l := range p.Layers {
		if l.Err == nil {
			continue
		}
		sev := Medium
		note := "Claude Code skips this file"
		if l.Kind == Managed {
			sev, note = High, "Claude Code refuses to start with an unparsable managed file"
		}
		add("layer-error", sev, "%s settings: %v (%s)", l.Kind, l.Err, note)
	}

	sort.SliceStable(fl, func(a, b int) bool {
		if fl[a].Severity != fl[b].Severity {
			return fl[a].Severity > fl[b].Severity
		}
		if fl[a].Code != fl[b].Code {
			return fl[a].Code < fl[b].Code
		}
		return fl[a].Detail < fl[b].Detail
	})
	return fl
}

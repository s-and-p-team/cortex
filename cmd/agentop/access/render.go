package access

import (
	"fmt"
	"strings"
)

// Text renders the policy for a terminal: the layer stack, the effective
// scalars, the rules in evaluation order, then anything worth a second look.
func (p Policy) Text() string {
	var b strings.Builder

	for _, n := range p.Notes {
		fmt.Fprintf(&b, "%s\n", Clean(n))
	}
	if len(p.Notes) > 0 {
		b.WriteString("\n")
	}
	b.WriteString("LAYERS (highest precedence first)\n")
	for _, l := range p.Layers {
		fmt.Fprintf(&b, "  %-8s", l.Kind)
		switch {
		case l.Path == "":
			b.WriteString("-")
		default:
			b.WriteString(Clean(l.Path))
		}
		switch {
		case l.Err != nil:
			fmt.Fprintf(&b, "  error: %s", Clean(l.Err.Error()))
		case l.Present:
			fmt.Fprintf(&b, "  present  allow %d / ask %d / deny %d", l.Counts.Allow, l.Counts.Ask, l.Counts.Deny)
		default:
			b.WriteString("  absent")
		}
		b.WriteString("\n")
		for _, f := range l.Files[min(1, len(l.Files)):] {
			if f.Present || f.Err != nil {
				fmt.Fprintf(&b, "  %-8s+ %s\n", "", Clean(f.Path))
			}
		}
		if l.Note != "" {
			fmt.Fprintf(&b, "  %-8s  %s\n", "", Clean(l.Note))
		}
	}

	b.WriteString("\nSETTINGS\n")
	if p.Mode.Set {
		fmt.Fprintf(&b, "  mode     %s (%s)\n", Clean(p.Mode.Value), p.Mode.Layer)
	} else {
		b.WriteString("  mode     not set in any layer (Claude Code's built-in default applies)\n")
	}
	if p.SessionMode != "" {
		fmt.Fprintf(&b, "  session  %s (the mode recorded for this session; \"mode\" above is the configured default for new ones)\n", Clean(p.SessionMode))
	}
	if p.Sandbox.Set {
		fmt.Fprintf(&b, "  sandbox  %s (%s)\n", onOff(p.Sandbox.Value), p.Sandbox.Layer)
	} else {
		b.WriteString("  sandbox  not set in any layer\n")
	}
	if len(p.Hooks) > 0 {
		var hs []string
		for _, h := range p.Hooks {
			hs = append(hs, fmt.Sprintf("%s (%s)", Clean(h.Event), h.Source))
		}
		fmt.Fprintf(&b, "  hooks    %s\n", strings.Join(hs, ", "))
	}
	for _, d := range p.Dirs {
		fmt.Fprintf(&b, "  dir      %s (%s)%s\n", Clean(d.Path), d.Source, trustNote(d.NeedsTrust))
	}
	for _, ig := range p.Ignored {
		fmt.Fprintf(&b, "  ignored  %s = %s in %s settings: %s\n", Clean(ig.Key), Clean(ig.Value), ig.Layer, Clean(ig.Reason))
	}

	b.WriteString("\nRULES (checked deny, then ask, then allow; first match wins)\n")
	if len(p.Rules) == 0 {
		b.WriteString("  none\n")
	}
	for _, r := range p.Rules {
		fmt.Fprintf(&b, "  %-5s %-34s %s", r.Decision, Clean(r.Raw), r.Source)
		switch {
		case r.Ignored != "":
			fmt.Fprintf(&b, "  %s", Clean(r.Ignored))
		case r.ShadowedBy != nil:
			fmt.Fprintf(&b, "  shadowed by %s %s (%s)", r.ShadowedBy.Decision, Clean(r.ShadowedBy.Raw), r.ShadowedBy.Source)
		}
		b.WriteString(trustNote(r.NeedsTrust))
		b.WriteString("\n")
	}

	if len(p.Flags) > 0 {
		b.WriteString("\nFLAGS\n")
		for _, f := range p.Flags {
			fmt.Fprintf(&b, "  %-6s %-20s %s\n", f.Severity, Clean(f.Code), Clean(f.Detail))
		}
	}
	return b.String()
}

func onOff(v bool) string {
	if v {
		return "on"
	}
	return "off"
}

func trustNote(needs bool) string {
	if needs {
		return "  (applies only after workspace trust)"
	}
	return ""
}

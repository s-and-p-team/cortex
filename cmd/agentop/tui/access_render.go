package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/rossoctl/cortex/cmd/agentop/access"
)

// accessLines draws the access pane as one string per line, each at most width columns.
//
// LINES IN A VIEWPORT, NOT A TABLE. A table cell cannot carry ANSI (it truncates escapes as
// text; see TestSessionsRows_CarryNoANSIUnderAForcedColourProfile), and dimming a shadowed rule
// is the point of the view.
//
// WIDTH IS EXACT BECAUSE TEXT IS CUT BEFORE IT IS STYLED. Every field is clipped as plain text
// to the room it has, then wrapped in its style, so a line never overruns and a style is never
// split. Policy text can be long (a Bash rule is a command line) and there is no wrapping: a
// rule stays on one line, and its source stays visible, because the source is what the reader
// came for.
//
// EVERY STRING THAT CAME FROM A FILE, A TRANSCRIPT OR THE WIRE IS CLEANED, once, here: the
// settings files may belong to any cloned repository, and nothing downstream sanitises.
//
// A refusal draws only its reason. A stale policy still held by the model is never drawn for a
// target that cannot resolve.
func accessLines(p access.Policy, t accessTarget, width int, loading bool) []string {
	width = max(width, 1)
	var out []string
	add := func(s string) { out = append(out, s) }
	// row styles one line: plain is cut to the width first.
	row := func(style lipgloss.Style, s string) {
		add(style.Render(truncRight(access.Clean(s), width)))
	}

	if !t.Kind.resolvable() {
		for _, l := range wrapPlain(access.Clean(t.Reason), width) {
			add(l)
		}
		return out
	}
	if t.Kind == targetNoCwd {
		for _, l := range wrapPlain(access.Clean(t.Reason), width) {
			add(styleWarn.Render(l))
		}
		add("")
	}

	for _, n := range p.Notes {
		row(styleHint, n)
	}
	if len(p.Notes) > 0 {
		add("")
	}
	switch {
	case loading && len(p.Layers) == 0:
		row(styleHint, "resolving…")
		return out
	case loading:
		row(styleHint, "refreshing…")
	}

	row(styleTitle, "LAYERS (highest precedence first)")
	for _, l := range p.Layers {
		add(layerLine(l, width))
		for _, f := range l.Files[min(1, len(l.Files)):] {
			if f.Present || f.Err != nil {
				row(styleHint, "           + "+f.Path)
			}
		}
		if l.Note != "" {
			row(styleHint, "           "+l.Note)
		}
	}
	add("")

	row(styleTitle, "SETTINGS")
	mode := "not set in any layer (Claude Code's built-in default applies)"
	if p.Mode.Set {
		mode = fmt.Sprintf("%s (%s)", p.Mode.Value, p.Mode.Layer)
	}
	row(lipgloss.NewStyle(), "  mode, configured: "+mode)
	if p.SessionMode != "" {
		st := lipgloss.NewStyle()
		if p.SessionMode == "bypassPermissions" {
			st = styleError
		}
		row(st, "  mode, this session: "+p.SessionMode)
	}
	if p.Sandbox.Set {
		row(lipgloss.NewStyle(), fmt.Sprintf("  sandbox: %s (%s)", onOffWord(p.Sandbox.Value), p.Sandbox.Layer))
	} else {
		row(styleHint, "  sandbox: not set in any layer")
	}
	for _, h := range p.Hooks {
		row(lipgloss.NewStyle(), fmt.Sprintf("  hooks: %s (%s)", h.Event, h.Source))
	}
	for _, d := range p.Dirs {
		row(lipgloss.NewStyle(), fmt.Sprintf("  directory: %s (%s)%s", d.Path, d.Source, trustSuffix(d.NeedsTrust)))
	}
	for _, ig := range p.Ignored {
		row(styleWarn, fmt.Sprintf("  ignored: %s = %s in %s settings: %s", ig.Key, ig.Value, ig.Layer, ig.Reason))
	}
	add("")

	if len(p.Flags) > 0 {
		row(styleTitle, "FLAGS")
		for _, f := range p.Flags {
			st := styleWarn
			switch f.Severity {
			case access.High:
				st = styleError
			case access.Low:
				st = styleHint
			}
			row(st, fmt.Sprintf("  %-6s %-20s %s", f.Severity, f.Code, f.Detail))
		}
		add("")
	}

	row(styleTitle, "RULES (checked deny, then ask, then allow; the first match wins)")
	if len(p.Rules) == 0 {
		row(styleHint, "  no rules in any readable layer")
	}
	for _, r := range p.Rules {
		add(ruleLine(r, width))
	}
	return out
}

// layerLine is one layer: kind, path, state. The path is the part that gives way.
func layerLine(l access.Layer, width int) string {
	state := "absent"
	switch {
	case l.Err != nil:
		state = "error: " + access.Clean(l.Err.Error())
	case l.Present:
		state = fmt.Sprintf("present  allow %d  ask %d  deny %d", l.Counts.Allow, l.Counts.Ask, l.Counts.Deny)
	}
	path := access.Clean(l.Path)
	if path == "" {
		path = "–"
	}
	const kindW = 9
	prefix := fmt.Sprintf("  %-*s", kindW, l.Kind)
	room := width - lipgloss.Width(prefix) - 2 - lipgloss.Width(state)
	switch {
	case room >= 8:
		// Paths are identified by their end, so the middle gives way: keep the tail.
		return prefix + truncLeft(path, room) + "  " + styleForState(l, state)
	default:
		// Too narrow for both: the state is the news, the path is recoverable.
		return truncRight(prefix+state, width)
	}
}

func styleForState(l access.Layer, state string) string {
	switch {
	case l.Err != nil:
		return styleError.Render(state)
	case !l.Present:
		return styleHint.Render(state)
	}
	return state
}

// ruleLine is one rule: decision, rule text, source, and any note. The rule text is clipped to
// leave the source and the note on screen.
func ruleLine(r access.Rule, width int) string {
	var note string
	switch {
	case r.Ignored != "":
		note = "  " + access.Clean(r.Ignored)
	case r.ShadowedBy != nil:
		note = fmt.Sprintf("  shadowed by %s %s (%s)", r.ShadowedBy.Decision, access.Clean(r.ShadowedBy.Raw), r.ShadowedBy.Source)
	}
	note += trustSuffix(r.NeedsTrust)
	source := "  " + r.Source.String()
	head := fmt.Sprintf("  %-5s ", r.Decision)

	room := width - lipgloss.Width(head) - lipgloss.Width(source)
	// The note is the first thing to give: the rule and its source are the row's content. It may
	// take at most half of what is left, so the rule text always keeps the other half.
	if lipgloss.Width(note) > max(room/2, 0) {
		note = truncRight(note, max(room/2, 0))
	}
	body := truncRight(access.Clean(r.Raw), max(room-lipgloss.Width(note), 1))
	line := head + body + source + note
	line = truncRight(line, width) // belt and braces for a width too small for the fixed parts

	dim := r.ShadowedBy != nil || r.Ignored != ""
	if dim {
		return styleMuted.Render(line)
	}
	if r.NeedsTrust {
		return styleWarn.Render(line)
	}
	return line
}

func onOffWord(v bool) string {
	if v {
		return "on"
	}
	return "off"
}

func trustSuffix(needs bool) string {
	if needs {
		return "  (applies only after workspace trust)"
	}
	return ""
}

// wrapPlain breaks s into lines of at most width columns on spaces. A word longer than the
// width is cut, so no line overruns.
func wrapPlain(s string, width int) []string {
	var out []string
	cur := ""
	for _, w := range strings.Fields(s) {
		for lipgloss.Width(w) > width {
			if cur != "" {
				out, cur = append(out, cur), ""
			}
			head := truncRight(w, width)
			out = append(out, head)
			w = strings.TrimPrefix(w, strings.TrimSuffix(head, "…"))
			if w == "" {
				break
			}
		}
		switch {
		case w == "":
		case cur == "":
			cur = w
		case lipgloss.Width(cur)+1+lipgloss.Width(w) <= width:
			cur += " " + w
		default:
			out, cur = append(out, cur), w
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	if len(out) == 0 {
		out = []string{""}
	}
	return out
}

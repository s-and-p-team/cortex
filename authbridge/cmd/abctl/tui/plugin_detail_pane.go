package tui

import (
	"fmt"
	"strings"

	"github.com/kagenti/kagenti-extensions/authbridge/cmd/abctl/apiclient"
)

// showPluginDetail loads the focused plugin into the detail viewport.
// Uses a simple labelled block rather than JSON — the values are short
// and human-readable.
func (m *model) showPluginDetail(p *apiclient.PipelinePlugin) {
	m.detailPlugin = p
	counts := m.countEventsPerPlugin()

	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\n\n", styleTitle.Render("Plugin:"), p.Name)
	fmt.Fprintf(&b, "%s %s\n", styleMuted.Render("Direction:"), p.Direction)
	fmt.Fprintf(&b, "%s %d\n", styleMuted.Render("Position: "), p.Position)
	if len(p.Writes) > 0 {
		fmt.Fprintf(&b, "%s %s\n", styleMuted.Render("Writes:   "), strings.Join(p.Writes, ", "))
	}
	if len(p.Reads) > 0 {
		fmt.Fprintf(&b, "%s %s\n", styleMuted.Render("Reads:    "), strings.Join(p.Reads, ", "))
	}
	body := "no"
	if p.BodyAccess {
		body = "yes"
	}
	fmt.Fprintf(&b, "%s %s\n", styleMuted.Render("Body:     "), body)
	fmt.Fprintf(&b, "%s %d events in cached sessions\n", styleMuted.Render("Activity: "), counts[p.Name])
	fmt.Fprintln(&b)
	b.WriteString(styleHint.Render("(per-plugin runtime config will be added when the Plugin interface\nexposes a Config() method — tracked as a follow-up.)"))

	m.detailVp.SetContent(b.String())
	m.detailVp.GotoTop()
}

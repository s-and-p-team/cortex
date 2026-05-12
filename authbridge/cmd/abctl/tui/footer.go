package tui

import (
	"fmt"
	"strings"
	"time"
)

// footerView renders the bottom two lines: status (connection + rate + drops
// + optional transient flash) and a context-sensitive keybinding hint. No
// lipgloss borders; parent view handles the frame.
func (m *model) footerView() string {
	var status strings.Builder

	// Connection state dot.
	switch m.connState.phase {
	case connOpen:
		status.WriteString(styleOK.Render("● connected"))
	case connReconnecting:
		status.WriteString(styleWarn.Render(
			fmt.Sprintf("◐ reconnecting (attempt %d, next in %ds)",
				m.connState.attempt,
				int(time.Until(m.connState.nextRetry).Round(time.Second).Seconds()))))
	case connFailed:
		msg := "✗ failed"
		if m.connState.err != nil {
			msg += ": " + m.connState.err.Error()
		}
		status.WriteString(styleError.Render(msg))
	default:
		status.WriteString(styleMuted.Render("… connecting"))
	}

	status.WriteString(styleMuted.Render("  "))

	// Rate + drops.
	status.WriteString(styleMuted.Render(fmt.Sprintf("%.1f ev/s", m.rate)))
	status.WriteString(styleMuted.Render("   "))
	if m.drops > 0 {
		status.WriteString(styleWarn.Render(fmt.Sprintf("drops: %d", m.drops)))
	} else {
		status.WriteString(styleMuted.Render("drops: 0"))
	}
	if m.paused {
		status.WriteString(styleWarn.Render("   [paused]"))
	}

	// Flash message (e.g. "yanked → /tmp/...").
	if m.flash != "" && time.Now().Before(m.flashUntil) {
		status.WriteString(styleTitle.Render("   " + m.flash))
	}

	hint := m.helpView()

	return status.String() + "\n" + styleHint.Render(hint)
}

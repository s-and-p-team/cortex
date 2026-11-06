package access

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Clean makes s safe to write to a terminal.
//
// Settings files, and the paths and errors derived from them, come from whatever repository
// was cloned or whatever a transcript contains. Printed raw, an escape sequence in a rule name
// can retitle the window, clear the screen or write the clipboard. Clean removes:
//
//   - whole escape sequences (CSI, OSC, and two-byte escapes), not just the ESC byte, so
//     "[31m" does not survive as visible junk and an OSC payload does not survive as text;
//   - every control character, including NUL, BEL, DEL and the C1 range;
//   - Unicode format characters (bidi overrides and isolates, zero-width joiners) and the line
//     and paragraph separators, which can reorder or hide what a reader sees;
//   - invalid UTF-8.
//
// Tab, newline and carriage return become a single space each, so one value stays on one
// line. Ordinary Unicode, including spaces, is kept as is. It is idempotent, and a single
// pass: an unterminated OSC consumes the rest of the input rather than rescanning it.
func Clean(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		c := s[i]
		if c == 0x1b {
			i = skipEscape(s, i)
			continue
		}
		r, n := utf8.DecodeRuneInString(s[i:])
		i += n
		switch {
		case r == utf8.RuneError && n <= 1:
			// invalid UTF-8: dropped, not repaired
		case r == '\t' || r == '\n' || r == '\r':
			b.WriteByte(' ')
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), unicode.Is(unicode.Zl, r), unicode.Is(unicode.Zp, r) && r != ' ':
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// skipEscape returns the index just past the escape sequence that starts at s[i] == ESC. An
// unterminated sequence runs to the end of s.
func skipEscape(s string, i int) int {
	i++ // ESC
	if i >= len(s) {
		return i
	}
	switch s[i] {
	case '[': // CSI: parameters 0x30-0x3f, intermediates 0x20-0x2f, one final byte 0x40-0x7e
		i++
		for i < len(s) && s[i] >= 0x20 && s[i] <= 0x3f {
			i++
		}
		if i < len(s) && s[i] >= 0x40 && s[i] <= 0x7e {
			i++
		}
	case ']', 'P', 'X', '^', '_': // OSC, DCS, SOS, PM, APC: a string ended by BEL or ST
		i++
		for i < len(s) {
			if s[i] == 0x07 {
				return i + 1
			}
			if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '\\' {
				return i + 2
			}
			i++
		}
	default:
		// A two-byte escape, optionally with intermediates (ESC ( 0, ESC # 8 ...).
		for i < len(s) && s[i] >= 0x20 && s[i] <= 0x2f {
			i++
		}
		if i < len(s) {
			_, n := utf8.DecodeRuneInString(s[i:])
			i += n
		}
	}
	return i
}

package access

import (
	"strings"
	"testing"
)

func TestClean(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"plain", "Bash(git status)", "Bash(git status)"},
		{"unicode kept", "Read(./ünï/日本)", "Read(./ünï/日本)"},
		{"spaces kept", "a  b", "a  b"},
		{"CSI colour", "a\x1b[31mred\x1b[0mb", "aredb"},
		{"CSI with intermediates", "a\x1b[?25lb", "ab"},
		{"OSC title ended by BEL", "a\x1b]0;pwned\x07b", "ab"},
		{"OSC title ended by ST", "a\x1b]0;pwned\x1b\\b", "ab"},
		{"unterminated OSC eats to the end", "a\x1b]0;pwned", "a"},
		{"two-byte escape", "a\x1bcb", "ab"},
		{"lone trailing ESC", "a\x1b", "a"},
		{"NUL", "a\x00b", "ab"},
		{"BEL", "a\x07b", "ab"},
		{"newline and tab become one space", "a\nb\tc", "a b c"},
		{"CR becomes a space", "a\rb", "a b"},
		{"C1 control", "a\u009bb", "ab"},
		{"bidi override", "a\u202eb", "ab"},
		{"bidi isolate", "a\u2066b\u2069", "ab"},
		{"zero width joiner removed", "a\u200bb", "ab"},
		{"line separator", "a\u2028b", "ab"},
		{"paragraph separator", "a\u2029b", "ab"},
		{"invalid UTF-8", "a\xffb", "ab"},
		{"DEL", "a\x7fb", "ab"},
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Clean(c.in)
			if got != c.want {
				t.Errorf("Clean(%q) = %q, want %q", c.in, got, c.want)
			}
			if again := Clean(got); again != got {
				t.Errorf("not idempotent: Clean(Clean(%q)) = %q, want %q", c.in, again, got)
			}
		})
	}
}

// Nothing Clean returns may contain a byte a terminal would act on.
func TestClean_NeverLeavesAControlByteBehind(t *testing.T) {
	hostile := "\x1b[2J\x1b]52;c;ZWNobyBoaQ==\x07\x1b(0\x00\x08\x0b\x0c\x0e\x1f\x7f\u0085\u009d\u202e\u2066 ok"
	got := Clean(hostile)
	for i := 0; i < len(got); i++ {
		if b := got[i]; b < 0x20 || b == 0x7f {
			t.Fatalf("Clean left byte %#x at %d in %q", b, i, got)
		}
	}
	if !strings.HasSuffix(got, " ok") {
		t.Errorf("Clean = %q, want the visible tail kept", got)
	}
}

func TestClean_IsLinearOnAHugeInput(t *testing.T) {
	// An unterminated OSC must not make the scan quadratic.
	in := strings.Repeat("\x1b]", 200000) + strings.Repeat("x", 200000)
	if got := Clean(in); got != "" {
		t.Errorf("Clean = %d bytes, want it all consumed as one unterminated OSC", len(got))
	}
}

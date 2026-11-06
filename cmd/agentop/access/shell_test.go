package access

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func subs(t *testing.T, cmd string) []string {
	t.Helper()
	p := splitCommand(cmd)
	if !p.ok {
		t.Fatalf("splitCommand(%q) is unparseable (%s)", cmd, p.reason)
	}
	return p.subs
}

// The recognised separators are && || ; | |& & and newline (docs, "Compound commands").
func TestSplitCommand_Separators(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"ls", []string{"ls"}},
		{"ls -la", []string{"ls -la"}},
		{"a && b", []string{"a", "b"}},
		{"a || b", []string{"a", "b"}},
		{"a ; b", []string{"a", "b"}},
		{"a;b", []string{"a", "b"}},
		{"a | b", []string{"a", "b"}},
		{"a |& b", []string{"a", "b"}},
		{"a & b", []string{"a", "b"}},
		{"a\nb", []string{"a", "b"}},
		{"a && b || c ; d | e", []string{"a", "b", "c", "d", "e"}},
		{"  a   &&   b  ", []string{"a", "b"}},
		{"a;\n;b", []string{"a", "b"}},
		{"echo hi &", []string{"echo hi"}}, // a trailing & backgrounds; nothing follows it
	}
	for _, c := range cases {
		if got := subs(t, c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("splitCommand(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// A separator inside quotes is text, not a separator.
func TestSplitCommand_QuotesAndEscapesHideSeparators(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{`echo "a && b"`, []string{`echo "a && b"`}},
		{`echo 'a ; b'`, []string{`echo 'a ; b'`}},
		{`echo "it's" && ls`, []string{`echo "it's"`, "ls"}},
		{`echo 'say "hi"' ; ls`, []string{`echo 'say "hi"'`, "ls"}},
		{`echo a\;b`, []string{`echo a\;b`}},
		{`echo a\&\&b`, []string{`echo a\&\&b`}},
		{`echo "a \" && b"`, []string{`echo "a \" && b"`}},
		{`echo 'a \' && ls`, []string{`echo 'a \'`, "ls"}}, // no escapes inside single quotes
		{`echo $'a\'b' && ls`, []string{`echo $'a\'b'`, "ls"}},
	}
	for _, c := range cases {
		if got := subs(t, c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("splitCommand(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// Deny and ask rules apply to a command nested inside $(...), backticks, a subshell or a
// control-flow body, so the splitter must surface those as subcommands too.
func TestSplitCommand_NestedCommandsAreSubcommands(t *testing.T) {
	cases := []struct {
		in   string
		want []string // every one of these must appear among the subcommands
	}{
		{`echo "$(git clean -f)"`, []string{"git clean -f"}},
		{`echo $(git clean -f)`, []string{"git clean -f"}},
		{"echo `git clean -f`", []string{"git clean -f"}},
		{`(git clean -f)`, []string{"git clean -f"}},
		{`(cd /tmp && git clean -f)`, []string{"cd /tmp", "git clean -f"}},
		{`{ git clean -f; }`, []string{"git clean -f"}},
		{`for f in a b; do git clean -f; done`, []string{"git clean -f"}},
		{`while true; do rm x; done`, []string{"rm x"}},
		{`if ls; then rm x; else echo no; fi`, []string{"rm x"}},
		{`echo $(echo $(rm x))`, []string{"rm x"}},
		{`echo "a $(rm x) b"`, []string{"rm x"}},
		{`diff <(ls a) <(rm x)`, []string{"ls a", "rm x"}},
		{`cat <<<"$(rm x)"`, []string{"rm x"}},
		{`x=$(rm y) ls`, []string{"rm y"}},
		{`echo '$(rm x)'`, nil}, // single quotes: it is text, not a command
	}
	for _, c := range cases {
		p := splitCommand(c.in)
		if !p.ok {
			t.Errorf("splitCommand(%q) unparseable: %s", c.in, p.reason)
			continue
		}
		for _, w := range c.want {
			found := false
			for _, s := range p.subs {
				found = found || s == w
			}
			if !found {
				t.Errorf("splitCommand(%q) = %q, missing nested %q", c.in, p.subs, w)
			}
		}
		if c.want == nil {
			for _, s := range p.subs {
				if s == "rm x" {
					t.Errorf("splitCommand(%q) surfaced a command from inside single quotes: %q", c.in, p.subs)
				}
			}
		}
	}
}

// "When && or || has nothing after it, Claude Code treats the command as unparseable and does
// not split it into subcommands for allow-rule matching."
func TestSplitCommand_ADanglingAndOrIsUnparseable(t *testing.T) {
	for _, in := range []string{"npm test &&", "npm test ||", "npm test && ", "a && b &&", "&& ls", "|| ls"} {
		if p := splitCommand(in); p.ok {
			t.Errorf("splitCommand(%q) = %q, want unparseable", in, p.subs)
		}
	}
	// A trailing ; or & is a valid ending.
	for _, in := range []string{"npm test ;", "npm test &", "npm test;"} {
		if p := splitCommand(in); !p.ok {
			t.Errorf("splitCommand(%q) unparseable (%s), want ok", in, p.reason)
		}
	}
}

func TestSplitCommand_UnbalancedConstructsAreUnparseableNotAPanic(t *testing.T) {
	for _, in := range []string{
		`echo "abc`, `echo 'abc`, `echo $(ls`, "echo `ls", `(ls`, `echo "$(ls"`, `echo ${x`,
		`for x in a; do ls`, `if ls; then echo`, `echo \`, `ls ))`, `ls )`,
	} {
		if p := splitCommand(in); p.ok {
			t.Errorf("splitCommand(%q) = %q, want unparseable", in, p.subs)
		}
	}
}

func TestSplitCommand_EmptyAndBlankAreNotACommand(t *testing.T) {
	for _, in := range []string{"", "   ", "\n\n", ";", " ; ; "} {
		p := splitCommand(in)
		if p.ok && len(p.subs) != 0 {
			t.Errorf("splitCommand(%q) = %q, want no subcommands", in, p.subs)
		}
	}
}

// "Commands longer than 10,000 characters always prompt because they exceed what the analysis
// parses."
func TestSplitCommand_OverTheLengthLimitIsUnparseable(t *testing.T) {
	if p := splitCommand(strings.Repeat("a", maxBashCommandLen)); !p.ok {
		t.Errorf("a command exactly at the limit was refused: %s", p.reason)
	}
	p := splitCommand(strings.Repeat("a", maxBashCommandLen+1))
	if p.ok || !strings.Contains(p.reason, "10,000") {
		t.Errorf("a command over the limit: ok=%v reason=%q", p.ok, p.reason)
	}
}

func TestSplitCommand_HostileInputIsBoundedAndNeverPanics(t *testing.T) {
	in := []string{
		strings.Repeat("$(", 9000) + "ls" + strings.Repeat(")", 9000),
		strings.Repeat("(", 9000),
		strings.Repeat("`", 9999),
		strings.Repeat("\"", 9999),
		strings.Repeat("a && ", 2000) + "b",
		strings.Repeat("\\", 9999),
		strings.Repeat("$(echo ", 3000),
		"\x00\x01\x02 ls \xff\xfe",
		strings.Repeat("'", 9999),
	}
	start := time.Now()
	for _, s := range in {
		_ = splitCommand(s)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("hostile inputs took %v", d)
	}
}

func TestSplitCommand_NestingDepthIsCapped(t *testing.T) {
	deep := strings.Repeat("$(", maxShellNesting+5) + "ls" + strings.Repeat(")", maxShellNesting+5)
	if p := splitCommand(deep); p.ok {
		t.Error("nesting past the cap was accepted: recursion depth must be bounded")
	}
	shallow := strings.Repeat("$(", 5) + "ls" + strings.Repeat(")", 5)
	if p := splitCommand(shallow); !p.ok {
		t.Errorf("modest nesting was refused: %s", p.reason)
	}
}

// --- wrappers ---------------------------------------------------------------------------------

func TestStripWrappers(t *testing.T) {
	cases := []struct {
		in       string
		want     string
		assigned bool // a leading environment assignment was stripped
	}{
		{"npm test", "npm test", false},
		{"timeout 30 npm test", "npm test", false},
		{"time npm test", "npm test", false},
		{"nice npm test", "npm test", false},
		{"nice -n 10 npm test", "npm test", false},
		{"nohup npm test", "npm test", false},
		{"stdbuf -oL npm test", "npm test", false},
		{"command npm test", "npm test", false},
		{"builtin cd /tmp", "cd /tmp", false},
		{"noglob ls *", "ls *", false},
		{"timeout 5 nohup nice npm test", "npm test", false},
		{"xargs grep pattern", "grep pattern", false},
		// not stripped
		{"command -v git", "command -v git", false},
		{"nocorrect ls", "nocorrect ls", false},
		{"xargs -n1 grep pattern", "xargs -n1 grep pattern", false},
		{"watch ls", "watch ls", false},
		{"npx jest", "npx jest", false},
		{"docker exec c ls", "docker exec c ls", false},
		{"devbox run npm test", "devbox run npm test", false},
		// leading assignments
		{"FOO=bar rm -rf tmp/", "rm -rf tmp/", true},
		{"A=1 B=2 rm x", "rm x", true},
		{"NODE_ENV=test npm test", "npm test", true},
		{`FOO="a b" rm x`, "rm x", true},
		// an assignment is only leading
		{"rm FOO=bar", "rm FOO=bar", false},
		{"echo FOO=bar", "echo FOO=bar", false},
	}
	for _, c := range cases {
		got, assigned := stripWrappers(c.in)
		if got != c.want || assigned != c.assigned {
			t.Errorf("stripWrappers(%q) = (%q, %v), want (%q, %v)", c.in, got, assigned, c.want, c.assigned)
		}
	}
}

func TestStripWrappers_TerminatesAndNeverPanics(t *testing.T) {
	for _, in := range []string{"", "timeout", "timeout 5", "nice -n", "xargs", strings.Repeat("timeout 1 ", 5000) + "ls", "A=", "=", "="} {
		_, _ = stripWrappers(in)
	}
}

// Inside double quotes only $( ), backticks and the closing quote are special. The branches that
// handle each are the ones a quoted string can hide a command in.
func TestSplitCommand_DoubleQuotedConstructs(t *testing.T) {
	cases := []struct {
		in       string
		want     []string // among the subcommands
		wantFail bool
	}{
		{`echo "a $(rm x) b"`, []string{"rm x"}, false},
		{"echo \"a `rm x` b\"", []string{"rm x"}, false},
		{`echo "$(echo $(rm x))"`, []string{"rm x"}, false},
		{`echo "arith $((1+2)) done"`, nil, false},
		{`echo "escaped \" quote $(rm y)"`, []string{"rm y"}, false},
		{`echo "tail \`, nil, true},
		{`echo "unterminated $(rm x`, nil, true},
		{`echo "arith $((1+2`, nil, true},
		{"echo \"a `rm x", nil, true},
		{`echo "never closes`, nil, true},
	}
	for _, c := range cases {
		p := splitCommand(c.in)
		if p.ok == c.wantFail {
			t.Errorf("splitCommand(%q) ok=%v, want ok=%v (%s)", c.in, p.ok, !c.wantFail, p.reason)
			continue
		}
		for _, w := range c.want {
			found := false
			for _, s := range p.subs {
				found = found || s == w
			}
			if !found {
				t.Errorf("splitCommand(%q) = %q, missing %q", c.in, p.subs, w)
			}
		}
	}
}

func TestSplitCommand_ArithmeticAndExpansionAreNotCommands(t *testing.T) {
	for _, in := range []string{`echo $((rm x))`, `echo ${rm}`, `echo ${x:-$(ls)}`} {
		p := splitCommand(in)
		if !p.ok {
			t.Errorf("splitCommand(%q) unparseable: %s", in, p.reason)
			continue
		}
		for _, s := range p.subs {
			if s == "rm x" || s == "rm" {
				t.Errorf("splitCommand(%q) surfaced %q as a command", in, s)
			}
		}
	}
}

func TestSplitCommand_DescribesWhatIsUnterminated(t *testing.T) {
	for in, want := range map[string]string{
		"(ls":               "parenthesis",
		"echo `ls":          "backtick",
		"{ ls":              "brace group",
		"echo $(ls":         "parenthesis",
		`echo $'abc`:        "$'",
		"for x in a; do ls": "compound",
	} {
		p := splitCommand(in)
		if p.ok || !strings.Contains(p.reason, want) {
			t.Errorf("splitCommand(%q): ok=%v reason=%q, want a reason mentioning %q", in, p.ok, p.reason, want)
		}
	}
}

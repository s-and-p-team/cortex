package access

import (
	"strings"
	"testing"
	"time"
)

func bash(cmd string) Call { return Call{Tool: "Bash", Input: map[string]any{"command": cmd}} }

// wildcard is the docs' "Wildcard patterns" table, verbatim, as an allow rule: what each rule
// shape matches and what it does not. (permissions, "Wildcard patterns")
func TestBashWildcardTable(t *testing.T) {
	rows := []struct {
		rule    string
		matches []string
		doesNot []string
	}{
		{"Bash(npm run build)", []string{"npm run build"}, []string{"npm run build --watch"}},
		{"Bash(npm run *)", []string{"npm run build", "npm run test --watch", "npm run"}, []string{"npm install"}},
		{"Bash(git log * main)", []string{"git log --oneline main", "git log -5 main", "git log --output=<file> main"}, []string{"git log main", "git push origin main"}},
		{"Bash(git * main)", []string{"git merge main", "git push origin main", "git -c core.fsmonitor=<script> diff main"}, []string{"git log"}},
		{"Bash(* --version)", []string{"node --version", "bash -c 'echo hi' --version"}, []string{"node -v"}},
		{"Bash(ls *)", []string{"ls -la", "ls"}, []string{"lsof"}},
		{"Bash(ls*)", []string{"ls -la", "lsof"}, nil},
		{"Bash(* --help *)", []string{"npm --help x"}, []string{"npm --help"}},
	}
	for _, row := range rows {
		for _, cmd := range row.matches {
			if got := pol(rl(Allow, row.rule)).Match(bash(cmd), MatchContext{}); got.Verdict != VerdictAllow {
				t.Errorf("%s should match %q; verdict %v (%+v)", row.rule, cmd, got.Verdict, got)
			}
		}
		for _, cmd := range row.doesNot {
			if got := pol(rl(Allow, row.rule)).Match(bash(cmd), MatchContext{}); got.Verdict == VerdictAllow {
				t.Errorf("%s should NOT match %q", row.rule, cmd)
			}
		}
	}
}

// The same table as a DENY rule: the match rule is the same, the consequence is not.
func TestBashWildcardTable_AsDeny(t *testing.T) {
	if got := pol(rl(Deny, "Bash(rm *)")).Match(bash("rm -rf build/"), MatchContext{}); got.Verdict != VerdictDeny {
		t.Errorf("verdict %v, want deny", got.Verdict)
	}
	if got := pol(rl(Deny, "Bash(rm *)")).Match(bash("rmdir x"), MatchContext{}); got.Verdict != VerdictNone {
		t.Errorf("rmdir matched Bash(rm *): %v", got.Verdict)
	}
}

// ":*" is an equivalent way to write a trailing wildcard, and is recognised only at the end.
func TestBashColonStar(t *testing.T) {
	for _, tc := range []struct {
		rule, cmd string
		want      bool
	}{
		{"Bash(ls:*)", "ls -la", true},
		{"Bash(ls:*)", "ls", true},
		{"Bash(ls:*)", "lsof", false},
		{"Bash(git:* push)", "git push", false}, // "the colon is treated as a literal character"
		{"Bash(git:* push)", "git:* push", true},
		{"Bash(git:* push)", "git foo push", false},
	} {
		got := pol(rl(Allow, tc.rule)).Match(bash(tc.cmd), MatchContext{}).Verdict == VerdictAllow
		if got != tc.want {
			t.Errorf("%s vs %q = %v, want %v", tc.rule, tc.cmd, got, tc.want)
		}
	}
}

// "What a Bash rule doesn't match" (permissions): a deny or ask rule covers the invocation
// Claude usually produces and is not a security boundary around the program.
func TestBashRuleLimits_FromTheDocs(t *testing.T) {
	rows := []struct {
		rule   string
		stops  string
		doesnt []string
	}{
		{"Bash(curl *)", "curl https://example.com", []string{"/usr/bin/curl https://example.com", "sh -c 'curl https://example.com'"}},
		{"Bash(rm *)", "rm -rf build/", []string{"/bin/rm -rf build/", "bash -c 'rm -rf build/'"}},
		{"Bash(git push *)", "git push origin main", []string{"git -C . push origin main", "git -c push.default=current push origin main", "git 'push' origin main"}},
	}
	for _, row := range rows {
		p := pol(rl(Deny, row.rule))
		if got := p.Match(bash(row.stops), MatchContext{}); got.Verdict != VerdictDeny {
			t.Errorf("%s should stop %q; verdict %v", row.rule, row.stops, got.Verdict)
		}
		for _, cmd := range row.doesnt {
			got := p.Match(bash(cmd), MatchContext{})
			if got.Verdict == VerdictDeny {
				t.Errorf("%s must NOT match %q (the docs say it does not)", row.rule, cmd)
			}
			// ...and the reader must be told, because a deny that does not apply is exactly the
			// surprise this view exists to prevent.
			if !hasCaveat(got, "not a security boundary") {
				t.Errorf("%s vs %q: no caveat that the rule is not a boundary: %q", row.rule, cmd, got.Caveats)
			}
		}
	}
}

func TestBashRuleLimits_NoCaveatWhenTheCommandDoesNotMentionTheProgram(t *testing.T) {
	got := pol(rl(Deny, "Bash(curl *)")).Match(bash("ls -la"), MatchContext{})
	if hasCaveat(got, "not a security boundary") {
		t.Errorf("a caveat on an unrelated command is noise: %q", got.Caveats)
	}
	// A word that merely contains the program name is not the program.
	got = pol(rl(Deny, "Bash(rm *)")).Match(bash("echo format"), MatchContext{})
	if hasCaveat(got, "not a security boundary") {
		t.Errorf("'format' contains 'rm' but is not rm: %q", got.Caveats)
	}
}

// Compound commands. (permissions, "Compound commands")
func TestBashCompound_DenyAndAskApplyToAnySubcommand(t *testing.T) {
	ask := pol(rl(Ask, "Bash(git clean *)"))
	for _, cmd := range []string{
		"git clean -f",
		"cd /tmp && git clean -f",
		`echo "$(git clean -f)"`,
		"echo `git clean -f`",
		"(cd x; git clean -f)",
		"for f in a b; do git clean -f; done",
		"ls | git clean -f",
		"timeout 5 git clean -f",
	} {
		if got := ask.Match(bash(cmd), MatchContext{}); got.Verdict != VerdictAsk {
			t.Errorf("ask Bash(git clean *) vs %q: verdict %v, want ask", cmd, got.Verdict)
		}
	}
	deny := pol(rl(Deny, "Bash(rm *)"))
	for _, cmd := range []string{"ls && rm -rf x", "FOO=bar rm -rf tmp/", "echo a | xargs rm x", "x=1; rm y"} {
		if got := deny.Match(bash(cmd), MatchContext{}); got.Verdict != VerdictDeny {
			t.Errorf("deny Bash(rm *) vs %q: verdict %v, want deny", cmd, got.Verdict)
		}
	}
	if got := deny.Match(bash(`echo '$(rm x)'`), MatchContext{}); got.Verdict == VerdictDeny {
		t.Error("a command inside single quotes is text, not a command")
	}
	if got := deny.Match(bash(`echo "rm -rf x"`), MatchContext{}); got.Verdict == VerdictDeny {
		t.Error("a quoted argument is not a command")
	}
}

func TestBashCompound_AllowNeedsEverySubcommand(t *testing.T) {
	allow := pol(rl(Allow, "Bash(safe-cmd *)"))
	cases := []struct {
		cmd  string
		want Verdict
	}{
		{"safe-cmd", VerdictAllow},
		{"safe-cmd a && safe-cmd b", VerdictAllow},
		{"safe-cmd && other-cmd", VerdictPartial}, // the docs' own example
		{"other-cmd && safe-cmd", VerdictPartial},
		{"other-cmd && another", VerdictNone},
		{"safe-cmd a | safe-cmd b", VerdictAllow},
		{`safe-cmd "$(other-cmd)"`, VerdictPartial},
		{"safe-cmd; other; safe-cmd", VerdictPartial},
	}
	for _, c := range cases {
		got := allow.Match(bash(c.cmd), MatchContext{})
		if got.Verdict != c.want {
			t.Errorf("allow Bash(safe-cmd *) vs %q: verdict %v, want %v (%+v)", c.cmd, got.Verdict, c.want, got)
		}
	}
	// two different allow rules can cover the two halves
	both := pol(rl(Allow, "Bash(a *)"), rl(Allow, "Bash(b *)"))
	if got := both.Match(bash("a x && b y"), MatchContext{}); got.Verdict != VerdictAllow || len(got.Rules) != 2 {
		t.Errorf("two allow rules covering two subcommands: %v rules %d", got.Verdict, len(got.Rules))
	}
}

// A partial result names what is covered and what is not, so the reader can see which
// subcommand decided the outcome.
func TestBashCompound_PartialSaysWhichSubcommandIsUncovered(t *testing.T) {
	got := pol(rl(Allow, "Bash(safe-cmd *)")).Match(bash("safe-cmd && other-cmd"), MatchContext{})
	wantVerdict(t, got, VerdictPartial)
	if !hasCaveat(got, "other-cmd") {
		t.Errorf("caveats = %q, want the uncovered subcommand named", got.Caveats)
	}
	if !hasCaveat(got, "read-only") {
		t.Errorf("caveats = %q, want the read-only set / mode named as the other deciders", got.Caveats)
	}
}

func TestBashCompound_ADanglingOperatorMeansAnAllowDoesNotApprove(t *testing.T) {
	got := pol(rl(Allow, "Bash(npm *)")).Match(bash("npm test &&"), MatchContext{})
	if got.Verdict == VerdictAllow || got.Verdict == VerdictPartial {
		t.Errorf("verdict %v: an unparseable command is not approved by an allow rule", got.Verdict)
	}
	if !hasCaveat(got, "cannot be analysed") || !hasCaveat(got, "ends with && or ||") {
		t.Errorf("caveats = %q, want the failure and its cause said", got.Caveats)
	}
}

// The docs' deny/ask rules still apply to an unparseable command's text where they can: but a
// command we cannot split is one we cannot say a deny does NOT match, so a deny/ask is unknown.
func TestBashUnparseable_NeverLetsAnAllowThroughPastADenyOrAsk(t *testing.T) {
	for _, d := range []Decision{Deny, Ask} {
		p := pol(rl(d, "Bash(rm *)"), rl(Allow, "Bash(echo *)"))
		got := p.Match(bash(`echo "unterminated`), MatchContext{})
		if got.Verdict != VerdictUnknown {
			t.Errorf("%v rule + unparseable command: verdict %v, want unknown", d, got.Verdict)
		}
	}
	// With no deny/ask rule that could apply to Bash, an unparseable command is simply uncovered.
	got := pol(rl(Allow, "Bash(echo *)")).Match(bash(`echo "unterminated`), MatchContext{})
	if got.Verdict == VerdictAllow {
		t.Errorf("verdict %v: an unparseable command must not be allowed", got.Verdict)
	}
}

func TestBashOverTheLengthLimitIsUnknownNotAllowed(t *testing.T) {
	long := "echo " + strings.Repeat("a", maxBashCommandLen)
	got := pol(rl(Allow, "Bash(echo *)")).Match(bash(long), MatchContext{})
	if got.Verdict == VerdictAllow {
		t.Error("a command over 10,000 characters always prompts; it cannot be allowed by a rule")
	}
	if !hasCaveat(got, "10,000") {
		t.Errorf("caveats = %q, want the length limit named", got.Caveats)
	}
	got = pol(rl(Deny, "Bash(rm *)")).Match(bash(long), MatchContext{})
	if got.Verdict != VerdictUnknown {
		t.Errorf("deny rule + over-limit command: verdict %v, want unknown", got.Verdict)
	}
}

// Wrappers: "a rule like Bash(npm test *) also matches timeout 30 npm test".
func TestBashWrappers(t *testing.T) {
	allow := pol(rl(Allow, "Bash(npm test *)"))
	for _, cmd := range []string{
		"timeout 30 npm test", "time npm test", "nice npm test", "nohup npm test",
		"stdbuf -oL npm test", "command npm test", "NODE_ENV=test npm test", "xargs npm test",
	} {
		got := allow.Match(bash(cmd), MatchContext{})
		if got.Verdict != VerdictAllow {
			t.Errorf("Bash(npm test *) vs %q: verdict %v, want allow", cmd, got.Verdict)
		}
	}
	for _, cmd := range []string{"npx npm test", "xargs -n1 npm test", "watch npm test", "docker exec c npm test", "devbox run npm test"} {
		if got := allow.Match(bash(cmd), MatchContext{}); got.Verdict == VerdictAllow {
			t.Errorf("Bash(npm test *) must not match %q: not a stripped wrapper", cmd)
		}
	}
}

// "A deny or ask rule matches past any leading assignment, so Bash(rm *) in deny still matches
// FOO=bar rm -rf tmp/." An allow rule "won't match past an assignment of any other variable".
func TestBashLeadingAssignment_DenyAndAskSeePastIt_AllowDoesNot(t *testing.T) {
	if got := pol(rl(Deny, "Bash(rm *)")).Match(bash("FOO=bar rm -rf tmp/"), MatchContext{}); got.Verdict != VerdictDeny {
		t.Errorf("deny vs FOO=bar rm: %v, want deny", got.Verdict)
	}
	got := pol(rl(Allow, "Bash(rm *)")).Match(bash("FOO=bar rm -rf tmp/"), MatchContext{})
	if got.Verdict == VerdictAllow {
		t.Error("an allow rule matched past an assignment of an arbitrary variable")
	}
	if !hasCaveat(got, "environment variable") {
		t.Errorf("caveats = %q, want the assignment named as the reason", got.Caveats)
	}
}

// Rules with the bare tool or a bare "*" apply to every Bash call, parseable or not.
func TestBashBareRuleMatchesAnythingIncludingUnparseableAndOverLimit(t *testing.T) {
	long := "echo " + strings.Repeat("a", maxBashCommandLen)
	for _, cmd := range []string{"ls", `echo "unterminated`, long, "npm test &&", ""} {
		if got := pol(rl(Deny, "Bash")).Match(bash(cmd), MatchContext{}); got.Verdict != VerdictDeny {
			t.Errorf("bare Bash deny vs %q: %v, want deny", truncate(cmd), got.Verdict)
		}
	}
}

func truncate(s string) string {
	if len(s) > 30 {
		return s[:30] + "…"
	}
	return s
}

// Missing or non-string command.
func TestBashCallWithoutACommand(t *testing.T) {
	for _, c := range []Call{
		{Tool: "Bash"},
		{Tool: "Bash", Input: map[string]any{}},
		{Tool: "Bash", Input: map[string]any{"command": 5}},
		{Tool: "Bash", Input: map[string]any{"command": nil}},
		{Tool: "Bash", Input: map[string]any{"command": []any{"ls"}}},
	} {
		got := pol(rl(Deny, "Bash(rm *)"), rl(Allow, "Bash(ls *)")).Match(c, MatchContext{})
		if got.Verdict == VerdictAllow {
			t.Errorf("%+v: a call with no usable command was allowed", c)
		}
	}
}

// Rule text is untrusted: a cloned repo can write any pattern.
func TestBashPatterns_AreMatchedInLinearTime(t *testing.T) {
	stars := strings.Repeat("*", 5000)
	hostile := []string{
		"Bash(" + stars + ")",
		"Bash(" + strings.Repeat("a*", 3000) + "b)",
		"Bash(" + strings.Repeat("* ", 3000) + ")",
		"Bash(" + stars + "x" + stars + ")",
	}
	cmd := strings.Repeat("a", 4000) + " " + strings.Repeat("a ", 2000)
	start := time.Now()
	for _, r := range hostile {
		for _, d := range []Decision{Deny, Ask, Allow} {
			_ = pol(rl(d, r)).Match(bash(cmd), MatchContext{})
		}
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("hostile patterns took %v; matching must not backtrack exponentially", d)
	}
}

func TestBashWildcardMatcher(t *testing.T) {
	cases := []struct {
		pat, s string
		want   bool
	}{
		{"abc", "abc", true}, {"abc", "abcd", false}, {"a*c", "abbbc", true}, {"a*c", "ac", true},
		{"*", "", true}, {"*", "anything at all", true}, {"a*", "a", true}, {"*a", "ba", true},
		{"a*b*c", "aXbYc", true}, {"a*b*c", "aXcYb", false}, {"", "", true}, {"", "a", false},
		{"**", "x", true}, {"a**b", "ab", true},
	}
	for _, c := range cases {
		if got := globMatch(c.pat, c.s); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", c.pat, c.s, got, c.want)
		}
	}
}

// The docs' own example: Bash(npm test *) matches NODE_ENV=test npm test. NODE_ENV is the only
// variable they name; any other assignment is not assumed safe.
func TestBashAllow_SeesPastNODE_ENVAndNothingElse(t *testing.T) {
	allow := pol(rl(Allow, "Bash(npm test *)"))
	if got := allow.Match(bash("NODE_ENV=test npm test"), MatchContext{}); got.Verdict != VerdictAllow {
		t.Errorf("the docs' own example: verdict %v, want allow", got.Verdict)
	}
	for _, cmd := range []string{"FOO=bar npm test", "NODE_ENV=test FOO=bar npm test", "PATH=/evil npm test", "LD_PRELOAD=x npm test"} {
		got := allow.Match(bash(cmd), MatchContext{})
		if got.Verdict == VerdictAllow {
			t.Errorf("%q: an allow rule matched past an assignment it cannot vouch for", cmd)
		}
		if !hasCaveat(got, "environment variable assignment") {
			t.Errorf("%q: caveats = %q, want the assignment named", cmd, got.Caveats)
		}
	}
	// Deny and ask always see past every assignment.
	for _, v := range []string{"NODE_ENV=test", "FOO=bar", "PATH=/evil"} {
		if got := pol(rl(Deny, "Bash(npm test *)")).Match(bash(v+" npm test"), MatchContext{}); got.Verdict != VerdictDeny {
			t.Errorf("deny vs %s: %v", v, got.Verdict)
		}
	}
}

// A program name that merely sits inside another word is not that program. The caveat fires on a
// WHOLE-word mention only; checking one side of the boundary would flag "format" for rm and
// "farm" for rm, and a caveat that cries wolf is a caveat nobody reads.
func TestMentionsProgram_NeedsBothSidesOfTheBoundary(t *testing.T) {
	cases := []struct {
		cmd, prog string
		want      bool
	}{
		{"rm -rf x", "rm", true},
		{"/bin/rm x", "rm", true},
		{"sh -c 'rm x'", "rm", true},
		{"echo hi; rm x", "rm", true},
		{"(rm x)", "rm", true},
		{"format c:", "rm", false},    // "rm" at the end of the left word? no: inside "format"
		{"farm animals", "rm", false}, // left side is a letter, right side is a boundary
		{"rmdir x", "rm", false},      // left side is a boundary, right side is a letter
		{"alarms", "rm", false},
		{"git-remote-https", "git", true}, // '-' is not a boundary character we treat as a word edge
		{"", "rm", false},
	}
	for _, c := range cases {
		got := mentionsProgram(c.cmd, c.prog)
		// "git-remote-https": '-' is not in the boundary set, so "git" followed by '-' is not a
		// whole-word mention. Pin that as the documented behaviour rather than a coincidence.
		if c.cmd == "git-remote-https" {
			c.want = false
		}
		if got != c.want {
			t.Errorf("mentionsProgram(%q, %q) = %v, want %v", c.cmd, c.prog, got, c.want)
		}
	}
}

func TestBashBoundaryCaveat_DoesNotFireForAnEmbeddedName(t *testing.T) {
	for _, cmd := range []string{"format c:", "farm animals", "rmdir x", "alarms"} {
		got := pol(rl(Deny, "Bash(rm *)")).Match(bash(cmd), MatchContext{})
		if hasCaveat(got, "not a security boundary") {
			t.Errorf("%q: the caveat fired for a name that only sits inside another word: %q", cmd, got.Caveats)
		}
	}
}

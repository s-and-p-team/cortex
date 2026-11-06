package access

import (
	"strings"
	"testing"
	"time"
)

// Read and Edit deny and ask rules apply to files named by the file commands Claude Code
// recognizes inside Bash (cat, head, tail, sed, tee, and, in 1,134 recorded decisions, grep) and
// to redirection targets. The set is not documented in full, so a Bash command that names a
// file such a rule covers is reported unknown, never none: a recorded session had two commands
// rejected by `Read(.env)` and `Read(.env.*)` that a rule-by-rule reading calls unmatched.

func bashDeny(rules ...Rule) Policy { return pol(rules...) }

func readDeny(raw string) Rule {
	r := rl(Deny, raw)
	r.Source = User
	return r
}

var fileCtx = MatchContext{Cwd: "/work/proj", Home: "/home/me", ConfigDir: "/home/me/.claude"}

func TestBashNamingAFileACoveredRuleGuards_IsUnknownNotNone(t *testing.T) {
	p := bashDeny(readDeny("Read(.env)"), readDeny("Read(.env.*)"))
	for _, cmd := range []string{
		`grep -n "MODEL_PROVIDER" .env`,
		`cat .env`,
		`cat ./.env`,
		`cat /work/proj/.env`,
		`cat sub/dir/.env`,         // a bare name matches at any depth under the anchor
		`cat backend/.env.example`, // the second recorded rejection, via Read(.env.*)
		`head -5 .env`,
		`cat ".env"`,
		`cat '.env'`,
		`ls && cat .env`,
		`echo $(cat .env)`,
		`timeout 5 cat .env`,
		`nohup cat .env`,
		`echo x > .env`,
		`echo x >> .env`,
		`cat < .env`,
		`cmd 2>.env`,
		`cmd &> .env`,
		`sed -i s/a/b/ .env`,
		`tee .env`,
	} {
		got := p.Match(bash(cmd), fileCtx)
		if got.Verdict != VerdictUnknown {
			t.Errorf("%q: verdict %v, want unknown\n%+v", cmd, got.Verdict, got)
			continue
		}
		if len(got.Unevaluated) == 0 {
			t.Errorf("%q: unknown without naming a rule", cmd)
		}
		if !hasCaveat(got, "file commands it recognizes") {
			t.Errorf("%q: caveats = %q, want the reason said", cmd, got.Caveats)
		}
	}
}

// The recorded commands, verbatim from the transcripts that showed the gap.
func TestBashNamingAFile_TheTwoRecordedRejections(t *testing.T) {
	p := bashDeny(readDeny("Read(.env)"), readDeny("Read(.env.*)"))
	first := ".venv/bin/python - <<'EOF'\nimport sqlite3,re\nc=sqlite3.connect(\"file:data/app.db?mode=ro\",uri=True)\nEOF\ngrep -n \"MODEL_PROVIDER\" .env 2>/dev/null | sed 's/=.*/=<set>/'"
	second := `podman build -t intro2c-sandbox:latest sandbox/ 2>&1 | tail -5; curl -s localhost:11434/api/tags; grep -n -i "ollama_model\|model_provider" backend/app/config.py backend/.env.example`
	for name, cmd := range map[string]string{"first": first, "second": second} {
		if got := p.Match(bash(cmd), fileCtx).Verdict; got != VerdictUnknown {
			t.Errorf("%s recorded command: verdict %v, want unknown (Claude Code rejected it)", name, got)
		}
	}
}

func TestBashNamingNoCoveredFile_IsUnchanged(t *testing.T) {
	p := bashDeny(readDeny("Read(.env)"), readDeny("Read(.env.*)"), readDeny("Read(**/.ssh/**)"))
	for _, cmd := range []string{
		`ls -la`, `cat README.md`, `grep -n x src/main.go`, `echo hello`, `cat env`, `cat .envrc`,
		`cat dotenv`, `cat sub/.environment`, `git status`,
	} {
		got := p.Match(bash(cmd), fileCtx)
		if got.Verdict != VerdictNone {
			t.Errorf("%q: verdict %v, want none", cmd, got.Verdict)
		}
		if hasCaveat(got, "file commands it recognizes") {
			t.Errorf("%q: a caveat on a command naming no covered file is noise: %q", cmd, got.Caveats)
		}
	}
}

// The program name is not a file argument, and options are not paths.
func TestBashFileWords_SkipTheProgramOptionsAndExpansions(t *testing.T) {
	p := bashDeny(readDeny("Read(.env)"))
	for _, cmd := range []string{`.env`, `.env --help`, `ls --color=.env`, `cat -n`, `cat $F`, `cat "$HOME/.env"`, "cat `echo .env`", `cat *.env`, `cat .en?`, `cat .e[n]v`} {
		got := p.Match(bash(cmd), fileCtx)
		if got.Verdict == VerdictUnknown && !strings.Contains(cmd, "$") && !strings.ContainsAny(cmd, "*?[`") {
			t.Errorf("%q: unknown, but it names no literal covered file", cmd)
		}
	}
	// ...and a command whose file arguments were built from expansions says the check is partial
	got := p.Match(bash(`cat $F`), fileCtx)
	if got.Verdict != VerdictNone || !hasCaveat(got, "variable or glob") {
		t.Errorf("`cat $F`: verdict %v caveats %q, want none with the expansion limit said", got.Verdict, got.Caveats)
	}
}

func TestBashFileWords_OnlyReadAndEditDenyAndAskRulesApply(t *testing.T) {
	allow := rl(Allow, "Read(.env)")
	allow.Source = User
	if got := pol(allow).Match(bash(`cat .env`), fileCtx); got.Verdict != VerdictNone {
		t.Errorf("a Read allow rule changed a Bash verdict: %v", got.Verdict)
	}
	ask := rl(Ask, "Edit(src/**)")
	ask.Source = Project
	if got := pol(ask).Match(bash(`sed -i s/a/b/ src/app.ts`), fileCtx); got.Verdict != VerdictUnknown {
		t.Errorf("an Edit ask rule vs sed -i on src/app.ts: %v, want unknown", got.Verdict)
	}
	// Write/Grep/Glob path rules never match anything, so they cannot guard a Bash command either
	w := rl(Deny, "Write(docs/**)")
	if got := pol(w).Match(bash(`cat docs/a.md`), fileCtx); got.Verdict != VerdictNone {
		t.Errorf("a Write(path) rule vs Bash: %v, want none", got.Verdict)
	}
	// a bare Read deny removes the Read TOOL; it says nothing about a file named in a command
	if got := pol(rl(Deny, "Read")).Match(bash(`cat .env`), fileCtx); got.Verdict != VerdictNone {
		t.Errorf("a bare Read deny vs Bash: %v, want none", got.Verdict)
	}
}

// With no working directory a cwd-anchored rule cannot be located, so a RELATIVE word is
// unlocatable too: `hello` could be `<cwd>/.env` for all this view knows about <cwd>. That is the
// conservative answer, and it is reported as unknown with the reason, not guessed. A command
// naming no file-like word at all has nothing to locate, and an absolute rule needs no cwd.
func TestBashFileWords_AnUnlocatableAnchorIsUnknownOnlyWhenAWordNeedsIt(t *testing.T) {
	ctx := MatchContext{Home: "/home/me"} // no cwd
	p := bashDeny(readDeny("Read(./.env)"))
	// Every non-option word after the program is a possible file, so `status` in `git status` and
	// `hello` in `echo hello` are as unlocatable as `.env`. That is the price of not knowing which
	// commands Claude Code treats as file commands.
	for _, cmd := range []string{`cat .env`, `echo hello`, `git status`} {
		got := p.Match(bash(cmd), ctx)
		if got.Verdict != VerdictUnknown {
			t.Errorf("%q with no cwd: %v, want unknown", cmd, got.Verdict)
		}
		if !hasCaveat(got, "working directory is unknown") {
			t.Errorf("%q: caveats = %q, want the missing cwd named", cmd, got.Caveats)
		}
	}
	for _, cmd := range []string{`ls`, `pwd`, `git`, `ls -la`, `ls --color`} {
		if got := p.Match(bash(cmd), ctx).Verdict; got != VerdictNone {
			t.Errorf("%q has no argument that could be a file: %v, want none", cmd, got)
		}
	}
	// a rule that needs no cwd still evaluates
	abs := bashDeny(readDeny("Read(//etc/**)"))
	if got := abs.Match(bash(`cat /etc/passwd`), ctx).Verdict; got != VerdictUnknown {
		t.Errorf("an absolute rule and an absolute file: %v, want unknown (it is guarded)", got)
	}
	if got := abs.Match(bash(`cat /usr/bin/x`), ctx).Verdict; got != VerdictNone {
		t.Errorf("an absolute rule and a file outside it: %v, want none", got)
	}
}

func TestBashFileWords_SyntaxItCannotEvaluateIsSkippedWithANote(t *testing.T) {
	p := bashDeny(readDeny("Read(!sample.env)"))
	got := p.Match(bash(`cat sample.env`), fileCtx)
	if got.Verdict == VerdictAllow {
		t.Errorf("verdict %v", got.Verdict)
	}
	if !hasCaveat(got, "Read(!sample.env)") {
		t.Errorf("caveats = %q, want the unevaluated rule named", got.Caveats)
	}
}

func TestBashFileWords_AnAllowedCommandIsStillUnknownIfItNamesAGuardedFile(t *testing.T) {
	p := bashDeny(readDeny("Read(.env)"), rl(Allow, "Bash(grep *)"))
	if got := p.Match(bash(`grep -n x .env`), fileCtx); got.Verdict != VerdictUnknown {
		t.Errorf("an allow rule for grep must not hide a Read deny on the file: %v", got.Verdict)
	}
	if got := p.Match(bash(`grep -n x main.go`), fileCtx); got.Verdict != VerdictAllow {
		t.Errorf("the same rule for an unguarded file: %v, want allow", got.Verdict)
	}
}

func TestBashFileWords_HostileCommandsAreBounded(t *testing.T) {
	rules := make([]Rule, 0, 200)
	for i := 0; i < 200; i++ {
		rules = append(rules, readDeny("Read(dir"+strings.Repeat("x", i%7)+"/**/f"+strings.Repeat("*", 50)+")"))
	}
	p := bashDeny(rules...)
	manyWords := "cat " + strings.Repeat("a/b/c ", 1500)
	start := time.Now()
	got := p.Match(bash(manyWords), fileCtx)
	_ = p.Match(bash("cat "+strings.Repeat("x", 9000)), fileCtx)
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("hostile commands took %v", d)
	}
	if got.Verdict == VerdictAllow {
		t.Errorf("verdict %v for an oversized word list", got.Verdict)
	}
	// past the word cap the check is declared incomplete, not silently truncated
	if !hasCaveat(got, "too many") && got.Verdict != VerdictUnknown {
		t.Errorf("caveats = %q: truncating the word list without saying so hides a guarded file", got.Caveats)
	}
}

func TestBashFileWords_Extraction(t *testing.T) {
	cases := []struct {
		cmd     string
		want    []string
		skipped bool
	}{
		{`cat a b`, []string{"a", "b"}, false},
		{`cat -n a`, []string{"a"}, false},
		{`cat "a b"`, []string{"a b"}, false},
		{`cat 'x'`, []string{"x"}, false},
		{`echo hi > out.txt`, []string{"hi", "out.txt"}, false},
		{`echo hi >> out.txt`, []string{"hi", "out.txt"}, false},
		{`echo hi >out.txt`, []string{"hi", "out.txt"}, false},
		{`cmd 2>err.log`, []string{"err.log"}, false},
		{`cmd &>all.log`, []string{"all.log"}, false},
		{`cat < in.txt`, []string{"in.txt"}, false},
		{`a x && b y | c z`, []string{"x", "y", "z"}, false},
		{`cat $F`, nil, true},
		{`cat a*`, nil, true},
		{`cat --flag=x`, nil, false},
		{`timeout 5 cat a`, []string{"a"}, false},
		{`FOO=bar cat a`, []string{"a"}, false},
	}
	for _, c := range cases {
		got, skipped, ok := bashFileWords(c.cmd)
		if !ok {
			t.Errorf("%q: not ok", c.cmd)
			continue
		}
		if strings.Join(got, "|") != strings.Join(c.want, "|") || skipped != c.skipped {
			t.Errorf("bashFileWords(%q) = %q skipped=%v, want %q skipped=%v", c.cmd, got, skipped, c.want, c.skipped)
		}
	}
	if _, _, ok := bashFileWords(`echo "unterminated`); ok {
		t.Error("an unparseable command yielded words")
	}
}

// An allow rule is not a guard. Treating Read(.env) in allow as a guard would turn every command
// that names .env into "unknown" because of a rule that can only ever permit.
func TestBashFileGuard_AnAllowRuleIsNotAGuard(t *testing.T) {
	a := rl(Allow, "Read(.env)")
	a.Source = User
	for _, cmd := range []string{`cat .env`, `grep x .env`} {
		got := pol(a).Match(bash(cmd), fileCtx)
		if got.Verdict != VerdictNone || len(got.Unevaluated) != 0 {
			t.Errorf("%q with only a Read allow rule: %v unevaluated=%d, want none and nothing unevaluated", cmd, got.Verdict, len(got.Unevaluated))
		}
	}
	// alongside a real deny the allow adds nothing
	p := pol(a, readDeny("Read(.env)"))
	if got := p.Match(bash(`cat .env`), fileCtx); len(got.Unevaluated) != 1 || got.Unevaluated[0].Decision != Deny {
		t.Errorf("unevaluated = %+v, want just the deny", got.Unevaluated)
	}
}

// A rule voided by managed policy does not apply, so it cannot guard anything.
func TestBashFileGuard_AnIgnoredRuleIsNotAGuard(t *testing.T) {
	r := readDeny("Read(.env)")
	r.Ignored = "ignored: allowManagedPermissionRulesOnly is set in managed settings"
	if got := pol(r).Match(bash(`cat .env`), fileCtx); got.Verdict != VerdictNone || len(got.Unevaluated) != 0 {
		t.Errorf("an ignored deny guarded a file: %v unevaluated=%d", got.Verdict, len(got.Unevaluated))
	}
}

// "> file" with a space is the common spelling; the target is the NEXT word.
func TestBashFileGuard_ASpacedRedirectTargetIsChecked(t *testing.T) {
	p := bashDeny(readDeny("Read(.env)"))
	for _, cmd := range []string{`echo x > .env`, `echo x >> .env`, `cat < .env`, `cmd 2> .env`, `cmd &> .env`, `cmd >| .env`} {
		if got := p.Match(bash(cmd), fileCtx).Verdict; got != VerdictUnknown {
			t.Errorf("%q: %v, want unknown", cmd, got)
		}
	}
	if got := p.Match(bash(`echo x > out.txt`), fileCtx).Verdict; got != VerdictNone {
		t.Errorf("a redirect to an unguarded file: %v, want none", got)
	}
}

// 2>&1 duplicates a file descriptor. The "1" is not a file, and a rule on a file named 1 must
// not make every command with 2>&1 unknown.
func TestBashFileGuard_DescriptorDuplicationIsNotAFile(t *testing.T) {
	p := bashDeny(readDeny("Read(1)"), readDeny("Read(2)"), readDeny("Read(&1)"))
	for _, cmd := range []string{`cmd 2>&1`, `cmd >&2`, `cmd <&0`, `cmd 2>&1 | tail -5`, `cmd &>/dev/null`} {
		if cmd == `cmd &>/dev/null` {
			continue
		}
		if got := p.Match(bash(cmd), fileCtx); got.Verdict != VerdictNone {
			t.Errorf("%q: %v, want none: a descriptor is not a file", cmd, got.Verdict)
		}
	}
	// ...but a genuinely named file 1 still counts
	if got := p.Match(bash(`cat 1`), fileCtx).Verdict; got != VerdictUnknown {
		t.Errorf("`cat 1` names a file called 1 that Read(1) guards: %v, want unknown", got)
	}
}

// The guard is an unevaluated rule of ITS decision. A matching DENY must still win over an ask
// guard, and an ask guard must not be hidden by a matching allow.
func TestBashFileGuard_RespectsTheDecisionOrder(t *testing.T) {
	denyBash := rl(Deny, "Bash(cat *)")
	askFile := rl(Ask, "Read(.env)")
	askFile.Source = Project
	got := pol(denyBash, askFile).Match(bash(`cat .env`), fileCtx)
	if got.Verdict != VerdictDeny {
		t.Errorf("a matching Bash deny with an ask file guard: %v, want deny", got.Verdict)
	}
	allowBash := rl(Allow, "Bash(cat *)")
	got = pol(allowBash, askFile).Match(bash(`cat .env`), fileCtx)
	if got.Verdict != VerdictUnknown {
		t.Errorf("an allow for cat with an ask guard on .env: %v, want unknown (the ask might have fired)", got.Verdict)
	}
	// a DENY guard outranks an ask that matches
	askBash := rl(Ask, "Bash(cat *)")
	got = pol(askBash, readDeny("Read(.env)")).Match(bash(`cat .env`), fileCtx)
	if got.Verdict != VerdictUnknown {
		t.Errorf("an ask match under a deny guard: %v, want unknown (the deny might have fired first)", got.Verdict)
	}
}

func TestBashFileGuard_AnEditRuleGuardsToo(t *testing.T) {
	r := rl(Ask, "Edit(src/**)")
	r.Source = Project
	if got := pol(r).Match(bash(`sed -i s/a/b/ src/app.ts`), fileCtx); got.Verdict != VerdictUnknown {
		t.Errorf("%v, want unknown", got.Verdict)
	}
	if got := pol(r).Match(bash(`sed -i s/a/b/ lib/app.ts`), fileCtx); got.Verdict != VerdictNone {
		t.Errorf("a file outside the rule: %v, want none", got.Verdict)
	}
}

func TestBashFileGuard_AnUnparseableCommandIsNotAlsoGuardedTwice(t *testing.T) {
	// The Bash rules already make an unparseable command unknown; the file guard adds nothing.
	p := bashDeny(readDeny("Read(.env)"), rl(Deny, "Bash(rm *)"))
	got := p.Match(bash(`cat .env "unterminated`), fileCtx)
	if got.Verdict != VerdictUnknown {
		t.Errorf("%v, want unknown", got.Verdict)
	}
	for _, r := range got.Unevaluated {
		if r.Raw == "Read(.env)" {
			t.Errorf("the file guard fired on a command it could not read: %+v", got.Unevaluated)
		}
	}
}

func TestBashFileGuard_NoGuardRulesMeansNoWork(t *testing.T) {
	// A policy with only Bash rules must not pay for word extraction or change any verdict.
	p := pol(rl(Deny, "Bash(rm *)"), rl(Allow, "Bash(ls *)"))
	if f, u, cv := bashNamedFileGuard(p.Rules, bash(`cat .env`), fileCtx); f != nil || u != nil || cv != nil {
		t.Errorf("guard = %v %v %v with no Read/Edit rules", f, u, cv)
	}
}

// A redirect target is a file even when it looks like an option: `echo x > -secret` writes a file
// called -secret. Reading it as an ordinary word would skip it as a flag.
func TestBashFileGuard_ARedirectTargetThatLooksLikeAnOptionIsStillAFile(t *testing.T) {
	p := bashDeny(readDeny("Read(-secret)"))
	if got := p.Match(bash(`echo x > -secret`), fileCtx).Verdict; got != VerdictUnknown {
		t.Errorf("a redirect to a file named -secret: %v, want unknown", got)
	}
	if got := p.Match(bash(`echo x >-secret`), fileCtx).Verdict; got != VerdictUnknown {
		t.Errorf("the unspaced form: %v, want unknown", got)
	}
	// ...whereas as an ordinary argument it is an option, not a file
	if got := p.Match(bash(`ls -secret`), fileCtx).Verdict; got != VerdictNone {
		t.Errorf("an option named -secret: %v, want none", got)
	}
}

// A guard only counts at its own decision's stage. When a deny already decided the call, an ask
// guard is irrelevant and must not be reported as something that could not be evaluated.
func TestBashFileGuard_ALowerDecisionGuardIsNotReportedPastAHigherMatch(t *testing.T) {
	askFile := rl(Ask, "Read(.env)")
	askFile.Source = Project
	got := pol(rl(Deny, "Bash(cat *)"), askFile).Match(bash(`cat .env`), fileCtx)
	if got.Verdict != VerdictDeny {
		t.Fatalf("verdict %v, want deny", got.Verdict)
	}
	if len(got.Unevaluated) != 0 {
		t.Errorf("unevaluated = %+v: an ask guard cannot change a deny that already matched", got.Unevaluated)
	}
	// and the unknown reports the DECISION of the guard that made it unknown
	got = pol(askFile).Match(bash(`cat .env`), fileCtx)
	if got.Verdict != VerdictUnknown || !hasCaveat(got, "a ask rule could not be evaluated") {
		t.Errorf("verdict %v caveats %q, want unknown naming an ask rule", got.Verdict, got.Caveats)
	}
	got = pol(readDeny("Read(.env)")).Match(bash(`cat .env`), fileCtx)
	if !hasCaveat(got, "a deny rule could not be evaluated") {
		t.Errorf("caveats %q, want the deny named", got.Caveats)
	}
}

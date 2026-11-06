package access

import (
	"strings"
	"testing"
	"time"
)

var pctx = MatchContext{Cwd: "/work/proj", Home: "/home/me", ConfigDir: "/home/me/.claude"}

func fileCall(tool, path string) Call {
	return Call{Tool: tool, Input: map[string]any{"file_path": path}}
}

func pathRule(d Decision, raw string, src LayerKind) Rule {
	r := rl(d, raw)
	r.Source = src
	return r
}

func verdictFor(p Policy, c Call) Verdict { return p.Match(c, pctx).Verdict }

// "How deep a pattern matches" (permissions): bare filenames follow gitignore and match at any
// depth under the anchor.
func TestPath_BareFilenamesMatchAtAnyDepth(t *testing.T) {
	for _, rule := range []string{"Read(.env)", "Read(**/.env)"} {
		p := pol(pathRule(Deny, rule, Project))
		for path, want := range map[string]Verdict{
			"/work/proj/.env":       VerdictDeny,
			"/work/proj/a/b/.env":   VerdictDeny,
			"/work/.env":            VerdictNone, // a parent directory
			"/work/other/.env":      VerdictNone, // another project
			"/work/proj/.env.local": VerdictNone,
			"/work/proj/x.env":      VerdictNone,
		} {
			if got := verdictFor(p, fileCall("Read", path)); got != want {
				t.Errorf("%s vs %s = %v, want %v", rule, path, got, want)
			}
		}
	}
	// Read(//**/.env) is anchored at the filesystem root: any .env anywhere.
	p := pol(pathRule(Deny, "Read(//**/.env)", Project))
	for _, path := range []string{"/work/.env", "/etc/x/.env", "/work/proj/a/.env", "/.env"} {
		if got := verdictFor(p, fileCall("Read", path)); got != VerdictDeny {
			t.Errorf("Read(//**/.env) vs %s = %v, want deny", path, got)
		}
	}
}

// The docs' second table: a single-segment directory pattern matches at a different depth
// depending on the rule type.
//
//	<cwd>/src/app.ts          and          <cwd>/vendor/pkg/src/lib.js
func TestPath_DirectoryPatternDepthDependsOnTheRuleType(t *testing.T) {
	type row struct {
		rule      string
		d         Decision
		src, deep bool // matches src/app.ts, matches vendor/pkg/src/lib.js
	}
	for _, r := range []row{
		{"Edit(src/**)", Allow, true, false},
		{"Edit(src/**)", Deny, true, true},
		{"Edit(src/**)", Ask, true, true},
		{"Edit(/src/**)", Allow, true, false},
		{"Edit(/src/**)", Deny, true, false},
		{"Edit(/src/**)", Ask, true, false},
		{"Edit(**/src/**)", Allow, true, true},
		{"Edit(**/src/**)", Deny, true, true},
		{"Edit(**/src/**)", Ask, true, true},
	} {
		p := pol(pathRule(r.d, r.rule, Project))
		for path, want := range map[string]bool{"/work/proj/src/app.ts": r.src, "/work/proj/vendor/pkg/src/lib.js": r.deep} {
			got := verdictFor(p, fileCall("Edit", path)) == verdictOf(r.d)
			if got != want {
				t.Errorf("%v %s vs %s: matched=%v, want %v", r.d, r.rule, path, got, want)
			}
		}
	}
}

// The anchor table: where "/path" resolves depends on which settings source defines the rule.
func TestPath_SlashPatternAnchorsAtTheSettingsSource(t *testing.T) {
	cases := []struct {
		src     LayerKind
		path    string
		matches bool
	}{
		{Project, "/work/proj/secrets/k", true},
		{Project, "/home/me/.claude/secrets/k", false},
		{Local, "/work/proj/secrets/k", true},
		{Local, "/home/me/.claude/secrets/k", false},
		// a user-settings /secrets/** blocks ~/.claude/secrets/**, NOT a secrets directory in the project
		{User, "/home/me/.claude/secrets/k", true},
		{User, "/work/proj/secrets/k", false},
		{Managed, "/work/proj/secrets/k", true},
		{CLI, "/work/proj/secrets/k", true},
	}
	for _, c := range cases {
		got := verdictFor(pol(pathRule(Deny, "Read(/secrets/**)", c.src)), fileCall("Read", c.path)) == VerdictDeny
		if got != c.matches {
			t.Errorf("Read(/secrets/**) from %v settings vs %s: matched=%v, want %v", c.src, c.path, got, c.matches)
		}
	}
}

func TestPath_SlashPatternInAUserFileUsesTheConfigDirNotHome(t *testing.T) {
	ctx := MatchContext{Cwd: "/work/proj", Home: "/home/me", ConfigDir: "/alt/claude"}
	p := pol(pathRule(Deny, "Read(/secrets/**)", User))
	if got := p.Match(fileCall("Read", "/alt/claude/secrets/k"), ctx).Verdict; got != VerdictDeny {
		t.Errorf("a relocated config dir: %v, want deny", got)
	}
	if got := p.Match(fileCall("Read", "/home/me/.claude/secrets/k"), ctx).Verdict; got != VerdictNone {
		t.Errorf("the default ~/.claude must not be used when CLAUDE_CONFIG_DIR moved it: %v", got)
	}
}

func TestPath_HomeAndAbsoluteAnchors(t *testing.T) {
	for _, c := range []struct {
		rule, path string
		want       bool
	}{
		{"Read(~/Documents/*.pdf)", "/home/me/Documents/a.pdf", true},
		{"Read(~/Documents/*.pdf)", "/home/me/Documents/sub/a.pdf", false}, // * does not cross directories
		{"Read(~/.zshrc)", "/home/me/.zshrc", true},
		{"Read(~/.zshrc)", "/home/other/.zshrc", false},
		{"Read(//Users/alice/secrets/**)", "/Users/alice/secrets/k", true},
		{"Read(//Users/alice/secrets/**)", "/Users/bob/secrets/k", false},
		{"Edit(//tmp/scratch.txt)", "/tmp/scratch.txt", true},
		{"Edit(//tmp/scratch.txt)", "/tmp/other.txt", false},
		// "A pattern like /Users/alice/file isn't an absolute path": it anchors at the settings source.
		{"Read(/Users/alice/file)", "/Users/alice/file", false},
		{"Read(/Users/alice/file)", "/work/proj/Users/alice/file", true},
	} {
		tool, _, _ := strings.Cut(c.rule, "(")
		got := verdictFor(pol(pathRule(Deny, c.rule, Project)), fileCall(tool, c.path)) == VerdictDeny
		if got != c.want {
			t.Errorf("%s vs %s: matched=%v, want %v", c.rule, c.path, got, c.want)
		}
	}
}

func TestPath_RelativePatternsAreRelativeToCwd(t *testing.T) {
	for _, c := range []struct {
		rule, path string
		want       bool
	}{
		{"Read(*.env)", "/work/proj/a.env", true},
		{"Read(*.env)", "/work/proj/deep/a.env", true}, // bare filename shape: any depth
		{"Read(./.env)", "/work/proj/.env", true},
		{"Read(./.env)", "/work/proj/a/.env", false}, // ./ pins the anchor: not a bare filename
		{"Read(src/components/**)", "/work/proj/src/components/a.tsx", true},
		{"Read(src/components/**)", "/work/proj/x/src/components/a.tsx", false}, // multi-segment: only at the anchor
		{"Read(docs/*.md)", "/work/proj/docs/a.md", true},
		{"Read(docs/*.md)", "/work/proj/docs/sub/a.md", false},
	} {
		got := verdictFor(pol(pathRule(Deny, c.rule, Project)), fileCall("Read", c.path)) == VerdictDeny
		if got != c.want {
			t.Errorf("%s vs %s: matched=%v, want %v", c.rule, c.path, got, c.want)
		}
	}
}

func TestPath_RelativeCallPathsResolveAgainstCwd(t *testing.T) {
	p := pol(pathRule(Deny, "Read(./.env)", Project))
	for _, path := range []string{".env", "./.env", "sub/../.env", "/work/proj/.env"} {
		if got := verdictFor(p, fileCall("Read", path)); got != VerdictDeny {
			t.Errorf("%q: %v, want deny", path, got)
		}
	}
	// `..` traversal out of the anchor is outside it.
	if got := verdictFor(p, fileCall("Read", "../.env")); got != VerdictNone {
		t.Errorf("../.env escapes the anchor but matched: %v", got)
	}
	if got := verdictFor(pol(pathRule(Deny, "Read(**/.env)", Project)), fileCall("Read", "/work/proj/../other/.env")); got != VerdictNone {
		t.Errorf("a path that cleans to outside the anchor matched: %v", got)
	}
}

func TestPath_ThePathFieldDependsOnTheTool(t *testing.T) {
	deny := func(tool string) Policy { return pol(pathRule(Deny, tool+"(**/secret)", Project)) }
	cases := []struct {
		tool  string
		input map[string]any
		want  Verdict
	}{
		{"Read", map[string]any{"file_path": "/work/proj/a/secret"}, VerdictDeny},
		{"Edit", map[string]any{"file_path": "/work/proj/a/secret"}, VerdictDeny},
		{"NotebookEdit", map[string]any{"notebook_path": "/work/proj/a/secret"}, VerdictNone}, // Edit(…) rules are the ones that apply
	}
	for _, c := range cases {
		if got := deny(c.tool).Match(Call{Tool: c.tool, Input: c.input}, pctx).Verdict; got != c.want {
			t.Errorf("%s %v: %v, want %v", c.tool, c.input, got, c.want)
		}
	}
	// an Edit rule applies to NotebookEdit through notebook_path, and to Write through file_path
	e := pol(pathRule(Deny, "Edit(**/secret)", Project))
	if got := e.Match(Call{Tool: "NotebookEdit", Input: map[string]any{"notebook_path": "/work/proj/a/secret"}}, pctx).Verdict; got != VerdictDeny {
		t.Errorf("Edit rule vs NotebookEdit(notebook_path): %v, want deny", got)
	}
	if got := e.Match(Call{Tool: "Write", Input: map[string]any{"file_path": "/work/proj/a/secret"}}, pctx).Verdict; got != VerdictDeny {
		t.Errorf("Edit rule vs Write: %v, want deny", got)
	}
	// Grep and Glob carry the path they search
	r := pol(pathRule(Deny, "Read(secrets/**)", Project))
	for _, tool := range []string{"Grep", "Glob"} {
		got := r.Match(Call{Tool: tool, Input: map[string]any{"path": "/work/proj/secrets/a"}}, pctx)
		if got.Verdict != VerdictDeny {
			t.Errorf("%s with path: %v, want deny (best effort)", tool, got.Verdict)
		}
	}
	// a Read deny blocks Edit and Write on the same path
	rd := pol(pathRule(Deny, "Read(./.env)", Project))
	for _, tool := range []string{"Edit", "Write"} {
		if got := rd.Match(fileCall(tool, "/work/proj/.env"), pctx).Verdict; got != VerdictDeny {
			t.Errorf("Read deny vs %s: %v, want deny", tool, got)
		}
	}
}

func TestPath_ACallWithNoUsablePathIsUnknownForDenyAndAskAndNoneForAllow(t *testing.T) {
	noPath := []Call{
		{Tool: "Read"}, {Tool: "Read", Input: map[string]any{}},
		{Tool: "Read", Input: map[string]any{"file_path": 5}},
		{Tool: "Read", Input: map[string]any{"file_path": ""}},
	}
	for _, c := range noPath {
		for _, d := range []Decision{Deny, Ask} {
			if got := pol(pathRule(d, "Read(./.env)", Project)).Match(c, pctx).Verdict; got != VerdictUnknown {
				t.Errorf("%v rule vs %+v: %v, want unknown", d, c.Input, got)
			}
		}
		if got := pol(pathRule(Allow, "Read(./.env)", Project)).Match(c, pctx).Verdict; got == VerdictAllow {
			t.Errorf("an allow rule approved a call with no path: %+v", c.Input)
		}
	}
}

// With an unknown cwd, a relative or cwd-anchored rule cannot be located: say so.
func TestPath_AnUnknownCwdMakesCwdAnchoredRulesUnevaluable(t *testing.T) {
	ctx := MatchContext{Home: "/home/me", ConfigDir: "/home/me/.claude"}
	for _, rule := range []string{"Read(./.env)", "Read(.env)", "Read(src/**)", "Read(/src/**)"} {
		got := pol(pathRule(Deny, rule, Project)).Match(fileCall("Read", "/work/proj/.env"), ctx)
		if got.Verdict != VerdictUnknown {
			t.Errorf("%s with no cwd: %v, want unknown", rule, got.Verdict)
		}
	}
	// ...but rules that do not need the cwd still evaluate
	if got := pol(pathRule(Deny, "Read(//etc/**)", Project)).Match(fileCall("Read", "/etc/passwd"), ctx).Verdict; got != VerdictDeny {
		t.Errorf("an absolute rule needs no cwd: %v", got)
	}
	if got := pol(pathRule(Deny, "Read(~/x)", Project)).Match(fileCall("Read", "/home/me/x"), ctx).Verdict; got != VerdictDeny {
		t.Errorf("a home rule needs no cwd: %v", got)
	}
	// a relative CALL path with no cwd is unresolvable
	if got := pol(pathRule(Deny, "Read(//etc/**)", Project)).Match(fileCall("Read", "etc/x"), ctx).Verdict; got != VerdictUnknown {
		t.Errorf("a relative call path with no cwd: %v, want unknown", got)
	}
}

// Syntax outside the supported subset is reported, never guessed.
func TestPath_UnsupportedSyntaxIsUnevaluableForDenyAndAsk(t *testing.T) {
	for _, rule := range []string{"Read(!sample.env)", "Read(*.[ch])", `Read(a\*b)`, "Read(src/[abc]/x)"} {
		for _, d := range []Decision{Deny, Ask} {
			got := pol(pathRule(d, rule, Project)).Match(fileCall("Read", "/work/proj/x"), pctx)
			if got.Verdict != VerdictUnknown || len(got.Unevaluated) != 1 {
				t.Errorf("%v %s: %v, want unknown naming the rule", d, rule, got.Verdict)
			}
		}
		// an unusable allow pattern "doesn't approve anything": it is not an allow, and cannot raise the answer
		if got := pol(pathRule(Allow, rule, Project)).Match(fileCall("Read", "/work/proj/x"), pctx).Verdict; got == VerdictAllow {
			t.Errorf("allow %s approved something", rule)
		}
	}
}

func TestPath_GlobSemantics(t *testing.T) {
	cases := []struct {
		pat, path string
		want      bool
	}{
		{"a/*.go", "a/b.go", true}, {"a/*.go", "a/b/c.go", false}, {"a/**/c.go", "a/c.go", true},
		{"a/**/c.go", "a/b/c.go", true}, {"a/**/c.go", "a/b/d/c.go", true}, {"a/**", "a/b/c", true},
		{"a/**", "a", true}, // "a trailing /** also matches its named root" (Cd) - and gitignore's dir match
		{"a/?.go", "a/b.go", true}, {"a/?.go", "a/bb.go", false}, {"*", "x", true}, {"*", "x/y", false},
		{"**", "x/y/z", true}, {"a/*", "a/b", true}, {"a/*", "a", false},
		{"**/b", "b", true}, {"**/b", "a/b", true}, {"**/b", "a/c/b", true},
	}
	for _, c := range cases {
		if got := pathGlob(c.pat, c.path); got != c.want {
			t.Errorf("pathGlob(%q, %q) = %v, want %v", c.pat, c.path, got, c.want)
		}
	}
}

func TestPath_HostileInputIsBounded(t *testing.T) {
	// 250 x 250 is the largest table evaluated (maxPathGlobCells); these are far past it. The
	// budget is generous because the suite also runs under -race -cover, ~75x slower.
	stars := strings.Repeat("*/", 3000) + "x"
	deepPath := "/work/proj/" + strings.Repeat("a/", 3000) + "x"
	start := time.Now()
	for _, rule := range []string{"Read(" + stars + ")", "Read(**/" + strings.Repeat("**/", 2000) + "x)", "Read(" + strings.Repeat("*", 10000) + ")", "Read(" + strings.Repeat("a*", 4000) + "b)"} {
		for _, d := range []Decision{Deny, Ask, Allow} {
			_ = pol(pathRule(d, rule, Project)).Match(fileCall("Read", deepPath), pctx)
		}
	}
	_ = pol(pathRule(Deny, "Read(**/x)", Project)).Match(fileCall("Read", "/work/proj/"+strings.Repeat("a", 200000)), pctx)
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("hostile path rules took %v", d)
	}
}

// Past the bound a rule is "not evaluated", never "does not match": a deny the matcher gave up
// on might be the deny.
func TestPath_ARuleTooLargeToEvaluateIsUnknownNotAMiss(t *testing.T) {
	big := "Read(" + strings.Repeat("*/", 300) + "x)"
	deep := "/work/proj/" + strings.Repeat("a/", 300) + "x"
	for _, d := range []Decision{Deny, Ask} {
		got := pol(pathRule(d, big, Project)).Match(fileCall("Read", deep), pctx)
		if got.Verdict != VerdictUnknown || !hasCaveat(got, "too large") {
			t.Errorf("%v: verdict %v caveats %q, want unknown and the size said", d, got.Verdict, got.Caveats)
		}
	}
	// an allow of that size approves nothing
	if got := pol(pathRule(Allow, big, Project)).Match(fileCall("Read", deep), pctx); got.Verdict == VerdictAllow {
		t.Error("an allow rule too large to evaluate approved something")
	}
	// at a realistic size the same shape evaluates
	ok := "Read(" + strings.Repeat("*/", 10) + "x)"
	if got := pol(pathRule(Deny, ok, Project)).Match(fileCall("Read", "/work/proj/"+strings.Repeat("a/", 10)+"x"), pctx); got.Verdict != VerdictDeny {
		t.Errorf("a realistic deep rule: %v, want deny", got.Verdict)
	}
}

func TestPathGlobBounded_ReportsWhetherItEvaluated(t *testing.T) {
	if m, ev := pathGlobBounded("a/*/c", "a/b/c"); !m || !ev {
		t.Errorf("small: matched %v evaluated %v", m, ev)
	}
	big := strings.Repeat("*/", 300) + "x"
	deep := strings.Repeat("a/", 300) + "x"
	if _, ev := pathGlobBounded(big, deep); ev {
		t.Error("a 300 x 300 table was evaluated: the bound is not enforced")
	}
	if m, ev := pathGlobBounded("", ""); !m || !ev {
		t.Errorf("empty: matched %v evaluated %v", m, ev)
	}
}

func TestPath_SymlinksAreAlwaysACaveat(t *testing.T) {
	got := pol(pathRule(Deny, "Read(./.env)", Project)).Match(fileCall("Read", "/work/proj/.env"), pctx)
	if !hasCaveat(got, "symlink") {
		t.Errorf("caveats = %q, want the symlink limit on every path match", got.Caveats)
	}
	// ...and only on path matches
	if got := pol(rl(Deny, "Bash")).Match(bash("ls"), pctx); hasCaveat(got, "symlink") {
		t.Errorf("a symlink caveat on a Bash call: %q", got.Caveats)
	}
}

// "Special characters": a deny or ask rule whose path is not usable as a gitignore pattern
// still guards that exact path; an allow rule with an unusable pattern approves nothing.
func TestPath_ControlCharactersAndNULInCallPathsDoNotPanic(t *testing.T) {
	for _, path := range []string{"/work/proj/\x00", "/work/proj/\n.env", "\x1b[2J", strings.Repeat("/", 5000), "////"} {
		_ = pol(pathRule(Deny, "Read(./.env)", Project)).Match(fileCall("Read", path), pctx)
	}
}

// "A rule only matches files under its anchor." A file elsewhere on the machine whose NAME fits
// the pattern must not match: a deny on ./secrets/** is about this project's secrets.
func TestPath_AFileOutsideTheAnchorNeverMatchesEvenIfTheNameFits(t *testing.T) {
	cases := []struct {
		rule, path string
	}{
		{"Read(./config/app.json)", "/other/config/app.json"},
		{"Read(src/components/**)", "/other/src/components/a.tsx"},
		{"Read(/src/**)", "/other/src/a.ts"},
		{"Read(~/notes/**)", "/home/other/notes/a"},
		{"Read(//etc/**)", "/usr/etc/x"},
		{"Read(*.pem)", "/other/place/key.pem"}, // a bare name matches at any depth, but only under the anchor
		{"Edit(**/secret)", "/elsewhere/secret"},
	}
	for _, c := range cases {
		tool, _, _ := strings.Cut(c.rule, "(")
		for _, d := range []Decision{Deny, Ask} {
			if got := pol(pathRule(d, c.rule, Project)).Match(fileCall(tool, c.path), pctx).Verdict; got != VerdictNone {
				t.Errorf("%v %s vs %s = %v, want none: the file is outside the rule's anchor", d, c.rule, c.path, got)
			}
		}
	}
	// the anchor directory itself and a sibling that merely shares its prefix
	if got := pol(pathRule(Deny, "Read(**/x)", Project)).Match(fileCall("Read", "/work/proj-evil/x"), pctx).Verdict; got != VerdictNone {
		t.Errorf("a sibling directory sharing the anchor's prefix matched: %v", got)
	}
}

func TestRelUnder(t *testing.T) {
	cases := []struct {
		base, target, rel string
		under             bool
	}{
		{"/a/b", "/a/b", "", true}, {"/a/b", "/a/b/c", "c", true}, {"/a/b", "/a/b/c/d", "c/d", true},
		{"/a/b", "/a/bc", "", false}, {"/a/b", "/a", "", false}, {"/a/b", "/x/a/b", "", false},
		{"/", "/a/b", "a/b", true}, {"/", "/", "", true},
	}
	for _, c := range cases {
		rel, under := relUnder(c.base, c.target)
		if rel != c.rel || under != c.under {
			t.Errorf("relUnder(%q, %q) = (%q, %v), want (%q, %v)", c.base, c.target, rel, under, c.rel, c.under)
		}
	}
}

// * stays inside a segment: Read(docs/*.md) must not reach into subdirectories, and a lone `*`
// pattern segment must not be a shortcut for `**`.
func TestPath_StarNeverCrossesADirectoryBoundary(t *testing.T) {
	for _, c := range []struct {
		pat, path string
		want      bool
	}{
		{"a/*/c", "a/b/c", true}, {"a/*/c", "a/b/x/c", false}, {"*/c", "b/c", true}, {"*/c", "a/b/c", false},
		{"a/*", "a/b/c", false}, {"*.md", "x/y.md", false}, {"a*", "ab/c", false},
	} {
		if got := pathGlob(c.pat, c.path); got != c.want {
			t.Errorf("pathGlob(%q, %q) = %v, want %v", c.pat, c.path, got, c.want)
		}
	}
	p := pol(pathRule(Deny, "Read(docs/*.md)", Project))
	if got := verdictFor(p, fileCall("Read", "/work/proj/docs/a/b.md")); got != VerdictNone {
		t.Errorf("Read(docs/*.md) reached into a subdirectory: %v", got)
	}
}

// ~/ needs the home directory. With none known the rule cannot be located, and saying "no match"
// would be a guess: it is reported as unevaluable.
func TestPath_ATildeRuleWithNoKnownHomeIsUnevaluableNotAMiss(t *testing.T) {
	ctx := MatchContext{Cwd: "/work/proj"}
	for _, d := range []Decision{Deny, Ask} {
		got := pol(pathRule(d, "Read(~/.ssh/**)", User)).Match(fileCall("Read", "/home/me/.ssh/id_rsa"), ctx)
		if got.Verdict != VerdictUnknown {
			t.Errorf("%v ~/ rule with no home: %v, want unknown", d, got.Verdict)
		}
		if !hasCaveat(got, "home directory is unknown") {
			t.Errorf("caveats = %q, want the missing home named", got.Caveats)
		}
	}
}

func TestCollapseStars(t *testing.T) {
	for in, want := range map[string]string{
		"": "", "a": "a", "*": "*", "**": "*", "***": "*", "a**b": "a*b", "a*b*c": "a*b*c",
		"**a**b**": "*a*b*", "*/**": "*/*",
	} {
		if got := collapseStars(in); got != want {
			t.Errorf("collapseStars(%q) = %q, want %q", in, got, want)
		}
	}
	// ...and a segment pattern means the same before and after
	for _, c := range []struct {
		pat, s string
		want   bool
	}{{"a**b", "axxb", true}, {"a**b", "ab", true}, {"a**b", "a", false}, {"**", "", true}, {"**x", "yx", true}} {
		if got := segGlob(c.pat, c.s); got != c.want {
			t.Errorf("segGlob(%q, %q) = %v, want %v", c.pat, c.s, got, c.want)
		}
	}
}

// An all-matching pattern is the case where the anchor bound is the only thing between a rule
// and every file on the machine: ** matches an empty relative path, so a file outside the
// anchor must be rejected BEFORE the pattern sees it.
func TestPath_AMatchEverythingPatternStillStopsAtItsAnchor(t *testing.T) {
	// Read(*) is not here: a lone * is "every use of the tool" (the docs' own wording), not a path
	// pattern, and matches wherever the file is. See TestMatch_ToolNames.
	for _, rule := range []string{"Read(**)", "Read(./**)", "Edit(**/**)"} {
		tool, _, _ := strings.Cut(rule, "(")
		for _, d := range []Decision{Deny, Ask} {
			p := pol(pathRule(d, rule, Project))
			if got := verdictFor(p, fileCall(tool, "/etc/passwd")); got != VerdictNone {
				t.Errorf("%v %s vs /etc/passwd = %v: a rule anchored in the project reached outside it", d, rule, got)
			}
			if got := verdictFor(p, fileCall(tool, "/work/proj-evil/x")); got != VerdictNone {
				t.Errorf("%v %s vs a sibling sharing the prefix = %v", d, rule, got)
			}
			// ...while a file inside is covered
			if got := verdictFor(p, fileCall(tool, "/work/proj/a/b")); got != verdictOf(d) {
				t.Errorf("%v %s vs a project file = %v, want %v", d, rule, got, verdictOf(d))
			}
		}
	}
	// //** is the explicit "everywhere" spelling
	if got := verdictFor(pol(pathRule(Deny, "Read(//**)", Project)), fileCall("Read", "/etc/passwd")); got != VerdictDeny {
		t.Errorf("Read(//**) is anchored at the filesystem root: %v, want deny", got)
	}
}

func TestPath_ALoneStarIsEveryUseOfTheToolWhateverThePath(t *testing.T) {
	for _, d := range []Decision{Deny, Ask} {
		p := pol(pathRule(d, "Read(*)", Project))
		for _, path := range []string{"/etc/passwd", "/work/proj/a", "/anywhere/else"} {
			if got := verdictFor(p, fileCall("Read", path)); got != verdictOf(d) {
				t.Errorf("%v Read(*) vs %s = %v: a lone * means every use of the tool", d, path, got)
			}
		}
	}
}

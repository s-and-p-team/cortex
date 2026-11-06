package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"

	"github.com/rossoctl/cortex/cmd/agentop/access"
)

// colour forces a colour profile for the test, so a style leaves a visible mark in the output.
func colour(t *testing.T) {
	t.Helper()
	orig := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.ANSI256)
	t.Cleanup(func() { lipgloss.SetColorProfile(orig) })
}

func plain(lines []string) string { return ansi.Strip(strings.Join(lines, "\n")) }

// a policy that exercises every section.
func richPolicy() access.Policy {
	deny := access.Rule{Decision: access.Deny, Raw: "Read(.env)", Tool: "Read", Pattern: ".env", Source: access.User, File: "/h/.claude/settings.json"}
	ask := access.Rule{Decision: access.Ask, Raw: "Bash(git push *)", Tool: "Bash", Pattern: "git push *", Source: access.Project, File: "/p/.claude/settings.json"}
	shadowed := access.Rule{Decision: access.Allow, Raw: "Bash(git push *)", Tool: "Bash", Pattern: "git push *", Source: access.Local, File: "/p/.claude/settings.local.json", ShadowedBy: &ask}
	ignored := access.Rule{Decision: access.Allow, Raw: "WebFetch", Tool: "WebFetch", Source: access.User, File: "/h/.claude/settings.json", Ignored: "ignored: allowManagedPermissionRulesOnly is set in managed settings"}
	trust := access.Rule{Decision: access.Allow, Raw: "Bash(npm *)", Tool: "Bash", Pattern: "npm *", Source: access.Project, File: "/p/.claude/settings.json", NeedsTrust: true}
	return access.Policy{
		Layers: []access.Layer{
			{Kind: access.Managed, Path: "/etc/claude-code/managed-settings.json", Note: "file sources only; MDM and console-delivered policy cannot be read"},
			{Kind: access.CLI},
			{Kind: access.Local, Path: "/p/.claude/settings.local.json", Present: true, Counts: access.Counts{Allow: 1}},
			{Kind: access.Project, Path: "/p/.claude/settings.json", Present: true, Counts: access.Counts{Allow: 1, Ask: 1}},
			{Kind: access.User, Path: "/h/.claude/settings.json", Present: true, Err: fmt.Errorf("invalid character 'x'"), Counts: access.Counts{Deny: 1}},
		},
		Mode:        access.Scalar[string]{Value: "default", Layer: access.User, Set: true},
		SessionMode: "acceptEdits",
		Sandbox:     access.Scalar[bool]{Value: true, Layer: access.User, Set: true},
		Rules:       []access.Rule{deny, ask, shadowed, ignored, trust},
		Dirs:        []access.Dir{{Path: "/data", Source: access.Local}},
		Hooks:       []access.Hook{{Event: "PreToolUse", Source: access.User}},
		Ignored: []access.IgnoredSetting{{Key: "permissions.defaultMode", Value: "bypassPermissions", Layer: access.Project,
			File: "/p/.claude/settings.json", Reason: "bypassPermissions does not take effect from project or local settings"}},
		Flags: []access.RiskFlag{
			{Code: "session-bypass", Severity: access.High, Detail: "this session was recorded in bypassPermissions mode"},
			{Code: "sandbox-off", Severity: access.Low, Detail: "sandbox.enabled is not set"},
		},
		Notes: []string{"session s1 (fix it) started in /p"},
	}
}

var okTarget = accessTarget{Kind: targetOK}

func TestAccessLines_ShowsEveryLayerEvenWhenAbsent(t *testing.T) {
	out := plain(accessLines(richPolicy(), okTarget, 120, false))
	for _, want := range []string{"managed", "cli", "local", "project", "user",
		"/etc/claude-code/managed-settings.json", "absent", "file sources only",
		"allow 1", "ask 1", "invalid character 'x'"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

// A layer that failed to parse contributed nothing, so it must not show counts beside its error.
func TestAccessLines_AFailedLayerShowsTheErrorNotCounts(t *testing.T) {
	for _, l := range accessLines(richPolicy(), okTarget, 140, false) {
		s := ansi.Strip(l)
		if strings.Contains(s, "/h/.claude/settings.json") && strings.Contains(s, "error:") && strings.Contains(s, "deny 1") {
			t.Errorf("a layer with a parse error also shows rule counts: %q", s)
		}
	}
}

func TestAccessLines_RulesInEvaluationOrderWithTheirSources(t *testing.T) {
	out := plain(accessLines(richPolicy(), okTarget, 140, false))
	d, a := strings.Index(out, "Read(.env)"), strings.Index(out, "Bash(git push *)")
	al := strings.LastIndex(out, "Bash(npm *)")
	if d < 0 || a < 0 || al < 0 || !(d < a && a < al) {
		t.Errorf("rules are not deny, ask, allow (deny@%d ask@%d allow@%d):\n%s", d, a, al, out)
	}
	for _, want := range []string{"deny", "ask", "allow", "user", "project", "local"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in the rules:\n%s", want, out)
		}
	}
}

func TestAccessLines_ShadowedIgnoredAndTrustAreSaidInWords(t *testing.T) {
	out := plain(accessLines(richPolicy(), okTarget, 160, false))
	for _, want := range []string{
		"shadowed by ask Bash(git push *) (project)",
		"allowManagedPermissionRulesOnly",
		"workspace trust",
		"bypassPermissions does not take effect from project or local settings",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestAccessLines_ShadowedRulesAreDimmedAndOthersAreNot(t *testing.T) {
	colour(t)
	var shadowed, normal string
	for _, l := range accessLines(richPolicy(), okTarget, 160, false) {
		switch {
		case strings.Contains(ansi.Strip(l), "shadowed by"):
			shadowed = l
		case strings.Contains(ansi.Strip(l), "Read(.env)"):
			normal = l
		}
	}
	if shadowed == "" || normal == "" {
		t.Fatalf("lines not found (shadowed %q normal %q)", shadowed, normal)
	}
	mutedPrefix := styleMuted.Render("x")
	mutedPrefix = mutedPrefix[:strings.Index(mutedPrefix, "x")]
	if !strings.Contains(shadowed, mutedPrefix) {
		t.Errorf("the shadowed rule is not dimmed: %q", shadowed)
	}
	if strings.Contains(normal, mutedPrefix) {
		t.Errorf("a live rule is dimmed: %q", normal)
	}
}

func TestAccessLines_ConfiguredAndSessionModesAreBothShownAndDistinct(t *testing.T) {
	out := plain(accessLines(richPolicy(), okTarget, 120, false))
	if !strings.Contains(out, "configured") || !strings.Contains(out, "default (user)") ||
		!strings.Contains(out, "this session") || !strings.Contains(out, "acceptEdits") {
		t.Errorf("both modes should be shown, labelled:\n%s", out)
	}
	p := richPolicy()
	p.SessionMode = ""
	if out := plain(accessLines(p, okTarget, 120, false)); strings.Contains(out, "this session:") {
		t.Errorf("a session mode appeared with none recorded:\n%s", out)
	}
}

func TestAccessLines_FlagsListHighFirstAndSessionBypassRenders(t *testing.T) {
	out := plain(accessLines(richPolicy(), okTarget, 140, false))
	hi, lo := strings.Index(out, "session-bypass"), strings.Index(out, "sandbox-off")
	if hi < 0 || lo < 0 || hi > lo {
		t.Errorf("flags not high-first (high@%d low@%d):\n%s", hi, lo, out)
	}
}

func TestAccessLines_EveryRefusalSaysWhyAndShowsNoPolicy(t *testing.T) {
	for _, k := range []accessTargetKind{targetRemote, targetNoEntry, targetOtherAgent, targetNoClient} {
		t.Run(fmt.Sprint(k), func(t *testing.T) {
			// A non-empty policy is passed on purpose: it must NOT be drawn for a refusal, even
			// if a stale one is still in the model.
			out := plain(accessLines(richPolicy(), accessTarget{Kind: k, Reason: "because reasons"}, 100, false))
			if !strings.Contains(out, "because reasons") {
				t.Errorf("the reason is missing:\n%s", out)
			}
			for _, leak := range []string{"Read(.env)", "LAYERS", "managed", "RULES"} {
				if strings.Contains(out, leak) {
					t.Errorf("a refusal drew policy text %q:\n%s", leak, out)
				}
			}
		})
	}
}

func TestAccessLines_NoDirectoryShowsLayersAndExplainsTheMissingOnes(t *testing.T) {
	p := richPolicy()
	p.Layers[2].Path, p.Layers[2].Present, p.Layers[2].Note = "", false, "no working directory for this session"
	out := plain(accessLines(p, accessTarget{Kind: targetNoCwd, Reason: "no working directory was recorded for this session"}, 120, false))
	if !strings.Contains(out, "no working directory") || !strings.Contains(out, "LAYERS") || !strings.Contains(out, "Read(.env)") {
		t.Errorf("the degraded state should say why AND still show what it can:\n%s", out)
	}
}

func TestAccessLines_LoadingAndErrorStates(t *testing.T) {
	if out := plain(accessLines(access.Policy{}, okTarget, 80, true)); !strings.Contains(out, "resolving") {
		t.Errorf("a load in flight with nothing yet should say so:\n%s", out)
	}
	p := richPolicy()
	if out := plain(accessLines(p, okTarget, 140, true)); !strings.Contains(out, "refreshing") || !strings.Contains(out, "Read(.env)") {
		t.Errorf("a refresh should keep the policy on screen and say it is refreshing:\n%s", out)
	}
}

func TestAccessLines_EmptyPolicyStillSaysSo(t *testing.T) {
	out := plain(accessLines(access.Policy{Layers: richPolicy().Layers}, okTarget, 100, false))
	if !strings.Contains(out, "no rules") {
		t.Errorf("an empty rule list should be stated, not omitted:\n%s", out)
	}
}

func TestAccessLines_NeverExceedTheWidth(t *testing.T) {
	colour(t)
	long := strings.Repeat("segment/", 60)
	p := richPolicy()
	p.Rules[0].Raw = "Read(" + long + ")"
	p.Rules[2].Raw = "Bash(" + strings.Repeat("very long command ", 40) + ")"
	p.Layers[2].Path = "/" + long + "settings.local.json"
	p.Notes = []string{"session " + strings.Repeat("x", 300)}
	// Down to widths smaller than the fixed parts of a rule row (decision, source), where only
	// the final clip keeps a line inside the terminal.
	for _, w := range []int{1, 2, 5, 8, 12, 15, 20, 40, 60, 80, 200} {
		for _, l := range accessLines(p, okTarget, w, false) {
			if got := lipgloss.Width(l); got > w {
				t.Fatalf("width %d: a line is %d columns wide: %q", w, got, ansi.Strip(l))
			}
			if strings.Contains(l, "\n") {
				t.Fatalf("width %d: a line contains a newline: %q", w, l)
			}
		}
	}
}

func TestAccessLines_TruncationKeepsTheRuleSourceVisible(t *testing.T) {
	p := richPolicy()
	p.Rules[0].Raw = "Read(" + strings.Repeat("a", 400) + ")"
	for _, l := range accessLines(p, okTarget, 70, false) {
		if s := ansi.Strip(l); strings.Contains(s, "Read(aaaa") && !strings.Contains(s, "user") {
			t.Errorf("the source column was cut off with the rule text: %q", s)
		}
	}
}

// Settings text, paths and errors come from files an attacker may have written.
func TestAccessLines_NeverEmitATerminalControlSequenceFromPolicyText(t *testing.T) {
	const evil = "\x1b]0;pwned\x07\x1b[2J\u202e"
	p := richPolicy()
	p.Rules[0].Raw = "Read(" + evil + ")"
	p.Rules[0].Pattern = evil
	p.Layers[4].Path = "/h" + evil
	p.Layers[4].Err = fmt.Errorf("boom %s", evil)
	p.Layers[0].Note = "note " + evil
	p.Notes = []string{"note " + evil}
	p.SessionMode = "plan" + evil
	p.Mode.Value = "m" + evil
	p.Dirs[0].Path = "/d" + evil
	p.Hooks[0].Event = "Pre" + evil
	p.Flags[0].Detail = "flag " + evil
	p.Rules[2].ShadowedBy = &access.Rule{Decision: access.Deny, Raw: "X" + evil, Source: access.User}
	p.Ignored[0].Reason = "why " + evil
	colour(t)
	for _, l := range accessLines(p, okTarget, 200, false) {
		s := ansi.Strip(l) // our own styling is stripped; anything left is from the data
		for i := 0; i < len(s); i++ {
			if b := s[i]; b < 0x20 || b == 0x7f {
				t.Fatalf("a line carries control byte %#x: %q", b, s)
			}
		}
		for _, leak := range []string{"pwned", "[2J", "\u202e"} {
			if strings.Contains(s, leak) {
				t.Fatalf("a line leaks %q from policy text: %q", leak, s)
			}
		}
	}
}

func TestAccessLines_ManyRulesRenderQuicklyAndScroll(t *testing.T) {
	p := richPolicy()
	p.Rules = nil
	for i := 0; i < 5000; i++ {
		p.Rules = append(p.Rules, access.Rule{Decision: access.Allow, Raw: fmt.Sprintf("Bash(cmd%d *)", i), Tool: "Bash", Source: access.Local})
	}
	start := time.Now()
	lines := accessLines(p, okTarget, 100, false)
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("5000 rules took %v to render", d)
	}
	if len(lines) < 5000 {
		t.Errorf("got %d lines for 5000 rules; none may be dropped", len(lines))
	}
}

func TestAccessLines_TinyWidthDoesNotPanic(t *testing.T) {
	for _, w := range []int{-5, 0, 1, 2, 3} {
		accessLines(richPolicy(), okTarget, w, false)
		accessLines(access.Policy{}, accessTarget{Kind: targetRemote, Reason: "x"}, w, false)
	}
}

// accessBody is what the viewport shows: it must use the real rendering, searched.
func TestAccessBody_DrawsThePolicyAndIsSearchable(t *testing.T) {
	m, _ := openedAccessModel(localURL, okEntry, true)
	m.width, m.height = 120, 40
	p := richPolicy()
	m.openAccess("s1")
	m.access.policy, m.access.loading = &p, false
	body := ansi.Strip(m.accessBody())
	if !strings.Contains(body, "Read(.env)") {
		t.Errorf("the pane body lacks the policy:\n%s", body)
	}
	if len(m.accessViews.doc.lines) == 0 {
		t.Error("the searchable document is empty: search would find nothing")
	}
}

// A stale policy can still be held by the model (the reader moved on, or the files became
// unreadable). It must not be drawn under a reason that says nothing can be shown.
func TestAccessBody_NeverDrawsAStalePolicyForARefusal(t *testing.T) {
	m, _ := openedAccessModel(remoteURL, okEntry, true)
	m.width, m.height = 120, 40
	p := richPolicy()
	m.openAccess("s1")
	m.access.policy = &p // left over from an earlier, resolvable visit
	body := ansi.Strip(m.accessBody())
	if strings.Contains(body, "Read(.env)") || strings.Contains(body, "LAYERS") {
		t.Errorf("a refusal drew a stale policy:\n%s", body)
	}
	if !strings.Contains(body, "not on this machine's Cortex") {
		t.Errorf("a refusal should say why:\n%s", body)
	}
}

package tui

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/rossoctl/cortex/cmd/agentop/access"
	"github.com/rossoctl/cortex/cmd/agentop/apiclient"
	"github.com/rossoctl/cortex/core/session"
)

const (
	localURL  = "http://127.0.0.1:47601"
	remoteURL = "http://127.0.0.1:19094" // a port-forward to a pod: loopback, but not this machine's Cortex
)

// accessModel is a model connected to endpoint, whose local Cortex is localURL, knowing one
// harvested session.
func accessModel(endpoint string, entry SessionMetadata, have bool) *model {
	m := &model{
		pane:               paneSessions,
		client:             apiclient.New(endpoint),
		localEndpoint:      localURL,
		previousPane:       paneNone,
		pipelineReturnPane: paneNone,
		sessionsData:       map[string]SessionMetadata{},
		sessions:           []session.SessionSummary{{ID: "s1"}},
		selectedSess:       "s1",
	}
	if have {
		m.sessionsData["s1"] = entry
	}
	// The sessions pane reads the row under the cursor, which exists only once the table is built.
	m.rebuildSessionsTable()
	return m
}

var okEntry = SessionMetadata{
	Title: "fix it", AgentType: "Claude Code", Cwd: "/w/proj",
	AgentConfigDir: "/w/claude", PermissionMode: "acceptEdits",
}

func TestAccessTargetFor(t *testing.T) {
	noCwd := okEntry
	noCwd.Cwd = ""
	codex := okEntry
	codex.AgentType = "Codex"
	untyped := okEntry
	untyped.AgentType = ""

	cases := []struct {
		name    string
		m       *model
		want    accessTargetKind
		reason  string // a substring of the reason, when the kind is degraded
		noInput bool   // the Input must be the zero value: no local path may leak into a refusal
	}{
		{"this machine's Cortex, harvested", accessModel(localURL, okEntry, true), targetOK, "", false},
		{"loopback is matched by host, not spelling", accessModel("http://localhost:47601", okEntry, true), targetOK, "", false},
		{"an entry with no agent type is Claude Code's", accessModel(localURL, untyped, true), targetOK, "", false},
		{"a port-forward to a pod is not this machine", accessModel(remoteURL, okEntry, true), targetRemote, "127.0.0.1:19094", true},
		{"a remote host", accessModel("http://cortex.example.com:9094", okEntry, true), targetRemote, "cortex.example.com", true},
		{"no local Cortex known at all is not local", func() *model {
			m := accessModel(localURL, okEntry, true)
			m.localEndpoint = ""
			return m
		}(), targetRemote, "", true},
		{"no client", func() *model {
			m := accessModel(localURL, okEntry, true)
			m.client = nil
			return m
		}(), targetNoClient, "", true},
		{"never harvested", accessModel(localURL, SessionMetadata{}, false), targetNoEntry, "read-claude-sessions", true},
		{"another agent", accessModel(localURL, codex, true), targetOtherAgent, "Codex", true},
		{"harvested but no directory", accessModel(localURL, noCwd, true), targetNoCwd, "no working directory", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.m.accessTargetFor("s1")
			if got.Kind != c.want {
				t.Fatalf("Kind = %v, want %v (reason %q)", got.Kind, c.want, got.Reason)
			}
			if c.reason != "" && !strings.Contains(got.Reason, c.reason) {
				t.Errorf("Reason = %q, want it to contain %q", got.Reason, c.reason)
			}
			if c.noInput && got.Input.FS != nil {
				t.Errorf("a %v target carries a usable Input: nothing local may be readable for it", got.Kind)
			}
		})
	}
}

func TestAccessTargetFor_ResolvableTargetsCarryTheSessionsFacts(t *testing.T) {
	got := accessModel(localURL, okEntry, true).accessTargetFor("s1")
	in := got.Input
	if in.Cwd != "/w/proj" || in.ConfigDir != "/w/claude" || in.SessionMode != "acceptEdits" || in.FS == nil {
		t.Errorf("Input = %+v", in)
	}
	if len(in.Notes) == 0 || !strings.Contains(in.Notes[0], "s1") || !strings.Contains(in.Notes[0], "/w/proj") {
		t.Errorf("Notes = %q, want the line saying which session this is", in.Notes)
	}
}

// A session with no directory resolves the user and managed layers only. The directory the
// viewer happens to run in must never stand in for it.
func TestAccessTargetFor_NoCwdNeverFallsBackToTheCurrentDirectory(t *testing.T) {
	noCwd := okEntry
	noCwd.Cwd = ""
	t.Chdir(t.TempDir())
	got := accessModel(localURL, noCwd, true).accessTargetFor("s1")
	if got.Kind != targetNoCwd || got.Input.Cwd != "" || got.Input.GitRoot != "" {
		t.Errorf("Kind %v Cwd %q GitRoot %q: the current directory leaked into a session that has none",
			got.Kind, got.Input.Cwd, got.Input.GitRoot)
	}
}

func TestAccessTargetFor_AnIdWithAControlByteIsStillRefusedCleanly(t *testing.T) {
	m := accessModel(localURL, SessionMetadata{}, false)
	got := m.accessTargetFor("s1\x1b]0;x\x07")
	if got.Kind != targetNoEntry || strings.ContainsAny(got.Reason, "\x1b\x07") {
		t.Errorf("Kind %v Reason %q: a session id comes from the wire and must not reach the screen raw", got.Kind, got.Reason)
	}
}

// `V` opens from the same panes `T` opens the timeline from, and from nowhere else.
func TestAccessKey_OpensFromTheSessionViewsAndNowhereElse(t *testing.T) {
	for _, from := range []paneID{paneSessions, paneEvents, paneDetail} {
		m := accessModel(localURL, okEntry, true)
		m.pane = from
		m.handleKey(keyRune('V'))
		if m.pane != paneAccess {
			t.Errorf("`V` from %v opened %v, want paneAccess", from, m.pane)
			continue
		}
		if m.access.returnPane != from || m.access.session != "s1" {
			t.Errorf("from %v: returnPane %v session %q, want %v and s1", from, m.access.returnPane, m.access.session, from)
		}
		// The parity claim, driven rather than asserted: T works wherever V does.
		tm := accessModel(localURL, okEntry, true)
		tm.pane = from
		tm.handleKey(keyRune('T'))
		if tm.pane != paneTimeline {
			t.Errorf("`T` from %v opened %v: V and T no longer share an allowlist", from, tm.pane)
		}
	}
	for _, from := range []paneID{paneNamespaces, panePods, panePipeline, paneCatalog, paneUsage, paneAgents, paneTimeline, panePluginDetail} {
		m := accessModel(localURL, okEntry, true)
		m.pane = from
		m.handleKey(keyRune('V'))
		if m.pane != from {
			t.Errorf("`V` from %v moved to %v; it must do nothing there", from, m.pane)
		}
	}
}

// While the search prompt is open every key is a character, `V` included; the prompt takes
// them before the pane-key handlers run, so this is the behaviour a user sees. The picker case
// is the one the `V` handler's own gate guards.
func TestAccessKey_IsATypedLetterWhileSearchingOrInThePicker(t *testing.T) {
	t.Run("search prompt", func(t *testing.T) {
		m := accessModel(localURL, okEntry, true)
		m.pane = paneEvents
		m.searchInput = newSearchInput() // a bare model has no input widget; New() builds one
		m.handleKey(keyRune('/'))
		if !m.searching {
			t.Fatal("search did not open")
		}
		m.handleKey(keyRune('V'))
		if m.pane == paneAccess {
			t.Error("`V` opened the pane instead of being typed into the query")
		}
		if got := m.searchInput.Value(); got != "V" {
			t.Errorf("query = %q, want the typed V", got)
		}
	})
	t.Run("column picker", func(t *testing.T) {
		m := accessModel(localURL, okEntry, true)
		m.pane = paneEvents
		m.colPicker = true
		m.handleKey(keyRune('V'))
		if m.pane == paneAccess {
			t.Error("`V` opened the pane over the column picker")
		}
	})
}

func TestAccessKey_NeedsASession(t *testing.T) {
	m := accessModel(localURL, okEntry, true)
	m.pane = paneEvents
	m.selectedSess = ""
	m.handleKey(keyRune('V'))
	if m.pane == paneAccess {
		t.Error("`V` with no session selected opened a pane with nothing to show")
	}
}

func TestAccessKey_OnSessionsUsesTheHighlightedRow(t *testing.T) {
	m := accessModel(localURL, okEntry, true)
	m.pane = paneSessions
	m.selectedSess = "" // sessions pane: the row under the cursor, not a prior selection
	m.sessions = []session.SessionSummary{{ID: "s1"}}
	m.rebuildSessionsTable()
	m.handleKey(keyRune('V'))
	if m.pane != paneAccess || m.access.session != "s1" {
		t.Errorf("pane %v session %q, want paneAccess on the highlighted s1", m.pane, m.access.session)
	}
}

// --- loading ---------------------------------------------------------------------------------

// recordingResolver is an injected resolver that counts its calls and returns canned policies.
type recordingResolver struct {
	calls []access.Input
	pol   access.Policy
	err   error
}

func (r *recordingResolver) resolve(in access.Input) (access.Policy, error) {
	r.calls = append(r.calls, in)
	return r.pol, r.err
}

func openedAccessModel(endpoint string, entry SessionMetadata, have bool) (*model, *recordingResolver) {
	m := accessModel(endpoint, entry, have)
	r := &recordingResolver{pol: access.Policy{Mode: access.Scalar[string]{Value: "default", Set: true}}}
	m.accessResolve = r.resolve
	return m, r
}

// run executes a tea.Cmd and returns its message, as the runtime would.
func run(t *testing.T, c tea.Cmd) tea.Msg {
	t.Helper()
	if c == nil {
		t.Fatal("expected a command, got nil")
	}
	return c()
}

func TestOpenAccess_ResolvesOffTheUIGoroutine(t *testing.T) {
	m, r := openedAccessModel(localURL, okEntry, true)
	cmd := m.openAccess("s1")
	if len(r.calls) != 0 {
		t.Fatalf("the resolver ran %d time(s) inside openAccess: it must run in the returned command", len(r.calls))
	}
	if !m.access.loading {
		t.Error("loading not set while a resolve is in flight")
	}
	msg, ok := run(t, cmd).(accessLoadedMsg)
	if !ok {
		t.Fatalf("command returned %T, want accessLoadedMsg", msg)
	}
	if len(r.calls) != 1 || r.calls[0].Cwd != "/w/proj" {
		t.Errorf("resolver calls = %+v, want one for /w/proj", r.calls)
	}
	m.handleAccessLoaded(msg)
	if m.access.loading || m.access.policy == nil || m.access.policy.Mode.Value != "default" {
		t.Errorf("after the reply: loading %v policy %+v", m.access.loading, m.access.policy)
	}
}

// The five states that cannot be resolved must not call the resolver at all.
func TestOpenAccess_NeverResolvesAnUnresolvableTarget(t *testing.T) {
	codex := okEntry
	codex.AgentType = "Codex"
	for name, c := range map[string]struct {
		endpoint string
		entry    SessionMetadata
		have     bool
	}{
		"remote":      {remoteURL, okEntry, true},
		"no entry":    {localURL, SessionMetadata{}, false},
		"other agent": {localURL, codex, true},
	} {
		m, r := openedAccessModel(c.endpoint, c.entry, c.have)
		cmd := m.openAccess("s1")
		if cmd != nil {
			if msg := cmd(); msg != nil {
				m.Update(msg)
			}
		}
		if len(r.calls) != 0 {
			t.Errorf("%s: the resolver was called (%+v): a refusal must not read any file", name, r.calls)
		}
		if m.access.policy != nil || m.access.loading {
			t.Errorf("%s: policy %v loading %v, want neither", name, m.access.policy, m.access.loading)
		}
	}
	m, r := openedAccessModel(localURL, okEntry, true)
	m.client = nil
	if cmd := m.openAccess("s1"); cmd != nil {
		cmd()
	}
	if len(r.calls) != 0 {
		t.Error("no client: the resolver was called")
	}
}

func TestOpenAccess_ADegradedNoDirectoryTargetStillResolvesUserAndManaged(t *testing.T) {
	noCwd := okEntry
	noCwd.Cwd = ""
	m, r := openedAccessModel(localURL, noCwd, true)
	msg := run(t, m.openAccess("s1"))
	if len(r.calls) != 1 || r.calls[0].Cwd != "" {
		t.Fatalf("calls = %+v, want one resolve with no cwd", r.calls)
	}
	m.handleAccessLoaded(msg.(accessLoadedMsg))
	if m.access.policy == nil {
		t.Error("the user and managed layers should still be shown")
	}
}

func TestHandleAccessLoaded_DropsAStaleReply(t *testing.T) {
	m, _ := openedAccessModel(localURL, okEntry, true)
	first := run(t, m.openAccess("s1")).(accessLoadedMsg)
	second := run(t, m.refreshAccess()).(accessLoadedMsg)
	if second.req <= first.req {
		t.Fatalf("req did not advance: %d then %d", first.req, second.req)
	}
	newer := access.Policy{Mode: access.Scalar[string]{Value: "plan", Set: true}}
	second.policy = newer
	m.handleAccessLoaded(second)
	first.policy = access.Policy{Mode: access.Scalar[string]{Value: "STALE", Set: true}}
	m.handleAccessLoaded(first)
	if m.access.policy == nil || m.access.policy.Mode.Value != "plan" {
		t.Errorf("policy = %+v: a late reply for an older request overwrote a newer one", m.access.policy)
	}
}

func TestHandleAccessLoaded_DropsAReplyForASessionTheReaderLeft(t *testing.T) {
	m, _ := openedAccessModel(localURL, okEntry, true)
	msg := run(t, m.openAccess("s1")).(accessLoadedMsg)
	// The reply carries the CURRENT request number but names another session: the request check
	// cannot catch it, so only the session check stands between it and the screen.
	msg.session = "s0-someone-else"
	msg.policy = access.Policy{Mode: access.Scalar[string]{Value: "WRONG-SESSION", Set: true}}
	m.handleAccessLoaded(msg)
	if m.access.policy != nil {
		t.Errorf("policy %+v: a reply naming another session was shown", m.access.policy)
	}
	if !m.access.loading {
		t.Error("a dropped reply must not end the real load")
	}
}

// The ordinary way to leave: open another session. Its reply for the first must be dropped
// whichever check does it.
func TestHandleAccessLoaded_AReplyArrivingAfterSwitchingSessionsIsDropped(t *testing.T) {
	m, _ := openedAccessModel(localURL, okEntry, true)
	msg := run(t, m.openAccess("s1")).(accessLoadedMsg)
	m.sessionsData["s2"] = okEntry
	m.openAccess("s2")
	m.handleAccessLoaded(msg)
	if m.access.policy != nil {
		t.Errorf("policy %+v: s1's policy was shown under s2", m.access.policy)
	}
}

func TestOpenAccess_KeepsTheLastPolicyOnScreenWhileRefreshingTheSameSession(t *testing.T) {
	m, _ := openedAccessModel(localURL, okEntry, true)
	m.handleAccessLoaded(run(t, m.openAccess("s1")).(accessLoadedMsg))
	have := m.access.policy
	m.pane = paneSessions
	cmd := m.openAccess("s1")
	if m.access.policy != have || have == nil {
		t.Error("re-opening the same session blanked the pane while it refreshes")
	}
	_ = cmd
	m.sessionsData["s2"] = okEntry
	m.openAccess("s2")
	if m.access.policy != nil {
		t.Error("opening a different session kept the previous session's policy")
	}
}

func TestRefreshAccess_RunsOnR(t *testing.T) {
	m, r := openedAccessModel(localURL, okEntry, true)
	m.handleAccessLoaded(run(t, m.openAccess("s1")).(accessLoadedMsg))
	cmd := m.handleKey(keyRune('r'))
	if cmd == nil {
		t.Fatal("r returned no command")
	}
	cmd()
	if len(r.calls) != 2 {
		t.Errorf("resolver calls = %d, want 2: r must re-read the files, they may have changed", len(r.calls))
	}
}

func TestHandleAccessLoaded_AResolverErrorIsKeptAndShown(t *testing.T) {
	m, r := openedAccessModel(localURL, okEntry, true)
	r.err = errors.New("boom")
	m.handleAccessLoaded(run(t, m.openAccess("s1")).(accessLoadedMsg))
	if m.access.err == nil || m.access.loading {
		t.Fatalf("err %v loading %v", m.access.err, m.access.loading)
	}
	if !strings.Contains(m.accessBody(), "boom") {
		t.Errorf("the failure is not on screen:\n%s", m.accessBody())
	}
}

// The reply arrives through Update, like every other pane's.
func TestUpdate_RoutesAccessLoadedMsg(t *testing.T) {
	m, _ := openedAccessModel(localURL, okEntry, true)
	msg := run(t, m.openAccess("s1"))
	updated, _ := m.Update(msg)
	if updated.(*model).access.policy == nil {
		t.Error("Update did not route accessLoadedMsg to the pane")
	}
}

// --- the pane inside the viewer ---------------------------------------------------------------

// sizedAccessModel is a model with a terminal size and the pane open on a resolved policy.
func sizedAccessModel(t *testing.T, w, h int) *model {
	t.Helper()
	m, _ := openedAccessModel(localURL, okEntry, true)
	m.width, m.height = w, h
	m.detailVp.Width, m.detailVp.Height = w, h
	m.layout()
	p := richPolicy()
	m.pane = paneSessions
	m.openAccess("s1")
	m.access.policy, m.access.loading = &p, false
	return m
}

func TestAccessPane_ViewShowsTheTitleAndThePolicy(t *testing.T) {
	m := sizedAccessModel(t, 120, 40)
	view := ansi.Strip(m.View())
	for _, want := range []string{"access", "s1", "LAYERS", "Read(.env)"} {
		if !strings.Contains(view, want) {
			t.Errorf("View lacks %q:\n%s", want, view)
		}
	}
}

func TestAccessPane_TitleCarriesTheSessionHeader(t *testing.T) {
	m := sizedAccessModel(t, 120, 40)
	m.sessionsData["s1"] = SessionMetadata{Title: "fix it", Cwd: "/w/proj", AgentType: "Claude Code", AgentConfigDir: "/w/claude"}
	if got := ansi.Strip(m.View()); !strings.Contains(got, "fix it") {
		t.Errorf("the title should name the session by its harvested title:\n%.300s", got)
	}
}

func TestAccessPane_EscReturnsToWhereItWasOpenedFrom(t *testing.T) {
	for _, from := range []paneID{paneSessions, paneEvents, paneDetail} {
		m, _ := openedAccessModel(localURL, okEntry, true)
		m.pane = from
		m.openAccess("s1")
		m.handleKey(tea.KeyMsg{Type: tea.KeyEsc})
		if m.pane != from {
			t.Errorf("opened from %v, esc went to %v", from, m.pane)
		}
	}
	// With no recorded caller it falls back to the sessions list, never to a dead pane.
	m, _ := openedAccessModel(localURL, okEntry, true)
	m.pane = paneAccess
	m.access.returnPane = paneNone
	m.handleKey(tea.KeyMsg{Type: tea.KeyEsc})
	if m.pane != paneSessions {
		t.Errorf("esc with no caller went to %v, want the sessions list", m.pane)
	}
}

// left/h also back out on the other panes. Here they must NOT be needed to scroll: this pane has
// no horizontal axis, so they behave as back, like the catalog.
func TestAccessPane_LeftAlsoGoesBack(t *testing.T) {
	m, _ := openedAccessModel(localURL, okEntry, true)
	m.pane = paneEvents
	m.openAccess("s1")
	m.handleKey(tea.KeyMsg{Type: tea.KeyLeft})
	if m.pane != paneEvents {
		t.Errorf("left went to %v", m.pane)
	}
}

func TestAccessPane_ScrollsAndJumps(t *testing.T) {
	m := sizedAccessModel(t, 100, 12) // short, so the policy does not fit
	p := richPolicy()
	for i := 0; i < 60; i++ {
		p.Rules = append(p.Rules, access.Rule{Decision: access.Allow, Raw: fmt.Sprintf("Bash(cmd%02d *)", i), Source: access.Local})
	}
	m.access.policy = &p
	m.accessViews.vp.SetContent(m.accessBody())
	if m.accessViews.vp.TotalLineCount() <= m.accessViews.vp.Height {
		t.Fatalf("fixture does not overflow: %d lines in %d rows", m.accessViews.vp.TotalLineCount(), m.accessViews.vp.Height)
	}
	m.handleKey(keyRune('G'))
	if !m.accessViews.vp.AtBottom() {
		t.Error("G did not reach the bottom")
	}
	m.handleKey(keyRune('g'))
	if !m.accessViews.vp.AtTop() {
		t.Error("g did not reach the top")
	}
	m.handleKey(tea.KeyMsg{Type: tea.KeyDown})
	if m.accessViews.vp.YOffset == 0 {
		t.Error("down did not scroll")
	}
	m.handleKey(tea.KeyMsg{Type: tea.KeyPgDown})
	if m.accessViews.vp.YOffset <= 1 {
		t.Error("page down did not page")
	}
}

func TestAccessPane_FooterAdvertisesOnlyWhatWorks(t *testing.T) {
	m := sizedAccessModel(t, 100, 40)
	foot := m.helpView()
	for _, want := range []string{"[r]", "[esc]", "[?]", "[q]"} {
		if !strings.Contains(foot, want) {
			t.Errorf("footer %q lacks %s", foot, want)
		}
	}
	// A remote session can never resolve and has nothing to scroll: [r] there would be inert.
	r, _ := openedAccessModel(remoteURL, okEntry, true)
	r.openAccess("s1")
	if f := r.helpView(); strings.Contains(f, "[r]") || strings.Contains(f, "scroll") {
		t.Errorf("a remote refusal's footer advertises a key that does nothing: %q", f)
	}
	// A not-yet-harvested session CAN resolve later, so there [r] does something and is said.
	u, _ := openedAccessModel(localURL, SessionMetadata{}, false)
	u.openAccess("s1")
	if f := u.helpView(); !strings.Contains(f, "[r]") {
		t.Errorf("an unharvested session's footer should offer [r]: %q", f)
	}
}

func TestAccessPane_SlashSearchesTheRenderedLines(t *testing.T) {
	m := sizedAccessModel(t, 120, 40)
	if m.surface(paneAccess) == nil {
		t.Fatal("the pane has no search surface: `/` would do nothing")
	}
	m.accessViews.vp.SetContent(m.accessBody())
	m.searchInput = newSearchInput()
	m.handleKey(keyRune('/'))
	for _, r := range "WebFetch" {
		m.handleKey(keyRune(r))
	}
	m.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	if got := m.surface(paneAccess).matchLines(); len(got) == 0 {
		t.Errorf("searching WebFetch found nothing in the rendered rules")
	}
}

// The tall policy must reflow when the terminal is resized, not keep the width it was drawn at.
func TestAccessPane_ResizeRedraws(t *testing.T) {
	m := sizedAccessModel(t, 120, 40)
	wide := ansi.Strip(m.View())
	m.width = 50
	m.layout()
	narrow := ansi.Strip(m.View())
	if wide == narrow {
		t.Error("the pane did not redraw after a resize")
	}
	for _, l := range strings.Split(narrow, "\n") {
		if w := lipgloss.Width(l); w > 50 {
			t.Fatalf("after shrinking to 50 columns a line is %d wide: %q", w, l)
		}
	}
}

func TestAccessPane_AZeroValueModelRendersEveryPaneIncludingThisOne(t *testing.T) {
	m := &model{pane: paneAccess}
	_ = m.View() // must not panic with no client, no session, no sizes
	m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	_ = m.View()
}

// `T` and `C` are in no footer (the session-pane footers are at their width budget and drop
// hints from the front), so `V` is advertised where they are: the [?] overlay's jump section,
// from exactly the panes it works from.
func TestAccessKey_IsInTheJumpSectionFromThePanesItWorksFrom(t *testing.T) {
	for _, from := range []paneID{paneEvents, paneDetail} {
		var got bool
		for _, jt := range jumpsFrom(from) {
			got = got || jt.key == "V"
		}
		if !got {
			t.Errorf("pane %v: the jump section does not list V", from)
		}
	}
	for _, from := range []paneID{paneNamespaces, panePods, paneAccess, panePipeline, paneCatalog, paneUsage, paneAgents, paneTimeline} {
		for _, jt := range jumpsFrom(from) {
			if jt.key == "V" {
				t.Errorf("pane %v lists V, where it does nothing", from)
			}
		}
	}
}

// `r` on a refusal is not inert: the cause may have gone. A session the harvest had not reached
// is the common case, and the reader should not have to leave the pane and come back.
func TestRefreshAccess_AfterTheHarvestReachesTheSessionItResolves(t *testing.T) {
	m, r := openedAccessModel(localURL, SessionMetadata{}, false)
	if cmd := m.openAccess("s1"); cmd != nil {
		t.Fatal("an unharvested session started a resolve")
	}
	if m.access.target.Kind != targetNoEntry {
		t.Fatalf("Kind = %v, want targetNoEntry", m.access.target.Kind)
	}
	m.sessionsData["s1"] = okEntry // the background harvest lands
	cmd := m.handleKey(keyRune('r'))
	if cmd == nil {
		t.Fatal("r after the harvest reached the session did nothing")
	}
	m.handleAccessLoaded(cmd().(accessLoadedMsg))
	if m.access.target.Kind != targetOK || m.access.policy == nil || len(r.calls) != 1 {
		t.Errorf("Kind %v policy %v calls %d, want a resolved policy", m.access.target.Kind, m.access.policy, len(r.calls))
	}
}

func TestRefreshAccess_OnAStillUnresolvableTargetReadsNothing(t *testing.T) {
	m, r := openedAccessModel(remoteURL, okEntry, true)
	m.openAccess("s1")
	if cmd := m.handleKey(keyRune('r')); cmd != nil {
		cmd()
	}
	if len(r.calls) != 0 {
		t.Errorf("r on a remote session read files: %+v", r.calls)
	}
}

package tui

import (
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

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

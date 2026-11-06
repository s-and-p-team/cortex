package tui

import (
	"strings"
	"testing"

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

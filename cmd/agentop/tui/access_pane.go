package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/rossoctl/cortex/cmd/agentop/access"
)

// accessTargetKind says whether, and how much of, a session's permission policy can be shown.
type accessTargetKind int

const (
	// targetOK: the session ran on this machine and was harvested with a directory. The whole
	// policy can be resolved.
	targetOK accessTargetKind = iota
	// targetNoCwd: harvested, but the transcript recorded no directory. The user and managed
	// layers can be resolved; the project and local ones cannot, and the pane says so.
	targetNoCwd
	// The rest resolve nothing. Each carries a Reason shown in the pane's place.
	targetRemote     // the connection is not this machine's Cortex
	targetNoEntry    // the harvest has not read this session
	targetOtherAgent // a coding agent whose settings model is not Claude Code's
	targetNoClient   // not connected
)

// resolvable reports a target the resolver can be run for.
func (k accessTargetKind) resolvable() bool { return k == targetOK || k == targetNoCwd }

// accessTarget is the decision about one session: what can be shown, and the resolver input
// when something can.
//
// Input is the zero value for every kind that cannot resolve. That is the property that
// matters: nothing local is then readable by a caller that forgets to check Kind.
type accessTarget struct {
	Kind   accessTargetKind
	Reason string
	Input  access.Input
}

// accessState is the access pane's state. Its shape follows timelineState: opened with a
// session and the pane to return to, loaded off the UI goroutine under a request number so a
// slow reply cannot overwrite a newer one.
type accessState struct {
	session    string
	returnPane paneID
	// reqSeq numbers loads; a reply carrying an older number is dropped.
	reqSeq  uint64
	loading bool
	target  accessTarget
	// policy is the last resolution for session, or nil. Kept on screen while a refresh runs.
	policy *access.Policy
	err    error
}

// accessDoc is the drawn pane, searched; accessVp scrolls it.
type accessViews struct {
	vp  viewport.Model
	doc searchDoc
}

// accessTargetFor decides what the access pane can show for session. It does no I/O beyond
// access.LocalInput's reading of the environment, so the degraded cases can be tested as a
// table.
//
// THE REMOTE TEST IS THE SAME ONE `e` AND `S` USE (localCortexTarget): the connection is this
// machine's Cortex only when the endpoint on screen matches the known local endpoint. The known
// one, not localEndpointOr(): its fallback is the in-cluster 9094, and matching that would
// treat a port-forward to a pod as this laptop. Unknown is not local. A session that ran in a
// cluster has none of its files here, and showing this machine's policy for it would be the one
// confidently wrong answer this pane can give.
func (m *model) accessTargetFor(session string) accessTarget {
	if m.client == nil {
		return accessTarget{Kind: targetNoClient, Reason: "not connected to a Cortex"}
	}
	if m.localEndpoint == "" || !sameEndpoint(m.client.Endpoint(), m.localEndpoint) {
		return accessTarget{
			Kind: targetRemote,
			Reason: fmt.Sprintf("this session is on %s, not on this machine's Cortex. Its settings files "+
				"are not here, so no policy is shown; run `agentop access` on the machine it ran on.",
				access.Clean(m.client.Endpoint())),
		}
	}
	entry, ok := m.sessionsData[session]
	if !ok {
		return accessTarget{
			Kind: targetNoEntry,
			Reason: fmt.Sprintf("session %s has not been read from a Claude Code transcript yet, so its "+
				"directory is unknown. It appears after the background harvest reaches it, or run "+
				"`agentop experimental read-claude-sessions`.", access.Clean(session)),
		}
	}
	if entry.AgentType != "" && entry.AgentType != "Claude Code" {
		return accessTarget{
			Kind: targetOtherAgent,
			Reason: fmt.Sprintf("this session was run by %s. The access view resolves Claude Code's "+
				"settings model only.", access.Clean(entry.AgentType)),
		}
	}
	in, err := access.LocalInput(entry.Cwd, "", "", entry.Cwd == "")
	if err != nil {
		return accessTarget{Kind: targetNoClient, Reason: access.Clean(err.Error())}
	}
	// The entry's config dir stands in for CLAUDE_CONFIG_DIR: it is where THIS session's
	// transcript came from. LocalInput's value comes from the viewer's own environment.
	if entry.AgentConfigDir != "" {
		in.ConfigDir = entry.AgentConfigDir
	}
	in.SessionMode = entry.PermissionMode
	in.Notes = append(in.Notes, access.DescribeSession(session, entry.Title, entry.Cwd))
	if entry.Cwd == "" {
		return accessTarget{
			Kind:   targetNoCwd,
			Reason: "no working directory was recorded for this session, so the project and local settings are not shown",
			Input:  in,
		}
	}
	return accessTarget{Kind: targetOK, Input: in}
}

// accessLoadedMsg carries one resolution back to the model. req and session say which request
// it answers, so a reply that arrives after the reader moved on is recognised and dropped.
type accessLoadedMsg struct {
	req     uint64
	session string
	policy  access.Policy
	err     error
}

// openAccess enters the pane for session, remembering where to return to, and starts the
// resolution. The resolver reads several files, so it runs in the returned command and never
// on the UI goroutine.
//
// A target that cannot resolve returns no command and reads nothing: its pane shows the reason.
func (m *model) openAccess(session string) tea.Cmd {
	m.access.returnPane = m.pane
	m.pane = paneAccess
	if m.access.session != session {
		// A different session's policy must never show under this one while it loads.
		m.access.policy, m.access.err = nil, nil
	}
	m.access.session = session
	return m.refreshAccess()
}

// refreshAccess re-resolves the open session. The files may have changed since (a rule saved
// with "don't ask again" writes the local file), and nothing watches them: there is no timer,
// by design. The pane says "as of now", and a quiet auto-refresh would blur the difference
// between a policy that was edited and one that was always so.
func (m *model) refreshAccess() tea.Cmd {
	m.access.target = m.accessTargetFor(m.access.session)
	m.access.reqSeq++
	if !m.access.target.Kind.resolvable() {
		m.access.policy, m.access.err, m.access.loading = nil, nil, false
		return nil
	}
	m.access.loading = true
	resolve := m.accessResolve
	if resolve == nil {
		resolve = access.Resolve
	}
	req, session, in := m.access.reqSeq, m.access.session, m.access.target.Input
	return func() tea.Msg {
		p, err := resolve(in)
		return accessLoadedMsg{req: req, session: session, policy: p, err: err}
	}
}

func (m *model) handleAccessLoaded(msg accessLoadedMsg) {
	// A newer request exists, or the pane moved to another session: this reply is no longer
	// the answer to anything on screen.
	if msg.req != m.access.reqSeq || msg.session != m.access.session {
		return
	}
	m.access.loading = false
	if msg.err != nil {
		m.access.err = msg.err
		return
	}
	p := msg.policy
	m.access.policy, m.access.err = &p, nil
}

// accessBody is the pane's drawn lines in the viewport, searched. Task 4 replaces the body of
// this with the real rendering; until then it shows the reasons and errors.
func (m *model) accessBody() string {
	var lines []string
	switch t := m.access.target; {
	case !t.Kind.resolvable():
		lines = append(lines, strings.Split(t.Reason, "\n")...)
	case m.access.err != nil:
		lines = append(lines, "could not resolve: "+access.Clean(m.access.err.Error()))
	case m.access.loading && m.access.policy == nil:
		lines = append(lines, "resolving…")
	}
	m.accessViews.doc.setLines(lines, 0)
	return m.accessViews.doc.render(m.searchQuery(paneAccess))
}

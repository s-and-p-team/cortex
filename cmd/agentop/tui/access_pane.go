package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"

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

// openAccess enters the pane for session, remembering where to return to.
func (m *model) openAccess(session string) {
	m.access.returnPane = m.pane
	m.pane = paneAccess
	if m.access.session != session {
		m.access.policy, m.access.err = nil, nil
	}
	m.access.session = session
	m.access.target = m.accessTargetFor(session)
}

// accessBody is the pane's drawn lines in the viewport, searched. Task 4 replaces this with
// the real rendering.
func (m *model) accessBody() string {
	var lines []string
	t := m.access.target
	if !t.Kind.resolvable() {
		lines = append(lines, strings.Split(t.Reason, "\n")...)
	}
	m.accessViews.doc.setLines(lines, 0)
	return m.accessViews.doc.render(m.searchQuery(paneAccess))
}

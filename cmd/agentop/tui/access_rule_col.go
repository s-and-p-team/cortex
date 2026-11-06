package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/rossoctl/cortex/cmd/agentop/access"
	"github.com/rossoctl/cortex/core/pipeline"
)

// The RULE column says which permission rule applies to the tool calls a response asked for.
//
// WHERE THE CALLS COME FROM. The events list is fetched with view=summary, which drops
// Inference.ToolCalls from every snapshot-loaded event (core/sessionapi/summary.go); only
// SSE-streamed events keep them. The timeline's Tool.Preview is no substitute: it is clipped to
// 80 characters, and 86% of 1,773 real Bash commands are longer, so a deny at the end of a long
// compound command would be missed. Fetching whole REQUEST events is exactly what the
// projection exists to avoid. A RESPONSE event is small (median 433 B, p95 3.9 KB over 2,219
// real tool-call turns), and its FinishReason survives projection, so the column fetches the
// full response for rows whose finish reason says tools were called, a few at a time, and only
// while the column is on.
//
// A CELL FUNCTION DOES NO WORK. It runs on every rebuild of a table that can hold thousands of
// rows; it reads the cache and nothing else. Resolving the policy, fetching and matching all
// happen in ruleWork, called after Update, and land through messages.

// ruleFetchBatch is how many full responses are in flight at once.
const ruleFetchBatch = 4

// rulePolicyState is the policy the column matches against, for one session, with the calls and
// verdicts computed under it.
type rulePolicyState struct {
	session string
	policy  *access.Policy
	// ctx anchors path rules for matching.
	ctx access.MatchContext
	// ready is set once the policy is resolved.
	ready bool
	// refused is set when this session's policy cannot be shown (a remote session, an
	// unharvested one, another agent's): the column then says n/a rather than guessing.
	refused bool
	// gen identifies this policy. A reply computed under an older one is dropped, and the
	// verdict cache is discarded with it.
	gen uint64
	// calls are the tool calls fetched per response seq.
	calls map[uint64][]pipeline.InferenceToolCall
	// verdicts is the cell computed for each seq under THIS policy.
	verdicts map[uint64]ruleVerdict
	// inflight is the seqs being fetched, so none is fetched twice.
	inflight map[uint64]bool
	// resolving is set while a resolve is in flight for session.
	resolving bool
}

// ruleVerdict is what the column shows for one response, and what the detail block lists.
type ruleVerdict struct {
	cell string
	// per is the verdict for each call, in order.
	per []ruleCallVerdict
}

type ruleCallVerdict struct {
	tool, summary string
	result        access.Result
	err           error
}

// ruleCallsMsg carries the full calls of one response back to the model.
type ruleCallsMsg struct {
	session string
	seq     uint64
	calls   []pipeline.InferenceToolCall
	gen     uint64
	err     error
}

// ruleResolvedMsg carries a resolved policy back.
type ruleResolvedMsg struct {
	session string
	policy  *access.Policy
	ctx     access.MatchContext
	req     uint64
	err     error
}

// verdictRank orders verdicts by how much a reader needs to see them: a deny before an ask,
// an unevaluable rule before anything softer, and so on down to "no rule matches".
func verdictRank(v access.Verdict) int {
	switch v {
	case access.VerdictDeny:
		return 5
	case access.VerdictAsk:
		return 4
	case access.VerdictUnknown:
		return 3
	case access.VerdictPartial:
		return 2
	case access.VerdictAllow:
		return 1
	}
	return 0
}

// ruleVerdictFor matches every call a response asked for and reduces them to one cell: the
// strongest verdict, with a count when there was more than one call.
func ruleVerdictFor(p *access.Policy, ctx access.MatchContext, calls []pipeline.InferenceToolCall) ruleVerdict {
	out := ruleVerdict{}
	best := access.VerdictNone
	for _, tc := range calls {
		cv := ruleCallVerdict{tool: tc.Name}
		call, err := access.CallFromJSON(tc.Name, tc.Arguments)
		if err != nil {
			// Arguments that cannot be read are not a call no rule matched: a deny might have.
			cv.err = err
			cv.result = access.Result{Verdict: access.VerdictUnknown}
		} else {
			cv.summary = callSummary(call)
			cv.result = p.Match(call, ctx)
		}
		if verdictRank(cv.result.Verdict) > verdictRank(best) {
			best = cv.result.Verdict
		}
		out.per = append(out.per, cv)
	}
	if len(out.per) == 0 {
		return out
	}
	out.cell = best.String()
	if len(out.per) > 1 {
		out.cell = fmt.Sprintf("%s ×%d", best, len(out.per))
	}
	return out
}

// callSummary is the primary argument of a call, for display. It is raw tool input and is
// cleaned by whoever draws it.
func callSummary(c access.Call) string {
	for _, k := range [...]string{"command", "file_path", "notebook_path", "path", "url", "subagent_type", "skill"} {
		if v, ok := c.Input[k].(string); ok {
			return v
		}
	}
	return ""
}

// isToolCallResponse reports a response event whose model asked for tools. FinishReason is the
// one fact about this that survives view=summary: Anthropic's "tool_use", chat completions'
// "tool_calls".
func isToolCallResponse(e *pipeline.SessionEvent) bool {
	if e == nil || e.Phase != pipeline.SessionResponse || e.Inference == nil {
		return false
	}
	if len(e.Inference.ToolCalls) > 0 {
		return true
	}
	switch e.Inference.FinishReason {
	case "tool_use", "tool_calls":
		return true
	}
	return false
}

// ruleCell is the RULE cell for one row. It reads the cache and does nothing else.
func (m *model) ruleCell(e *pipeline.SessionEvent) string {
	if !isToolCallResponse(e) {
		return ""
	}
	st := m.rulePolicy
	switch {
	case st == nil:
		return ""
	case st.refused:
		return "n/a"
	case !st.ready:
		return "…"
	}
	if v, ok := st.verdicts[e.Seq]; ok {
		return v.cell
	}
	// The row already carries its calls (an SSE-streamed event is not projected): use them, and
	// remember the verdict. Matching is cheap and bounded, and this is the only place a cell
	// writes, to a cache the next rebuild reads.
	if len(e.Inference.ToolCalls) > 0 {
		v := ruleVerdictFor(st.policy, st.ctx, e.Inference.ToolCalls)
		if st.verdicts == nil {
			st.verdicts = map[uint64]ruleVerdict{}
		}
		st.verdicts[e.Seq] = v
		return v.cell
	}
	return "…"
}

// ruleColumnOn reports whether the RULE column is shown.
func (m *model) ruleColumnOn() bool { return m.eventColumns[colRule] }

// ruleWant is a response to fetch.
type ruleWant struct {
	session string
	seq     uint64
}

// ruleWanted lists the responses to fetch now: tool-call responses of the session on screen
// whose calls are not cached and not already on their way, at most ruleFetchBatch minus what is
// in flight. Nothing while the column is off, the policy is not ready, or the target is refused.
func (m *model) ruleWanted() []ruleWant {
	st := m.rulePolicy
	if !m.ruleColumnOn() || st == nil || !st.ready || st.refused || st.session != m.selectedSess {
		return nil
	}
	room := ruleFetchBatch - len(st.inflight)
	if room <= 0 {
		return nil
	}
	var out []ruleWant
	for i := len(m.events[st.session]) - 1; i >= 0 && len(out) < room; i-- { // newest first: what the reader is looking at
		e := &m.events[st.session][i]
		if !isToolCallResponse(e) || len(e.Inference.ToolCalls) > 0 {
			continue
		}
		if _, have := st.calls[e.Seq]; have || st.inflight[e.Seq] {
			continue
		}
		out = append(out, ruleWant{session: eventSession(st.session, e), seq: e.Seq})
	}
	return out
}

// ruleWork starts whatever the RULE column needs: the policy for the session on screen, then
// the calls of the responses it has not seen. It is called after Update, never from a cell.
func (m *model) ruleWork() tea.Cmd {
	if !m.ruleColumnOn() || m.pane != paneEvents && m.pane != paneDetail || m.selectedSess == "" {
		return nil
	}
	st := m.rulePolicy
	if st == nil || st.session != m.selectedSess {
		return m.resolveRulePolicy(m.selectedSess)
	}
	if !st.ready || st.refused {
		return nil
	}
	wants := m.ruleWanted()
	if len(wants) == 0 {
		return nil
	}
	if st.inflight == nil {
		st.inflight = map[uint64]bool{}
	}
	var cmds []tea.Cmd
	for _, w := range wants {
		st.inflight[w.seq] = true
		client, ctx, gen, w := m.client, m.ctx, st.gen, w
		cmds = append(cmds, func() tea.Msg {
			ev, err := client.GetEvent(ctx, w.session, w.seq)
			msg := ruleCallsMsg{session: st.session, seq: w.seq, gen: gen, err: err}
			if err == nil && ev != nil && ev.Inference != nil {
				msg.calls = ev.Inference.ToolCalls
			}
			return msg
		})
	}
	return tea.Batch(cmds...)
}

// resolveRulePolicy starts the resolution of session's policy, or marks the column refused when
// there is none to show. It reuses accessTargetFor, so the column and the pane can never
// disagree about what may be read.
func (m *model) resolveRulePolicy(session string) tea.Cmd {
	t := m.accessTargetFor(session)
	gen := uint64(1)
	if m.rulePolicy != nil {
		gen = m.rulePolicy.gen + 1
	}
	st := &rulePolicyState{session: session, gen: gen}
	m.rulePolicy = st
	if !t.Kind.resolvable() {
		st.refused = true
		return nil
	}
	st.resolving = true
	resolve := m.accessResolve
	if resolve == nil {
		resolve = access.Resolve
	}
	in := t.Input
	ctx := access.MatchContext{Cwd: in.Cwd, Home: in.Home, ConfigDir: in.ConfigDir}
	if ctx.ConfigDir == "" && in.Home != "" {
		ctx.ConfigDir = in.Home + "/.claude"
	}
	return func() tea.Msg {
		p, err := resolve(in)
		return ruleResolvedMsg{session: session, policy: &p, ctx: ctx, req: gen, err: err}
	}
}

// setRulePolicy installs a resolved policy and discards every verdict computed under the last.
func (m *model) setRulePolicy(session string, p *access.Policy) {
	gen := uint64(1)
	if m.rulePolicy != nil {
		gen = m.rulePolicy.gen + 1
	}
	m.rulePolicy = &rulePolicyState{session: session, policy: p, ready: true, gen: gen}
}

func (m *model) applyRuleResolved(msg ruleResolvedMsg) {
	st := m.rulePolicy
	if st == nil || st.session != msg.session || st.gen != msg.req {
		return
	}
	st.resolving = false
	if msg.err != nil || msg.policy == nil {
		st.refused = true
		return
	}
	st.policy, st.ctx, st.ready = msg.policy, msg.ctx, true
}

// applyRuleCalls stores the calls of one response and the verdict computed from them. A reply
// for another session, or computed under an older policy, is dropped.
func (m *model) applyRuleCalls(msg ruleCallsMsg) {
	st := m.rulePolicy
	if st == nil || st.session != msg.session || st.gen != msg.gen {
		return
	}
	delete(st.inflight, msg.seq)
	if msg.err != nil {
		// Remember the failure as "no calls" so the row is not refetched in a loop; the pane's r
		// (which drops the policy state) tries again.
		if st.calls == nil {
			st.calls = map[uint64][]pipeline.InferenceToolCall{}
		}
		st.calls[msg.seq] = nil
		return
	}
	if st.calls == nil {
		st.calls = map[uint64][]pipeline.InferenceToolCall{}
		st.verdicts = map[uint64]ruleVerdict{}
	}
	if st.verdicts == nil {
		st.verdicts = map[uint64]ruleVerdict{}
	}
	st.calls[msg.seq] = msg.calls
	if st.policy != nil {
		st.verdicts[msg.seq] = ruleVerdictFor(st.policy, st.ctx, msg.calls)
	}
}

// accessDetailBlock is the "ACCESS" block of the event detail: each tool call, the strongest
// rule that applies to it, and what is not known. Empty when there is nothing to say.
func (m *model) accessDetailBlock(e *pipeline.SessionEvent) string {
	if !isToolCallResponse(e) {
		return ""
	}
	st := m.rulePolicy
	if st == nil {
		return ""
	}
	if st.refused {
		return styleHint.Render("ACCESS  not available for this session (its settings are not on this machine, or it has not been read yet)")
	}
	if !st.ready {
		return ""
	}
	calls := e.Inference.ToolCalls
	if len(calls) == 0 {
		calls = st.calls[e.Seq]
	}
	if len(calls) == 0 {
		return ""
	}
	v, ok := st.verdicts[e.Seq]
	if !ok {
		v = ruleVerdictFor(st.policy, st.ctx, calls)
	}
	var b strings.Builder
	b.WriteString(styleTitle.Render("ACCESS"))
	b.WriteString(styleHint.Render("  which rule applies to each call (not what happened: the mode, hooks and the read-only set also decide)"))
	for i, cv := range v.per {
		b.WriteString("\n  ")
		b.WriteString(access.Clean(cv.tool))
		if cv.summary != "" {
			b.WriteString(" ")
			b.WriteString(access.Clean(truncRight(cv.summary, 70)))
		}
		fmt.Fprintf(&b, "  → %s", cv.result.Verdict)
		for _, r := range cv.result.Rules {
			fmt.Fprintf(&b, "  %s %s (%s)", r.Decision, access.Clean(r.Raw), r.Source)
		}
		if cv.err != nil {
			fmt.Fprintf(&b, "  arguments unreadable: %s", access.Clean(cv.err.Error()))
		}
		for _, c := range cv.result.Caveats {
			b.WriteString("\n      · ")
			b.WriteString(access.Clean(c))
		}
		_ = i
	}
	return b.String()
}

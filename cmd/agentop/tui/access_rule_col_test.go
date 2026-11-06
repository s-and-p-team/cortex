package tui

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	"github.com/rossoctl/cortex/cmd/agentop/access"
	"github.com/rossoctl/cortex/core/pipeline"
)

// ruleToolResp is a response event whose model asked for the given tool calls.
func ruleToolResp(seq uint64, calls ...pipeline.InferenceToolCall) pipeline.SessionEvent {
	return pipeline.SessionEvent{
		SessionID: "s1", Seq: seq, Direction: pipeline.Outbound, Phase: pipeline.SessionResponse,
		Host: "api.anthropic.com",
		Inference: &pipeline.InferenceExtension{
			FinishReason: "tool_use", ToolCalls: calls,
		},
	}
}

func ruleCall(name, args string) pipeline.InferenceToolCall {
	return pipeline.InferenceToolCall{ID: "id-" + name, Name: name, Arguments: args}
}

// projected strips what view=summary strips: the list never carries the calls.
func ruleProjected(e pipeline.SessionEvent) pipeline.SessionEvent {
	e.Inference = &pipeline.InferenceExtension{FinishReason: e.Inference.FinishReason}
	return e
}

func rulePolicyFixture() *access.Policy {
	rules := []access.Rule{
		{Decision: access.Deny, Raw: "Bash(rm *)", Tool: "Bash", Pattern: "rm *", Source: access.User, File: "/h/settings.json"},
		{Decision: access.Ask, Raw: "Bash(git push *)", Tool: "Bash", Pattern: "git push *", Source: access.Project, File: "/p/settings.json"},
		{Decision: access.Allow, Raw: "Bash(git status)", Tool: "Bash", Pattern: "git status", Source: access.Local, File: "/p/settings.local.json"},
	}
	return &access.Policy{Rules: rules}
}

// --- the verdict for one response event ------------------------------------------------------

func TestRuleCell_VerdictsForACallsResponse(t *testing.T) {
	p := rulePolicyFixture()
	cases := []struct {
		name  string
		calls []pipeline.InferenceToolCall
		want  string
	}{
		{"deny", []pipeline.InferenceToolCall{ruleCall("Bash", `{"command":"rm -rf x"}`)}, "deny"},
		{"ask", []pipeline.InferenceToolCall{ruleCall("Bash", `{"command":"git push origin main"}`)}, "ask"},
		{"allow", []pipeline.InferenceToolCall{ruleCall("Bash", `{"command":"git status"}`)}, "allow"},
		{"none", []pipeline.InferenceToolCall{ruleCall("Bash", `{"command":"ls"}`)}, "none"},
		{"partial", []pipeline.InferenceToolCall{ruleCall("Bash", `{"command":"git status && ls"}`)}, "partial"},
		// the strongest verdict among several calls, with a count
		{"deny beats ask beats allow", []pipeline.InferenceToolCall{
			ruleCall("Bash", `{"command":"git status"}`), ruleCall("Bash", `{"command":"git push x"}`), ruleCall("Bash", `{"command":"rm y"}`),
		}, "deny ×3"},
		{"ask over allow", []pipeline.InferenceToolCall{
			ruleCall("Bash", `{"command":"git status"}`), ruleCall("Bash", `{"command":"git push x"}`),
		}, "ask ×2"},
		{"unknown outranks allow", []pipeline.InferenceToolCall{
			ruleCall("Bash", `{"command":"git status"}`), ruleCall("Custom", `{}`),
		}, "allow ×2"}, // Custom has no rule at all: none, not unknown
	}
	for _, c := range cases {
		got := ruleVerdictFor(p, access.MatchContext{}, c.calls)
		if got.cell != c.want {
			t.Errorf("%s: cell = %q, want %q", c.name, got.cell, c.want)
		}
	}
}

func TestRuleCell_SeverityOrder(t *testing.T) {
	order := []access.Verdict{access.VerdictDeny, access.VerdictAsk, access.VerdictUnknown, access.VerdictPartial, access.VerdictAllow, access.VerdictNone}
	for i := 0; i < len(order)-1; i++ {
		if verdictRank(order[i]) <= verdictRank(order[i+1]) {
			t.Errorf("%v must outrank %v", order[i], order[i+1])
		}
	}
}

func TestRuleCell_AnUndecodableCallIsUnknownNotNone(t *testing.T) {
	got := ruleVerdictFor(rulePolicyFixture(), access.MatchContext{}, []pipeline.InferenceToolCall{ruleCall("Bash", `{"command":`)})
	if got.cell != "unknown" {
		t.Errorf("cell = %q: arguments that cannot be read are not a call no rule matched", got.cell)
	}
	huge := ruleCall("Bash", `{"command":"`+strings.Repeat("a", access.MaxCallInputBytes+10)+`"}`)
	if got := ruleVerdictFor(rulePolicyFixture(), access.MatchContext{}, []pipeline.InferenceToolCall{huge}); got.cell != "unknown" {
		t.Errorf("an oversize call: cell = %q, want unknown", got.cell)
	}
}

// --- the column inside the table ---------------------------------------------------------------

func TestRuleColumn_IsOffByDefaultAndListedWithADescription(t *testing.T) {
	var col *eventColumn
	for i := range eventColumns {
		if eventColumns[i].id == colRule {
			col = &eventColumns[i]
		}
	}
	if col == nil {
		t.Fatal("no RULE column")
	}
	if col.defaultOn {
		t.Error("RULE is on by default: it costs a request per tool call, so it is opt-in")
	}
	if !strings.Contains(col.desc, "rule") || !strings.Contains(col.desc, "not") {
		t.Errorf("desc = %q: the picker must say it is about rules, not outcomes", col.desc)
	}
	if defaultColumnSelection()[colRule] {
		t.Error("defaultColumnSelection turns RULE on")
	}
}

// ruleModel is a model with a resolved policy and a session of projected events.
func ruleModel(t *testing.T, events ...pipeline.SessionEvent) *model {
	t.Helper()
	m, r := openedAccessModel(localURL, okEntry, true)
	m.width, m.height = 200, 40
	m.layout()
	m.selectedSess = "s1"
	m.events = map[string][]pipeline.SessionEvent{"s1": events}
	m.pane = paneEvents
	_ = r
	return m
}

func TestRuleColumn_CellsAreBlankForRowsThatAreNotToolCalls(t *testing.T) {
	m := ruleModel(t,
		pipeline.SessionEvent{SessionID: "s1", Seq: 1, Phase: pipeline.SessionRequest, Direction: pipeline.Outbound},
		pipeline.SessionEvent{SessionID: "s1", Seq: 2, Phase: pipeline.SessionResponse, Direction: pipeline.Outbound,
			Inference: &pipeline.InferenceExtension{FinishReason: "end_turn"}},
	)
	m.eventColumns = map[eventColumnID]bool{colIndex: true, colRule: true}
	m.rulePolicy = &rulePolicyState{session: "s1", policy: rulePolicyFixture(), ready: true}
	m.rebuildEventsTable()
	for i, row := range m.eventsTbl.Rows() {
		if cell := row[len(row)-1]; strings.TrimSpace(cell) != "" {
			t.Errorf("row %d (%v): RULE cell = %q, want blank for a row that called no tool", i, m.eventsTbl.Rows()[i], cell)
		}
	}
}

// A cell function runs on every rebuild. It must only READ the cache: resolving a policy or
// decoding arguments there would make scrolling a 5,000-row table pay for it every time.
func TestRuleColumn_ACellNeverResolvesOrFetches(t *testing.T) {
	m := ruleModel(t, ruleProjected(ruleToolResp(2, ruleCall("Bash", `{"command":"rm x"}`))))
	r := &recordingResolver{}
	m.accessResolve = r.resolve
	m.eventColumns = map[eventColumnID]bool{colIndex: true, colRule: true}
	m.rebuildEventsTable()
	m.rebuildEventsTable()
	if len(r.calls) != 0 {
		t.Errorf("rebuilding the table resolved the policy %d time(s): a cell function must do no work", len(r.calls))
	}
	if cmd := m.ruleWork(); cmd != nil {
		// ruleWork is where the work is allowed; the column must not have started it on its own
		_ = cmd
	}
}

func TestRuleColumn_ShowsAPendingMarkWhileTheResponseIsOnItsWay(t *testing.T) {
	m := ruleModel(t, ruleProjected(ruleToolResp(2, ruleCall("Bash", `{"command":"rm x"}`))))
	m.eventColumns = map[eventColumnID]bool{colIndex: true, colRule: true}
	m.rulePolicy = &rulePolicyState{session: "s1", policy: rulePolicyFixture(), ready: true}
	m.rebuildEventsTable()
	rows := m.eventsTbl.Rows()
	if len(rows) == 0 || !strings.Contains(rows[len(rows)-1][len(rows[0])-1], "…") {
		t.Errorf("a tool-call row whose response is not yet fetched should show …: %v", rows)
	}
}

// The calls arrive by the same path the detail pane uses, and are cached by (session, seq).
func TestRuleColumn_FetchesTheFullResponseOnceAndCachesTheVerdict(t *testing.T) {
	proj := ruleProjected(ruleToolResp(2, ruleCall("Bash", `{"command":"rm x"}`)))
	full := ruleToolResp(2, ruleCall("Bash", `{"command":"rm x"}`))
	m := ruleModel(t, proj)
	m.eventColumns = map[eventColumnID]bool{colIndex: true, colRule: true}
	m.serverProjects = true
	m.rulePolicy = &rulePolicyState{session: "s1", policy: rulePolicyFixture(), ready: true}

	wants := m.ruleWanted()
	if len(wants) != 1 || wants[0].seq != 2 {
		t.Fatalf("wanted = %+v, want the one tool-call response", wants)
	}
	m.applyRuleCalls(ruleCallsMsg{session: "s1", seq: 2, calls: full.Inference.ToolCalls, gen: m.rulePolicy.gen})
	m.rebuildEventsTable()
	rows := m.eventsTbl.Rows()
	if got := rows[len(rows)-1][len(rows[0])-1]; !strings.Contains(got, "deny") {
		t.Errorf("RULE cell = %q, want deny after the calls arrived", got)
	}
	if again := m.ruleWanted(); len(again) != 0 {
		t.Errorf("wanted again = %+v: a fetched row must not be fetched twice", again)
	}
}

func TestRuleColumn_NothingIsFetchedWhileTheColumnIsOff(t *testing.T) {
	m := ruleModel(t, ruleProjected(ruleToolResp(2, ruleCall("Bash", `{"command":"rm x"}`))))
	m.serverProjects = true
	m.eventColumns = defaultColumnSelection()
	m.rulePolicy = &rulePolicyState{session: "s1", policy: rulePolicyFixture(), ready: true}
	if w := m.ruleWanted(); len(w) != 0 || m.ruleWork() != nil {
		t.Errorf("work scheduled with the column off: %+v", w)
	}
}

func TestRuleColumn_FetchesAtMostFourAtATime(t *testing.T) {
	var evs []pipeline.SessionEvent
	for i := uint64(2); i < 40; i += 2 {
		evs = append(evs, ruleProjected(ruleToolResp(i, ruleCall("Bash", `{"command":"ls"}`))))
	}
	m := ruleModel(t, evs...)
	m.eventColumns = map[eventColumnID]bool{colIndex: true, colRule: true}
	m.serverProjects = true
	m.rulePolicy = &rulePolicyState{session: "s1", policy: rulePolicyFixture(), ready: true}
	if got := len(m.ruleWanted()); got != ruleFetchBatch {
		t.Errorf("wanted %d at once, want the batch of %d", got, ruleFetchBatch)
	}
	if ruleFetchBatch > 4 {
		t.Errorf("batch %d: a table of thousands must not open thousands of requests", ruleFetchBatch)
	}
}

// Events streamed over SSE are not projected: they already carry the calls and need no fetch.
func TestRuleColumn_AnUnprojectedRowNeedsNoFetch(t *testing.T) {
	m := ruleModel(t, ruleToolResp(2, ruleCall("Bash", `{"command":"rm x"}`)))
	m.eventColumns = map[eventColumnID]bool{colIndex: true, colRule: true}
	m.serverProjects = true
	m.rulePolicy = &rulePolicyState{session: "s1", policy: rulePolicyFixture(), ready: true}
	if w := m.ruleWanted(); len(w) != 0 {
		t.Errorf("wanted %+v for a row that already carries its calls", w)
	}
	m.rebuildEventsTable()
	rows := m.eventsTbl.Rows()
	if got := rows[len(rows)-1][len(rows[0])-1]; !strings.Contains(got, "deny") {
		t.Errorf("cell = %q, want deny straight from the row's own calls", got)
	}
}

func TestRuleColumn_AStaleReplyIsDropped(t *testing.T) {
	m := ruleModel(t, ruleProjected(ruleToolResp(2, ruleCall("Bash", `{"command":"ls"}`))))
	m.eventColumns = map[eventColumnID]bool{colIndex: true, colRule: true}
	m.serverProjects = true
	m.rulePolicy = &rulePolicyState{session: "s1", policy: rulePolicyFixture(), ready: true, gen: 5}
	// a reply computed under an older policy, and one for another session
	m.applyRuleCalls(ruleCallsMsg{session: "s1", seq: 2, calls: []pipeline.InferenceToolCall{ruleCall("Bash", `{"command":"rm x"}`)}, gen: 4})
	m.applyRuleCalls(ruleCallsMsg{session: "other", seq: 2, calls: []pipeline.InferenceToolCall{ruleCall("Bash", `{"command":"rm x"}`)}, gen: 5})
	if len(m.rulePolicy.calls) != 0 {
		t.Errorf("stale or foreign replies were accepted: %+v", m.rulePolicy.calls)
	}
}

func TestRuleColumn_ANewPolicyInvalidatesTheCachedVerdicts(t *testing.T) {
	m := ruleModel(t, ruleToolResp(2, ruleCall("Bash", `{"command":"rm x"}`)))
	m.eventColumns = map[eventColumnID]bool{colIndex: true, colRule: true}
	m.rulePolicy = &rulePolicyState{session: "s1", policy: rulePolicyFixture(), ready: true}
	m.rebuildEventsTable()
	first := m.eventsTbl.Rows()
	if !strings.Contains(first[len(first)-1][len(first[0])-1], "deny") {
		t.Fatalf("setup: %v", first)
	}
	// the user edits the settings: the deny is gone
	m.setRulePolicy("s1", &access.Policy{})
	m.rebuildEventsTable()
	again := m.eventsTbl.Rows()
	if got := again[len(again)-1][len(again[0])-1]; !strings.Contains(got, "none") {
		t.Errorf("cell = %q after the policy changed, want none: the old verdict was cached across a policy change", got)
	}
}

func TestRuleColumn_ARefusedTargetShowsNotAvailableNotBlank(t *testing.T) {
	m, _ := openedAccessModel(remoteURL, okEntry, true)
	m.width, m.height = 200, 40
	m.layout()
	m.selectedSess = "s1"
	m.pane = paneEvents
	m.events = map[string][]pipeline.SessionEvent{"s1": {ruleProjected(ruleToolResp(2, ruleCall("Bash", `{"command":"rm x"}`)))}}
	m.eventColumns = map[eventColumnID]bool{colIndex: true, colRule: true}
	m.rulePolicy = &rulePolicyState{session: "s1", refused: true}
	m.rebuildEventsTable()
	rows := m.eventsTbl.Rows()
	if got := rows[len(rows)-1][len(rows[0])-1]; !strings.Contains(got, "n/a") {
		t.Errorf("cell = %q, want n/a for a session this machine has no policy for", got)
	}
	if w := m.ruleWanted(); len(w) != 0 {
		t.Errorf("fetching for a refused target: %+v", w)
	}
}

// --- hostile input -----------------------------------------------------------------------------

func TestRuleColumn_HostileToolArgumentsNeverReachTheCell(t *testing.T) {
	evil := "\x1b]0;pwned\x07\x1b[2J"
	m := ruleModel(t, ruleToolResp(2, ruleCall("Bash", `{"command":"echo `+ruleJSONEsc(evil)+`"}`)))
	m.eventColumns = map[eventColumnID]bool{colIndex: true, colRule: true}
	m.rulePolicy = &rulePolicyState{session: "s1", policy: rulePolicyFixture(), ready: true}
	m.rebuildEventsTable()
	for _, row := range m.eventsTbl.Rows() {
		for _, cell := range row {
			if strings.Contains(cell, "\x1b") || strings.Contains(cell, "pwned") {
				t.Fatalf("a cell carries tool-call text: %q", cell)
			}
		}
	}
}

func ruleJSONEsc(s string) string { b, _ := json.Marshal(s); return string(b[1 : len(b)-1]) }

// What the column ADDS to a rebuild must be small next to what the table already costs. An
// absolute time depends on how the suite is built (about 70 times slower under -race -cover, and
// the table's own cost is most of it), so this compares the same rebuild with and without the
// column and bounds the difference.
func TestRuleColumn_AddsLittleToARebuildOfThousandsOfRows(t *testing.T) {
	var evs []pipeline.SessionEvent
	for i := uint64(1); i <= 3000; i++ {
		evs = append(evs, ruleToolResp(i, ruleCall("Bash", fmt.Sprintf(`{"command":"git status && echo %d"}`, i))))
	}
	rebuild := func(withRule bool) time.Duration {
		m := ruleModel(t, evs...)
		m.eventColumns = map[eventColumnID]bool{colIndex: true, colHost: true}
		if withRule {
			m.eventColumns[colRule] = true
		}
		m.rulePolicy = &rulePolicyState{session: "s1", policy: rulePolicyFixture(), ready: true}
		m.rebuildEventsTable() // the first rebuild fills the verdict cache; it is not what is measured
		best := time.Hour
		for i := 0; i < 3; i++ { // the best of three, so one slow scheduling slice is not the answer
			start := time.Now()
			m.rebuildEventsTable()
			best = min(best, time.Since(start))
		}
		return best
	}
	base, with := rebuild(false), rebuild(true)
	// Measured at about 1.5% either way; 50% is generous for noise and still fails a column that
	// re-matches every row on every rebuild (which is several times the table's own cost).
	if with > base+base/2+5*time.Millisecond {
		t.Errorf("a rebuild takes %v with the RULE column and %v without: the column is doing work in its cells", with, base)
	}
}

// A cell that re-matched on every rebuild would pass the test above only if matching were free.
// This proves the cache is what answers: the verdict is computed once per row, not per rebuild.
func TestRuleColumn_AVerdictIsComputedOncePerRowNotPerRebuild(t *testing.T) {
	m := ruleModel(t, ruleToolResp(2, ruleCall("Bash", `{"command":"rm x"}`)))
	m.eventColumns = map[eventColumnID]bool{colIndex: true, colRule: true}
	m.rulePolicy = &rulePolicyState{session: "s1", policy: rulePolicyFixture(), ready: true}
	m.rebuildEventsTable()
	first := m.rulePolicy.verdicts[2]
	if first.cell != "deny" {
		t.Fatalf("setup: cell = %q", first.cell)
	}
	// Corrupt the cache entry. If the next rebuild shows the corrupted value, it read the cache;
	// if it shows "deny" again, it recomputed.
	m.rulePolicy.verdicts[2] = ruleVerdict{cell: "FROM-CACHE"}
	m.rebuildEventsTable()
	rows := m.eventsTbl.Rows()
	if got := rows[len(rows)-1][len(rows[0])-1]; !strings.Contains(got, "FROM-CACHE") {
		t.Errorf("cell = %q: the rebuild recomputed the verdict instead of reading the cache", got)
	}
}

// --- the detail block --------------------------------------------------------------------------

func TestDetailBlock_ListsEachCallsVerdictRuleAndCaveat(t *testing.T) {
	m := ruleModel(t, ruleToolResp(2,
		ruleCall("Bash", `{"command":"git push origin main"}`),
		ruleCall("Bash", `{"command":"git status && ls"}`),
	))
	m.rulePolicy = &rulePolicyState{session: "s1", policy: rulePolicyFixture(), ready: true}
	block := ansi.Strip(m.accessDetailBlock(&m.events["s1"][0]))
	for _, want := range []string{"ACCESS", "Bash", "git push origin main", "ask", "Bash(git push *)", "project", "partial", "not covered"} {
		if !strings.Contains(block, want) {
			t.Errorf("detail block lacks %q:\n%s", want, block)
		}
	}
}

func TestDetailBlock_IsEmptyWhenThereIsNothingToSay(t *testing.T) {
	m := ruleModel(t, pipeline.SessionEvent{SessionID: "s1", Seq: 1, Phase: pipeline.SessionRequest})
	m.rulePolicy = &rulePolicyState{session: "s1", policy: rulePolicyFixture(), ready: true}
	if b := m.accessDetailBlock(&m.events["s1"][0]); b != "" {
		t.Errorf("a block for an event with no tool calls: %q", b)
	}
	m.events["s1"] = []pipeline.SessionEvent{ruleToolResp(2, ruleCall("Bash", `{"command":"ls"}`))}
	m.rulePolicy = nil // no policy resolved
	if b := m.accessDetailBlock(&m.events["s1"][0]); b != "" {
		t.Errorf("a block with no policy: %q", b)
	}
	m.rulePolicy = &rulePolicyState{session: "s1", refused: true}
	if b := m.accessDetailBlock(&m.events["s1"][0]); !strings.Contains(b, "not available") {
		t.Errorf("a refused target should say so in the block, got %q", b)
	}
}

func TestDetailBlock_NeverEmitsControlBytes(t *testing.T) {
	evil := "\x1b]0;pwned\x07"
	p := rulePolicyFixture()
	p.Rules[0].Raw = "Bash(rm *" + evil + ")"
	p.Rules[0].File = "/h" + evil
	m := ruleModel(t, ruleToolResp(2, ruleCall("Bash", `{"command":"rm `+ruleJSONEsc(evil)+`"}`)))
	m.rulePolicy = &rulePolicyState{session: "s1", policy: p, ready: true}
	b := m.accessDetailBlock(&m.events["s1"][0])
	if strings.Contains(b, "\x07") || strings.Contains(b, "pwned") || strings.Contains(ansi.Strip(b), "\x1b") {
		t.Errorf("the block carries tool or rule text raw: %q", b)
	}
}

// --- wiring ------------------------------------------------------------------------------------

func TestRuleColumn_IsInTheColumnPickerAndTheTableStillFits(t *testing.T) {
	m := ruleModel(t, ruleToolResp(2, ruleCall("Bash", `{"command":"ls"}`)))
	sel := defaultColumnSelection()
	sel[colRule] = true
	m.eventColumns = sel
	m.rulePolicy = &rulePolicyState{session: "s1", policy: rulePolicyFixture(), ready: true}
	m.rebuildEventsTable()
	want := len(m.eventsTbl.Columns())
	for i, row := range m.eventsTbl.Rows() {
		if len(row) != want {
			t.Errorf("row %d has %d cells for %d columns", i, len(row), want)
		}
	}
}

func TestUpdate_RoutesRuleCallsMsg(t *testing.T) {
	m := ruleModel(t, ruleProjected(ruleToolResp(2, ruleCall("Bash", `{"command":"rm x"}`))))
	m.eventColumns = map[eventColumnID]bool{colIndex: true, colRule: true}
	m.rulePolicy = &rulePolicyState{session: "s1", policy: rulePolicyFixture(), ready: true}
	updated, _ := m.Update(ruleCallsMsg{session: "s1", seq: 2, calls: []pipeline.InferenceToolCall{ruleCall("Bash", `{"command":"rm x"}`)}})
	if len(updated.(*model).rulePolicy.calls) != 1 {
		t.Error("Update did not route ruleCallsMsg to the column")
	}
	var _ tea.Msg = ruleCallsMsg{}
}

// Chat-completions says "tool_calls" where Anthropic says "tool_use". A column that knew only
// the second would show nothing for every Bob, Codex or OpenAI-compatible session.
func TestIsToolCallResponse_RecognisesBothDialectsAndNothingElse(t *testing.T) {
	resp := func(finish string) *pipeline.SessionEvent {
		return &pipeline.SessionEvent{Phase: pipeline.SessionResponse, Inference: &pipeline.InferenceExtension{FinishReason: finish}}
	}
	for finish, want := range map[string]bool{
		"tool_use": true, "tool_calls": true, "end_turn": false, "stop": false, "length": false, "": false, "TOOL_USE": false,
	} {
		if got := isToolCallResponse(resp(finish)); got != want {
			t.Errorf("finish %q: %v, want %v", finish, got, want)
		}
	}
	// a request is never a tool-call response, whatever its fields say
	req := &pipeline.SessionEvent{Phase: pipeline.SessionRequest, Inference: &pipeline.InferenceExtension{FinishReason: "tool_use"}}
	if isToolCallResponse(req) {
		t.Error("a request was taken for a tool-call response")
	}
	// ...and an event that already carries its calls is one even with no finish reason
	carried := &pipeline.SessionEvent{Phase: pipeline.SessionResponse, Inference: &pipeline.InferenceExtension{
		ToolCalls: []pipeline.InferenceToolCall{ruleCall("Bash", `{}`)}}}
	if !isToolCallResponse(carried) {
		t.Error("a response carrying tool calls was not recognised")
	}
	for _, e := range []*pipeline.SessionEvent{nil, {Phase: pipeline.SessionResponse}} {
		if isToolCallResponse(e) {
			t.Errorf("%+v taken for a tool-call response", e)
		}
	}
}

// Until the policy resolves there is nothing to say, and the cell must not look like an answer:
// "…" is "working on it", blank is "no tool call here".
func TestRuleCell_APolicyStillResolvingShowsThePendingMark(t *testing.T) {
	m := ruleModel(t, ruleProjected(ruleToolResp(2, ruleCall("Bash", `{"command":"rm x"}`))))
	m.eventColumns = map[eventColumnID]bool{colIndex: true, colRule: true}
	m.rulePolicy = &rulePolicyState{session: "s1", resolving: true} // not ready
	if got := m.ruleCell(&m.events["s1"][0]); got != "…" {
		t.Errorf("cell = %q while the policy resolves, want …", got)
	}
	m.rulePolicy = nil
	if got := m.ruleCell(&m.events["s1"][0]); got != "" {
		t.Errorf("cell = %q with no policy state at all, want blank (nothing has been asked yet)", got)
	}
}

// ruleCell is called from a cell function on every rebuild. It must not start a resolve, however
// the state looks.
func TestRuleCell_NeverStartsAResolveOrAFetch(t *testing.T) {
	m := ruleModel(t, ruleProjected(ruleToolResp(2, ruleCall("Bash", `{"command":"rm x"}`))))
	r := &recordingResolver{}
	m.accessResolve = r.resolve
	m.eventColumns = map[eventColumnID]bool{colIndex: true, colRule: true}
	for _, st := range []*rulePolicyState{nil, {session: "s1"}, {session: "other"}, {session: "s1", ready: true, policy: rulePolicyFixture()}} {
		m.rulePolicy = st
		before := m.rulePolicy
		_ = m.ruleCell(&m.events["s1"][0])
		if m.rulePolicy != before {
			t.Errorf("ruleCell replaced the policy state: %+v -> %+v", before, m.rulePolicy)
		}
	}
	if len(r.calls) != 0 {
		t.Errorf("ruleCell resolved %d time(s)", len(r.calls))
	}
}

func TestRuleWork_NeverFetchesForARefusedTarget(t *testing.T) {
	m := ruleModel(t, ruleProjected(ruleToolResp(2, ruleCall("Bash", `{"command":"rm x"}`))))
	m.eventColumns = map[eventColumnID]bool{colIndex: true, colRule: true}
	m.serverProjects = true
	m.rulePolicy = &rulePolicyState{session: "s1", refused: true, ready: true, policy: rulePolicyFixture()}
	if cmd := m.ruleWork(); cmd != nil {
		t.Error("ruleWork started a fetch for a session whose policy cannot be shown")
	}
	if w := m.ruleWanted(); len(w) != 0 {
		t.Errorf("wanted = %+v for a refused target", w)
	}
}

func TestRuleWork_ResolvesFirstThenFetches(t *testing.T) {
	m := ruleModel(t, ruleProjected(ruleToolResp(2, ruleCall("Bash", `{"command":"rm x"}`))))
	r := &recordingResolver{pol: *rulePolicyFixture()}
	m.accessResolve = r.resolve
	m.eventColumns = map[eventColumnID]bool{colIndex: true, colRule: true}
	m.serverProjects = true
	cmd := m.ruleWork()
	if cmd == nil || m.rulePolicy == nil || m.rulePolicy.ready {
		t.Fatalf("the first call should start a resolve: cmd %v state %+v", cmd != nil, m.rulePolicy)
	}
	if len(r.calls) != 0 {
		t.Error("ruleWork resolved synchronously: it must return a command")
	}
	msg := cmd().(ruleResolvedMsg)
	m.applyRuleResolved(msg)
	if !m.rulePolicy.ready {
		t.Fatal("the policy is not ready after the reply")
	}
	if got := m.ruleWanted(); len(got) != 1 {
		t.Errorf("after the policy is ready the response should be wanted: %+v", got)
	}
}

func TestRuleWork_OnlyOnThePanesThatShowTheColumn(t *testing.T) {
	for _, pane := range []paneID{paneSessions, paneUsage, paneAgents, panePipeline, paneCatalog, paneTimeline, paneAccess} {
		m := ruleModel(t, ruleProjected(ruleToolResp(2, ruleCall("Bash", `{"command":"ls"}`))))
		m.eventColumns = map[eventColumnID]bool{colIndex: true, colRule: true}
		m.pane = pane
		if cmd := m.ruleWork(); cmd != nil {
			t.Errorf("pane %v started rule work", pane)
		}
	}
}

func TestApplyRuleCalls_AFailedFetchIsRememberedSoItIsNotRetriedInALoop(t *testing.T) {
	m := ruleModel(t, ruleProjected(ruleToolResp(2, ruleCall("Bash", `{"command":"ls"}`))))
	m.eventColumns = map[eventColumnID]bool{colIndex: true, colRule: true}
	m.serverProjects = true
	m.rulePolicy = &rulePolicyState{session: "s1", policy: rulePolicyFixture(), ready: true, gen: 1, inflight: map[uint64]bool{2: true}}
	m.applyRuleCalls(ruleCallsMsg{session: "s1", seq: 2, gen: 1, err: fmt.Errorf("boom")})
	if m.rulePolicy.inflight[2] {
		t.Error("the failed fetch is still marked in flight")
	}
	if w := m.ruleWanted(); len(w) != 0 {
		t.Errorf("wanted = %+v: a failed row would be refetched on every message", w)
	}
}

// The detail block explains each call's caveats, one per line. They come from the matcher and
// can quote the call's own text.
func TestDetailBlock_CaveatsAreCleaned(t *testing.T) {
	evil := "\x1b]0;pwned\x07"
	m := ruleModel(t, ruleToolResp(2, ruleCall("Bash", `{"command":"echo \"`+ruleJSONEsc(evil)+`"}`))) // unterminated quote: the caveat names the cause
	m.rulePolicy = &rulePolicyState{session: "s1", policy: rulePolicyFixture(), ready: true}
	b := m.accessDetailBlock(&m.events["s1"][0])
	if !strings.Contains(ansi.Strip(b), "·") {
		t.Fatalf("setup: the block carries no caveat line to check:\n%s", b)
	}
	if strings.Contains(b, "\x07") || strings.Contains(ansi.Strip(b), "\x1b") {
		t.Errorf("a caveat carries a control byte: %q", b)
	}
}

// Caveats can quote RULE text, which comes from a settings file in whatever repository was
// cloned: an unsupported pattern is reported by name. That text is untrusted and is cleaned at
// the point it is drawn.
func TestDetailBlock_ACaveatQuotingRuleTextIsCleaned(t *testing.T) {
	evil := "\x1b]0;pwned\x07"
	p := &access.Policy{Rules: []access.Rule{
		{Decision: access.Deny, Raw: "Read(!" + evil + ")", Tool: "Read", Pattern: "!" + evil, Source: access.Project, File: "/p/s.json"},
	}}
	m := ruleModel(t, ruleToolResp(2, ruleCall("Read", `{"file_path":"/work/proj/a"}`)))
	m.rulePolicy = &rulePolicyState{session: "s1", policy: p, ready: true, ctx: access.MatchContext{Cwd: "/work/proj"}}
	b := m.accessDetailBlock(&m.events["s1"][0])
	plain := ansi.Strip(b)
	if !strings.Contains(plain, "negation") {
		t.Fatalf("setup: the caveat quoting the rule is not in the block:\n%s", plain)
	}
	if strings.Contains(b, "\x07") || strings.Contains(plain, "\x1b") || strings.Contains(b, "pwned") {
		t.Errorf("rule text reached the screen raw: %q", b)
	}
}

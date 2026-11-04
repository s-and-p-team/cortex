package lineage

// The Sentry gate keys its verdict on the lineage-parent tracestate member of
// the forwarded request. That member names THIS exchange only when this
// plugin wrote it in this same pipeline pass. When the plugin skips the
// exchange (not ready at pod start, a bypass_paths or bypass_hosts match) the
// header still carries whatever the application propagated — in a sidecar
// mesh, the stamp this pod's INBOUND sidecar wrote on the call that caused
// the egress — and a gate that reads it asks the verdict service about the
// wrong exchange. An allow on that inbound exchange then lets the egress out.
//
// These tests pin what the gate must do in each case. They live here, beside
// the plugin whose skip paths they drive, because the lineage test helpers
// are what make the skip reproducible; the plugin under test is the gate.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rossoctl/cortex/core/bootstrap"
	"github.com/rossoctl/cortex/core/bypass"
	"github.com/rossoctl/cortex/core/config"
	"github.com/rossoctl/cortex/core/pipeline"
	"github.com/rossoctl/cortex/core/plugins"
	"github.com/rossoctl/cortex/core/plugins/sentrygate"
)

// A chain with the gate before lineage-telemetry, or without it, is refused at
// build: the gate keys on the stamp lineage writes in the same pass, so a gate
// that ran first would refuse every request as no_lineage_stamp.
func TestSentryGate_ChainNeedsLineageBeforeIt(t *testing.T) {
	parser := config.PluginEntry{Name: "mcp-parser"}
	gate := config.PluginEntry{Name: "sentry-gate", Config: json.RawMessage(`{"verdict_url":"http://127.0.0.1:1"}`)}
	lineage := config.PluginEntry{Name: "lineage-telemetry", Config: json.RawMessage(`{"namespace":"team1"}`)}
	for name, chain := range map[string][]config.PluginEntry{
		"gate first":    {parser, gate, lineage},
		"gate alone":    {parser, gate},
		"lineage first": {parser, lineage, gate},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := plugins.Build(chain)
			if want := name == "lineage first"; (err == nil) != want {
				t.Fatalf("Build: %v, want ok=%v", err, want)
			}
			if err != nil && !strings.Contains(err.Error(), `"sentry-gate" requires "lineage-telemetry" earlier`) {
				t.Errorf("err = %v", err)
			}
		})
	}
}

const (
	gateTraceID      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	gateInboundStamp = "1111111111111111" // the stamp the app propagated from its inbound
)

// askedGate returns a configured gate and the path of the last verdict call.
func askedGate(t *testing.T, extra string) (*sentrygate.Gate, *atomic.Value) {
	t.Helper()
	var last atomic.Value
	last.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		last.Store(r.URL.Path)
		fmt.Fprint(w, `{"state":"decided","verdict":"allow"}`)
	}))
	t.Cleanup(srv.Close)
	g := sentrygate.New()
	if err := g.Configure(json.RawMessage(`{"verdict_url":"` + srv.URL + `"` + extra + `}`)); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	return g, &last
}

// propagated is an outbound request as the app's propagate-only shim leaves
// it: the inbound's trace and the inbound sidecar's stamp.
func propagated() http.Header {
	h := traceparent(gateTraceID, "2222222222222222")
	h.Set("tracestate", "lineage-parent="+gateInboundStamp)
	return h
}

func gateInvocation(t *testing.T, pctx *pipeline.Context) pipeline.Invocation {
	t.Helper()
	inv := pctx.Extensions.Invocations
	if inv == nil {
		t.Fatal("no invocations recorded")
	}
	for i := len(inv.Outbound) - 1; i >= 0; i-- {
		if inv.Outbound[i].Plugin == "sentry-gate" {
			return inv.Outbound[i]
		}
	}
	t.Fatal("the gate recorded no invocation")
	return pipeline.Invocation{}
}

// When lineage skipped the exchange, the gate must not key on the header:
// the only stamp there is the inbound's. Refused, no call.
func TestSentryGate_SkippedExchangeIsUnknownNotTheInbound(t *testing.T) {
	cases := map[string]func(p *LineageTelemetry, pctx *pipeline.Context){
		"not_ready":   func(p *LineageTelemetry, _ *pipeline.Context) { p.ready.Store(false) },
		"bypass_path": func(p *LineageTelemetry, pctx *pipeline.Context) { pctx.Path = "/healthz" },
		"bypass_host": func(p *LineageTelemetry, pctx *pipeline.Context) {
			p.cfg.BypassHosts = []string{"outside.example"}
		},
	}
	for name, arrange := range cases {
		t.Run(name, func(t *testing.T) {
			p, _ := newTestPlugin(t)
			g, asked := askedGate(t, "")
			pctx := fakeContext(pipeline.Outbound, propagated())
			pctx.Host = "outside.example:8000"
			arrange(p, pctx)

			pl, err := pipeline.New([]pipeline.Plugin{p, g})
			if err != nil {
				t.Fatalf("pipeline.New: %v", err)
			}
			act := pl.Run(context.Background(), pctx)

			if got := asked.Load().(string); strings.HasSuffix(got, "/"+gateInboundStamp) {
				t.Errorf("the gate asked for the INBOUND exchange's verdict: %s", got)
			} else if got != "" {
				t.Errorf("the gate asked %s; nothing to ask about on a skipped exchange", got)
			}
			if act.Type != pipeline.Reject {
				t.Errorf("action = %v, want Reject", act.Type)
			}
			if inv := gateInvocation(t, pctx); strings.HasPrefix(inv.Reason, "verdict_") {
				t.Errorf("reason = %q, want an unknown-key reason, not a verdict", inv.Reason)
			}
		})
	}
}

// When lineage stamped, the gate asks by that stamp — the fresh request span
// id, never the inbound's — and a stamp the app put on the request itself is
// overwritten before the gate reads it, even on a tracestate already at the
// W3C cap of 32 members.
func TestSentryGate_KeysOnTheStampLineageWroteThisPass(t *testing.T) {
	for name, h := range map[string]http.Header{
		"propagated": propagated(),
		"forged_full": func() http.Header {
			h := fullTracestate(31)
			h.Set("traceparent", "00-"+gateTraceID+"-2222222222222222-01")
			h.Set("tracestate", "lineage-parent="+gateInboundStamp+","+h.Get("tracestate"))
			return h
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			p, exp := newTestPlugin(t)
			p.bypassPaths, _ = bypass.NewMatcher(nil)
			g, asked := askedGate(t, "")
			pctx := fakeContext(pipeline.Outbound, h)
			pctx.Host = "outside.example:8000"

			pl, err := pipeline.New([]pipeline.Plugin{p, g})
			if err != nil {
				t.Fatalf("pipeline.New: %v", err)
			}
			if act := pl.Run(context.Background(), pctx); act.Type != pipeline.Continue {
				t.Fatalf("action = %v, want Continue (allow verdict)", act.Type)
			}
			spans := exp.GetSpans()
			if len(spans) != 1 {
				t.Fatalf("exported %d spans before finish, want the request span", len(spans))
			}
			want := "/verdicts/" + gateTraceID + "/" + spans[0].SpanContext.SpanID().String()
			if got := asked.Load().(string); got != want {
				t.Errorf("asked %s, want %s", got, want)
			}
		})
	}
}

// With the gate in the chain, an exchange lineage has not stamped is refused
// (above), so a sidecar whose lineage is not ready yet would refuse every
// unlisted egress. The sidecar's readiness already covers that: the outbound
// pipeline ANDs every Readier into /readyz, and the gate's Requires puts
// lineage in that pipeline, so /readyz answers 503 naming lineage-telemetry
// until it is ready. The gate adds no condition of its own: a verdict service
// that is down refuses requests; it is no reason to take the pod out of its
// Service. Whether the kubelet asks /readyz is the pod spec's business.
func TestSentryGate_ReadinessWaitsForLineage(t *testing.T) {
	p, _ := newTestPlugin(t)
	g, _ := askedGate(t, "")
	out, err := pipeline.New([]pipeline.Plugin{p, g})
	if err != nil {
		t.Fatalf("pipeline.New: %v", err)
	}
	in, err := pipeline.New(nil)
	if err != nil {
		t.Fatalf("pipeline.New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := bootstrap.ServeHealthServer(pipeline.NewHolder(in), pipeline.NewHolder(out), ln)
	t.Cleanup(func() { _ = srv.Close() })

	readyz := func() (int, string) {
		t.Helper()
		resp, err := http.Get("http://" + ln.Addr().String() + "/readyz")
		if err != nil {
			t.Fatalf("GET /readyz: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	p.ready.Store(false)
	if status, body := readyz(); status != http.StatusServiceUnavailable || !strings.Contains(body, "lineage-telemetry") {
		t.Errorf("lineage not ready: /readyz = %d %q, want 503 naming lineage-telemetry", status, body)
	}
	p.ready.Store(true)
	if status, body := readyz(); status != http.StatusOK {
		t.Errorf("lineage ready: /readyz = %d %q, want 200", status, body)
	}
}

// The real lineage plugin tells the real gate whether capture is off, in the
// pass that emitted the span: an unread body continues only with capture_io off.
func TestSentryGate_CaptureOffComesFromLineage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"state":"unjudged","verdict":"allow","reason":"body_not_captured"}`)
	}))
	t.Cleanup(srv.Close)
	for _, tc := range []struct {
		capture    bool
		wantAction pipeline.ActionType
		wantReason string
	}{
		{false, pipeline.Continue, "unread_capture_off"},
		{true, pipeline.Reject, "verdict_unjudged"},
	} {
		t.Run(fmt.Sprintf("capture_io=%v", tc.capture), func(t *testing.T) {
			p, _ := newTestPlugin(t)
			p.bypassPaths, _ = bypass.NewMatcher(nil)
			p.cfg.CaptureIO = tc.capture
			g := sentrygate.New()
			if err := g.Configure(json.RawMessage(`{"verdict_url":"` + srv.URL + `"}`)); err != nil {
				t.Fatalf("Configure: %v", err)
			}
			pctx := fakeContext(pipeline.Outbound, propagated())
			pctx.Host = "outside.example:8000"
			pl, err := pipeline.New([]pipeline.Plugin{p, g})
			if err != nil {
				t.Fatalf("pipeline.New: %v", err)
			}
			if act := pl.Run(context.Background(), pctx); act.Type != tc.wantAction {
				t.Errorf("action = %v, want %v", act.Type, tc.wantAction)
			}
			if inv := gateInvocation(t, pctx); inv.Reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", inv.Reason, tc.wantReason)
			}
		})
	}
}

// The body mark. With capture on, lineage marks its record of the pass when it cut
// the request body at max_payload_bytes (body_cut) or captured none of a body that
// has bytes (body_not_captured). The gate reads the mark only when a slow or dead
// service gave no verdict: a marked body is refused whatever the fallback, because
// the verdict would have said unjudged. These run the real lineage beside the real
// gate in one pipeline, the order the gate's Requires enforces.

// markCap is the max_payload_bytes the mark tests run under.
const markCap = 64

// markedChain runs one outbound request through the real lineage (capture_io as
// given, max_payload_bytes markCap) and then the real gate (fallback as given),
// against a verdict service that gives one answer.
func markedChain(t *testing.T, capture bool, fallback string, status int, answer string, pctx *pipeline.Context) pipeline.Action {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		fmt.Fprint(w, answer)
	}))
	t.Cleanup(srv.Close)
	p, _ := newTestPlugin(t)
	p.bypassPaths, _ = bypass.NewMatcher(nil)
	p.cfg.CaptureIO = capture
	p.cfg.MaxPayloadBytes = markCap
	g := sentrygate.New()
	if err := g.Configure(json.RawMessage(`{"verdict_url":"` + srv.URL + `","fallback":"` + fallback + `"}`)); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	pl, err := pipeline.New([]pipeline.Plugin{p, g})
	if err != nil {
		t.Fatalf("pipeline.New: %v", err)
	}
	return pl.Run(context.Background(), pctx)
}

// withBody is an outbound plain-HTTP request to an unlisted host carrying body.
func withBody(body string) *pipeline.Context {
	pctx := fakeContext(pipeline.Outbound, propagated())
	pctx.Host = "outside.example:8000"
	pctx.Body = []byte(body)
	return pctx
}

// mcpNoParams is an MCP tools/call with no params: the body has bytes, and the
// parser's reduction, which capture takes, is nothing.
func mcpNoParams() *pipeline.Context {
	pctx := withBody(`{"jsonrpc":"2.0","id":7,"method":"tools/call"}`)
	pctx.Extensions.MCP = &pipeline.MCPExtension{Method: "tools/call", RPCID: 7}
	return pctx
}

// lineageRecord is lineage-telemetry's request-pass record and its index among the
// pass's records.
func lineageRecord(t *testing.T, pctx *pipeline.Context) (pipeline.Invocation, int) {
	t.Helper()
	if inv := pctx.Extensions.Invocations; inv != nil {
		for i, rec := range inv.Outbound {
			if rec.Plugin == "lineage-telemetry" && rec.Phase == pipeline.InvocationPhaseRequest {
				return rec, i
			}
		}
	}
	t.Fatal("lineage recorded nothing")
	return pipeline.Invocation{}, -1
}

const (
	answerPending = `{"state":"pending"}`
	answerAllow   = `{"state":"decided","verdict":"allow","version":1}`
	answerUnread  = `{"state":"unjudged","verdict":"allow","reason":"body_not_captured","version":1}`
)

// wantMarkedRefusal checks a marked-body refusal: a 503 under the cause, the mark in
// the record and in the refusal details, never a fallback outcome.
func wantMarkedRefusal(t *testing.T, act pipeline.Action, pctx *pipeline.Context, cause, mark string) {
	t.Helper()
	if act.Type != pipeline.Reject || act.Violation == nil {
		t.Fatalf("action = %v, want Reject", act.Type)
	}
	inv := gateInvocation(t, pctx)
	if inv.Action != pipeline.ActionDeny || inv.Reason != cause || inv.Details[mark] != "true" {
		t.Errorf("record = %s/%s %v, want deny/%s with %s", inv.Action, inv.Reason, inv.Details, cause, mark)
	}
	if _, ok := inv.Details["no_verdict"]; ok || strings.HasPrefix(inv.Reason, "fallback_") {
		t.Errorf("record = %s %v: a marked body is never the fallback's", inv.Reason, inv.Details)
	}
	v := act.Violation
	if v.Status != http.StatusServiceUnavailable || v.Code != "policy.verdict-unavailable" {
		t.Errorf("refusal = %d %s, want 503 policy.verdict-unavailable", v.Status, v.Code)
	}
	if v.Details["reason"] != cause || v.Details[mark] != true || v.Details["fallback"] != nil {
		t.Errorf("refusal details = %v, want reason %s and %s, no fallback", v.Details, cause, mark)
	}
	if !strings.Contains(v.Reason, "No verdict arrived, and the request body could not be judged in full") {
		t.Errorf("message = %q, want it to say the body was not fully judged", v.Reason)
	}
}

// A body over the cap, no verdict in time: refused under its cause with body_cut,
// whatever the fallback. The mark touches nothing else: a verdict that arrived
// decides, and a fault stays a fault.
func TestSentryGate_CutBodyIsRefusedWhateverTheFallback(t *testing.T) {
	cut := strings.Repeat("x", markCap+1)
	for _, fallback := range []string{"allow", "deny"} {
		for _, tc := range []struct {
			name   string
			status int
			answer string
			cause  string
		}{
			{"pending", http.StatusOK, answerPending, "verdict_pending"},
			{"5xx", http.StatusInternalServerError, `{}`, "verdict_error"},
		} {
			t.Run(fallback+"/"+tc.name, func(t *testing.T) {
				pctx := withBody(cut)
				act := markedChain(t, true, fallback, tc.status, tc.answer, pctx)
				wantMarkedRefusal(t, act, pctx, tc.cause, "body_cut")
			})
		}
	}
	t.Run("a verdict that arrived decides", func(t *testing.T) {
		pctx := withBody(cut)
		if act := markedChain(t, true, "allow", http.StatusOK, answerAllow, pctx); act.Type != pipeline.Continue {
			t.Fatalf("action = %v, want Continue", act.Type)
		}
		if inv := gateInvocation(t, pctx); inv.Reason != "verdict_allow" || inv.Details["body_cut"] != "" {
			t.Errorf("record = %s %v, want verdict_allow with no mark", inv.Reason, inv.Details)
		}
	})
	t.Run("a fault stays a fault", func(t *testing.T) {
		pctx := withBody(cut)
		if act := markedChain(t, true, "allow", http.StatusNotFound, `{}`, pctx); act.Type != pipeline.Reject {
			t.Fatalf("action = %v, want Reject", act.Type)
		}
		inv := gateInvocation(t, pctx)
		if inv.Reason != "verdict_error" || inv.Details["status"] != "404" || inv.Details["body_cut"] != "" {
			t.Errorf("record = %s %v, want the fault verdict_error 404 with no mark", inv.Reason, inv.Details)
		}
	})
}

// A body the parser reduces to nothing, no verdict in time: refused with
// body_not_captured under an allow fallback.
func TestSentryGate_UncapturedBodyIsRefusedWhateverTheFallback(t *testing.T) {
	pctx := mcpNoParams()
	act := markedChain(t, true, "allow", http.StatusOK, answerPending, pctx)
	wantMarkedRefusal(t, act, pctx, "verdict_pending", "body_not_captured")
}

// Capture off writes no mark and changes nothing: an unjudged answer for an unread
// body continues as unread_capture_off, and with no verdict the fallback decides.
func TestSentryGate_CaptureOffWritesNoMark(t *testing.T) {
	for name, body := range map[string]func() *pipeline.Context{
		"over the cap":  func() *pipeline.Context { return withBody(strings.Repeat("x", markCap+1)) },
		"mcp no params": mcpNoParams,
	} {
		for _, tc := range []struct{ answer, want string }{
			{answerUnread, "unread_capture_off"},
			{answerPending, "fallback_allow"},
		} {
			t.Run(name+"/"+tc.want, func(t *testing.T) {
				pctx := body()
				if act := markedChain(t, false, "allow", http.StatusOK, tc.answer, pctx); act.Type != pipeline.Continue {
					t.Fatalf("action = %v, want Continue", act.Type)
				}
				if rec, _ := lineageRecord(t, pctx); rec.Details["body_cut"] != "" || rec.Details["body_not_captured"] != "" {
					t.Errorf("lineage record = %v, want no mark with capture off", rec.Details)
				}
				if inv := gateInvocation(t, pctx); inv.Reason != tc.want {
					t.Errorf("record = %s %v, want %s", inv.Reason, inv.Details, tc.want)
				}
			})
		}
	}
}

// gateFirst is the real gate without its Requires, so a chain can run it before
// lineage, which the Requires otherwise refuses at build.
type gateFirst struct{ *sentrygate.Gate }

func (gateFirst) Capabilities() pipeline.PluginCapabilities { return pipeline.PluginCapabilities{} }

// The mark is written in lineage's request-pass record, before the gate reads
// it: in order, lineage's marked record precedes the gate's, which carries the mark;
// a gate run before lineage sees no record and so no mark.
func TestSentryGate_MarkIsWrittenBeforeTheGateReads(t *testing.T) {
	t.Run("lineage first", func(t *testing.T) {
		pctx := withBody(strings.Repeat("x", markCap+1))
		markedChain(t, true, "allow", http.StatusOK, answerPending, pctx)
		rec, at := lineageRecord(t, pctx)
		inv := gateInvocation(t, pctx)
		if rec.Details["body_cut"] != "true" || inv.Details["body_cut"] != "true" {
			t.Errorf("lineage %v, gate %v: want the mark in both", rec.Details, inv.Details)
		}
		if gateAt := len(pctx.Extensions.Invocations.Outbound) - 1; at >= gateAt {
			t.Errorf("lineage record at %d, gate at %d: lineage must write first", at, gateAt)
		}
	})
	t.Run("gate first", func(t *testing.T) {
		p, _ := newTestPlugin(t)
		p.bypassPaths, _ = bypass.NewMatcher(nil)
		p.cfg.CaptureIO = true
		p.cfg.MaxPayloadBytes = markCap
		g, asked := askedGate(t, `,"fallback":"allow"`)
		pl, err := pipeline.New([]pipeline.Plugin{gateFirst{g}, p})
		if err != nil {
			t.Fatalf("pipeline.New: %v", err)
		}
		pctx := withBody(strings.Repeat("x", markCap+1))
		pl.Run(context.Background(), pctx)
		inv := pctx.Extensions.Invocations.Outbound[0]
		if inv.Plugin != "sentry-gate" || inv.Reason != "no_lineage_stamp" || inv.Details["body_cut"] != "" {
			t.Errorf("gate record = %s %s %v, want sentry-gate no_lineage_stamp with no mark", inv.Plugin, inv.Reason, inv.Details)
		}
		if got := asked.Load().(string); got != "" {
			t.Errorf("the gate asked %s before lineage stamped", got)
		}
	})
}

// A body exactly at the cap is captured whole: no mark, and the fallback
// decides. One byte more is cut.
func TestSentryGate_BodyAtTheCapIsTheFallbacks(t *testing.T) {
	for _, tc := range []struct {
		fallback   string
		wantAction pipeline.ActionType
		wantReason string
	}{
		{"allow", pipeline.Continue, "fallback_allow"},
		{"deny", pipeline.Reject, "fallback_deny"},
	} {
		t.Run(tc.fallback, func(t *testing.T) {
			pctx := withBody(strings.Repeat("x", markCap))
			if act := markedChain(t, true, tc.fallback, http.StatusOK, answerPending, pctx); act.Type != tc.wantAction {
				t.Fatalf("action = %v, want %v", act.Type, tc.wantAction)
			}
			rec, _ := lineageRecord(t, pctx)
			inv := gateInvocation(t, pctx)
			if rec.Details["body_cut"] != "" || inv.Reason != tc.wantReason || inv.Details["no_verdict"] != "verdict_pending" {
				t.Errorf("lineage %v, gate %s %v: want no mark and %s", rec.Details, inv.Reason, inv.Details, tc.wantReason)
			}
		})
	}
	t.Run("one byte over", func(t *testing.T) {
		pctx := withBody(strings.Repeat("x", markCap+1))
		act := markedChain(t, true, "allow", http.StatusOK, answerPending, pctx)
		wantMarkedRefusal(t, act, pctx, "verdict_pending", "body_cut")
	})
}

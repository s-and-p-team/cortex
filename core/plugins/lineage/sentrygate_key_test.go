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
		fmt.Fprint(w, `{"state":"decided","verdict":"allow","interaction_id":"i"}`)
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
		fmt.Fprint(w, `{"state":"unjudged","verdict":"allow","reason":"body_not_captured","interaction_id":"i"}`)
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

package sentrygate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rossoctl/cortex/core/listener/httpx"
	"github.com/rossoctl/cortex/core/pipeline"
	"github.com/rossoctl/cortex/core/redact"
)

const (
	traceID    = "4bf92f3577b34da6a3ce929d0e0e4736"
	exchangeID = "00f067aa0ba902b7"
)

// stamped returns outbound headers as lineage-telemetry leaves them: a valid
// traceparent and the lineage stamp naming this exchange.
func stamped() http.Header {
	h := http.Header{}
	h.Set("traceparent", "00-"+traceID+"-b7ad6b7169203331-01")
	h.Set("tracestate", "lineage-parent="+exchangeID+",other=1")
	return h
}

// verdictServer answers every verdict GET with body and counts the calls; it
// records the last path and query so a test can check the key it was asked by.
func verdictServer(t *testing.T, delay time.Duration, body string) (*httptest.Server, *atomic.Int32, *atomic.Value) {
	t.Helper()
	var calls atomic.Int32
	var last atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		last.Store(r.Method + " " + r.URL.RequestURI())
		time.Sleep(delay)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls, &last
}

func gate(t *testing.T, raw string) *Gate {
	t.Helper()
	g := New()
	if err := g.Configure(json.RawMessage(raw)); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	return g
}

// outbound is a request as it reaches the gate: lineage-telemetry has run
// before it and recorded that it stamped the forwarded tracestate.
func outbound(host string, h http.Header) *pipeline.Context {
	pctx := &pipeline.Context{Direction: pipeline.Outbound, Host: host, Headers: h}
	lineageStamped(pctx)
	return pctx
}

func lineageStamped(pctx *pipeline.Context) {
	pctx.Record(pipeline.Invocation{Plugin: "lineage-telemetry", Phase: pipeline.InvocationPhaseRequest,
		Action: pipeline.ActionModify, Reason: "stamped_tracestate"})
}

func lastInvocation(t *testing.T, pctx *pipeline.Context) pipeline.Invocation {
	t.Helper()
	inv := pctx.Extensions.Invocations
	if inv == nil || len(inv.Outbound) == 0 {
		t.Fatal("no invocation recorded")
	}
	return inv.Outbound[len(inv.Outbound)-1]
}

func TestBlockVerdictRejects(t *testing.T) {
	srv, calls, last := verdictServer(t, 0,
		`{"state":"decided","verdict":"block","exchange_id":"00f067aa0ba902b7","version":2}`)
	g := gate(t, `{"verdict_url":"`+srv.URL+`/enforce/v1/","wait_ms":1500}`)
	pctx := outbound("outside.example:8000", stamped())

	act := g.OnRequest(context.Background(), pctx)
	if act.Type != pipeline.Reject {
		t.Fatalf("action = %v, want Reject", act.Type)
	}
	if act.Violation.Code != "policy.content-blocked" {
		t.Errorf("code = %q, want policy.content-blocked", act.Violation.Code)
	}
	if status, _, _ := act.Violation.Render(); status != http.StatusForbidden {
		t.Errorf("status = %d, want 403", status)
	}
	if calls.Load() != 1 {
		t.Errorf("verdict calls = %d, want 1", calls.Load())
	}
	want := "GET /enforce/v1/verdicts/" + traceID + "/" + exchangeID + "?wait_ms=1500"
	if got := last.Load(); got != want {
		t.Errorf("asked %q, want %q", got, want)
	}
	inv := lastInvocation(t, pctx)
	if inv.Action != pipeline.ActionDeny || inv.Reason != "verdict_block" {
		t.Errorf("invocation = %s/%s, want deny/verdict_block", inv.Action, inv.Reason)
	}
	if inv.Details["exchange_id"] != exchangeID {
		t.Errorf("details = %v", inv.Details)
	}
}

func TestAllowVerdictContinues(t *testing.T) {
	srv, _, _ := verdictServer(t, 0, `{"state":"decided","verdict":"allow","version":1}`)
	g := gate(t, `{"verdict_url":"`+srv.URL+`"}`)
	pctx := outbound("peer.example.com", stamped())

	if act := g.OnRequest(context.Background(), pctx); act.Type != pipeline.Continue {
		t.Fatalf("action = %v, want Continue", act.Type)
	}
	if inv := lastInvocation(t, pctx); inv.Action != pipeline.ActionAllow || inv.Reason != "verdict_allow" {
		t.Errorf("invocation = %s/%s, want allow/verdict_allow", inv.Action, inv.Reason)
	}
}

// deny_on decides which verdicts reject; one outside it continues even when
// it is not "allow".
func TestDenyOnSelectsVerdicts(t *testing.T) {
	srv, _, _ := verdictServer(t, 0, `{"state":"decided","verdict":"require_approval"}`)
	if act := gate(t, `{"verdict_url":"`+srv.URL+`"}`).OnRequest(context.Background(), outbound("x.example", stamped())); act.Type != pipeline.Continue {
		t.Errorf("require_approval with default deny_on: action = %v, want Continue", act.Type)
	}
	g := gate(t, `{"verdict_url":"`+srv.URL+`","deny_on":["block","require_approval"]}`)
	if act := g.OnRequest(context.Background(), outbound("x.example", stamped())); act.Type != pipeline.Reject {
		t.Errorf("require_approval in deny_on: action = %v, want Reject", act.Type)
	}
	// The answer's verdict is case-folded as deny_on is: a "BLOCK" is a block.
	upper, _, _ := verdictServer(t, 0, `{"state":"decided","verdict":"BLOCK"}`)
	if act := gate(t, `{"verdict_url":"`+upper.URL+`"}`).OnRequest(context.Background(), outbound("x.example", stamped())); act.Type != pipeline.Reject {
		t.Errorf("verdict BLOCK with default deny_on: action = %v, want Reject", act.Type)
	}
}

// The verdict is compared as deny_on is decoded, trimmed and case-folded: a
// block written with stray whitespace must not read as an allow.
func TestVerdictIsNormalizedBeforeDenyOn(t *testing.T) {
	for _, tc := range []struct {
		verdict string
		want    pipeline.ActionType
	}{
		{"block", pipeline.Reject},
		{"BLOCK", pipeline.Reject},
		{" block", pipeline.Reject},
		{"block\\n", pipeline.Reject},
		{"\\tBlock ", pipeline.Reject},
		{"allow", pipeline.Continue},
		{" allow ", pipeline.Continue},
		{"blocked", pipeline.Continue},
	} {
		srv, _, _ := verdictServer(t, 0, `{"state":"decided","verdict":"`+tc.verdict+`"}`)
		pctx := outbound("x.example", stamped())
		if act := gate(t, `{"verdict_url":"`+srv.URL+`"}`).OnRequest(context.Background(), pctx); act.Type != tc.want {
			t.Errorf("verdict %q: action = %v, want %v", tc.verdict, act.Type, tc.want)
		}
	}
}

// An IP literal is never a short name, whatever form it comes in, and only a
// name with no dot passes as one.
func TestSingleLabelPass(t *testing.T) {
	srv, _, _ := verdictServer(t, 0, `{"state":"decided","verdict":"allow"}`)
	g := gate(t, `{"verdict_url":"`+srv.URL+`"}`)
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"api", true},
		{"api:8000", true},
		{"api.team1.svc", false},
		{"10.0.0.1", false},
		{"[::1]", false},
		{"[::1]:80", false},
		{"[fe80::1%eth0]", false},
		{"[fe80::1%eth0]:8080", false},
		{"fe80::1%eth0", false},
		{"[fe80::1%25eth0]:8080", false},
		{"api-2", true},
		{"2fast", true},
		{"exfil\u3002example", false},
		{"127\uff0e0\uff0e0\uff0e1:8080", false},
		{"exfil%E3%80%82example", false},
		{"134744072", false},
		{"0x08080808", false},
		{"0X08080808", false},
		{"-api", false},
	} {
		if got := g.passes(tc.host); got != tc.want {
			t.Errorf("passes(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

// A pass-list host and a cluster short name continue without asking — the
// selective wait: only unlisted egress pays for a verdict.
func TestPassHostsNeverAsk(t *testing.T) {
	srv, calls, _ := verdictServer(t, 0, `{"state":"decided","verdict":"block"}`)
	g := gate(t, `{"verdict_url":"`+srv.URL+`","pass_hosts":["*.svc.cluster.local","host.containers.internal"]}`)
	for _, host := range []string{
		"api:8000", // single label
		"opa.data-governance.svc.cluster.local:8181", // pass glob
		"HOST.containers.internal:11434",             // case folded
	} {
		pctx := outbound(host, stamped())
		if act := g.OnRequest(context.Background(), pctx); act.Type != pipeline.Continue {
			t.Errorf("%s: action = %v, want Continue", host, act.Type)
		}
		if inv := lastInvocation(t, pctx); inv.Reason != "pass_host" {
			t.Errorf("%s: reason = %q, want pass_host", host, inv.Reason)
		}
	}
	if calls.Load() != 0 {
		t.Errorf("verdict calls = %d, want 0", calls.Load())
	}
	// pass_single_label off: a short name waits like any other host.
	g = gate(t, `{"verdict_url":"`+srv.URL+`","pass_single_label":false}`)
	if act := g.OnRequest(context.Background(), outbound("api:8000", stamped())); act.Type != pipeline.Reject {
		t.Errorf("short name with pass_single_label off: action = %v, want Reject", act.Type)
	}
	// An IP literal has no dot only in IPv6; it is never a short name, with a
	// port or without one (a Host header may carry the bracketed form alone).
	g = gate(t, `{"verdict_url":"`+srv.URL+`"}`)
	for _, host := range []string{"[::1]:80", "[::1]", "[2001:db8::1]", "[2001:db8::1]:8080"} {
		if g.passes(host) {
			t.Errorf("the IPv6 literal %s passed as a short name", host)
		}
	}
}

// No verdict in time is a 503: nothing was judged.
func TestPendingRefuses(t *testing.T) {
	srv, _, _ := verdictServer(t, 0, `{"state":"pending"}`)
	pctx := outbound("outside.example", stamped())
	act := gate(t, `{"verdict_url":"`+srv.URL+`"}`).OnRequest(context.Background(), pctx)
	if act.Type != pipeline.Reject {
		t.Fatalf("action = %v, want Reject", act.Type)
	}
	if status, _, _ := act.Violation.Render(); status != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", status)
	}
	if inv := lastInvocation(t, pctx); inv.Reason != "verdict_pending" {
		t.Errorf("reason = %q, want verdict_pending", inv.Reason)
	}
}

// A record that did not see the whole body has no answer about the rest of it,
// unless what it did see is already refused.
func TestUnjudgedRefusesAndADenyStillDenies(t *testing.T) {
	srv, _, _ := verdictServer(t, 0, `{"state":"unjudged","verdict":"allow","reason":"body_not_captured","version":1}`)
	pctx := outbound("outside.example", stamped())
	act := gate(t, `{"verdict_url":"`+srv.URL+`"}`).OnRequest(context.Background(), pctx)
	if act.Type != pipeline.Reject {
		t.Fatalf("action = %v, want Reject", act.Type)
	}
	if status, _, _ := act.Violation.Render(); status != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", status)
	}
	inv := lastInvocation(t, pctx)
	if inv.Reason != "verdict_unjudged" || inv.Details["unread"] != "body_not_captured" || inv.Details["verdict"] != "allow" {
		t.Errorf("recorded %q %v", inv.Reason, inv.Details)
	}

	srv, _, _ = verdictServer(t, 0, `{"state":"unjudged","verdict":"block","reason":"body_truncated","version":1}`)
	pctx = outbound("outside.example", stamped())
	act = gate(t, `{"verdict_url":"`+srv.URL+`"}`).OnRequest(context.Background(), pctx)
	if act.Type != pipeline.Reject {
		t.Fatalf("action = %v, want Reject", act.Type)
	}
	if status, _, _ := act.Violation.Render(); status != http.StatusForbidden {
		t.Errorf("status = %d, want 403", status)
	}
	if inv := lastInvocation(t, pctx); inv.Reason != "verdict_block" {
		t.Errorf("reason = %q, want verdict_block", inv.Reason)
	}
}

// Only capture off lets an unread body through, only for that reason, and only
// when lineage's own record of this pass says so: an older lineage or a missing
// detail reads as capture on. A deny stays a deny.
func TestUnreadBodyPassesOnlyWithCaptureOff(t *testing.T) {
	for _, tc := range []struct {
		name, capture, verdict, reason string
		wantStatus                     int // 0 = continues
		wantReason                     string
	}{
		{"off, not captured", "false", "allow", "body_not_captured", 0, "unread_capture_off"},
		{"off, truncated", "false", "allow", "body_truncated", 503, "verdict_unjudged"},
		{"off, not captured, block", "false", "block", "body_not_captured", 403, "verdict_block"},
		{"off, unknown reason", "false", "allow", "something_new", 503, "verdict_unjudged"},
		{"on, not captured", "true", "allow", "body_not_captured", 503, "verdict_unjudged"},
		{"on, truncated", "true", "allow", "body_truncated", 503, "verdict_unjudged"},
		{"detail missing", "", "allow", "body_not_captured", 503, "verdict_unjudged"},
		{"detail garbled", "FALSE", "allow", "body_not_captured", 503, "verdict_unjudged"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, calls, _ := verdictServer(t, 0, `{"state":"unjudged","verdict":"`+tc.verdict+`","reason":"`+tc.reason+`","version":1}`)
			pctx := &pipeline.Context{Direction: pipeline.Outbound, Host: "outside.example", Headers: stamped()}
			rec := pipeline.Invocation{Plugin: "lineage-telemetry", Phase: pipeline.InvocationPhaseRequest,
				Action: pipeline.ActionModify, Reason: "stamped_tracestate"}
			if tc.capture != "" {
				rec.Details = map[string]string{"capture_io": tc.capture}
			}
			pctx.Record(rec)
			act := gate(t, `{"verdict_url":"`+srv.URL+`"}`).OnRequest(context.Background(), pctx)
			if calls.Load() != 1 {
				t.Errorf("verdict calls = %d, want 1: capture off still asks", calls.Load())
			}
			if tc.wantStatus == 0 {
				if act.Type != pipeline.Continue {
					t.Fatalf("action = %v, want Continue", act.Type)
				}
			} else {
				if act.Type != pipeline.Reject {
					t.Fatalf("action = %v, want Reject", act.Type)
				}
				if status, _, _ := act.Violation.Render(); status != tc.wantStatus {
					t.Errorf("status = %d, want %d", status, tc.wantStatus)
				}
			}
			if inv := lastInvocation(t, pctx); inv.Reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", inv.Reason, tc.wantReason)
			}
		})
	}
}

// The warning says something only when a body really left unread, once per
// gate, and a reload (a new gate) says it again.
func TestUnreadWarningOncePerGate(t *testing.T) {
	var logged bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	warnings := func() int { return strings.Count(logged.String(), "bodies leave unread") }

	send := func(g *Gate, capture string) {
		t.Helper()
		pctx := &pipeline.Context{Direction: pipeline.Outbound, Host: "outside.example", Headers: stamped()}
		pctx.Record(pipeline.Invocation{Plugin: "lineage-telemetry", Phase: pipeline.InvocationPhaseRequest,
			Action: pipeline.ActionModify, Reason: "stamped_tracestate", Details: map[string]string{"capture_io": capture}})
		g.OnRequest(context.Background(), pctx)
	}
	srv, _, _ := verdictServer(t, 0, `{"state":"unjudged","verdict":"allow","reason":"body_not_captured","version":1}`)
	raw := `{"verdict_url":"` + srv.URL + `"}`

	g := gate(t, raw)
	send(g, "true")
	if n := warnings(); n != 0 {
		t.Errorf("capture on: %d warnings, want 0", n)
	}
	send(g, "false")
	send(g, "false")
	if n := warnings(); n != 1 {
		t.Errorf("two unread bodies: %d warnings, want 1", n)
	}
	send(gate(t, raw), "false")
	if n := warnings(); n != 2 {
		t.Errorf("after a reload: %d warnings, want 2", n)
	}
}

// A CONNECT sent inside a decrypted tunnel opens nothing: the bridge carries it
// with its body, so it is judged. Only the listener's mark tells the two apart.
func TestConnectInsideATunnelIsJudged(t *testing.T) {
	srv, calls, _ := verdictServer(t, 0, `{"state":"decided","verdict":"block"}`)
	pctx := outbound("outside.example", stamped())
	pctx.Method = http.MethodConnect
	pctx.MarkRedirectable()
	act := gate(t, `{"verdict_url":"`+srv.URL+`"}`).OnRequest(context.Background(), pctx)
	if act.Type != pipeline.Reject {
		t.Fatalf("action = %v, want Reject", act.Type)
	}
	if calls.Load() != 1 {
		t.Errorf("verdict calls = %d, want 1", calls.Load())
	}
}

// deny_on is compared as the verdict is: a config's " BLOCK " still blocks.
func TestDenyOnIsNormalized(t *testing.T) {
	srv, _, _ := verdictServer(t, 0, `{"state":"decided","verdict":"block"}`)
	g := gate(t, `{"verdict_url":"`+srv.URL+`","deny_on":[" BLOCK "]}`)
	if act := g.OnRequest(context.Background(), outbound("outside.example", stamped())); act.Type != pipeline.Reject {
		t.Errorf("action = %v, want Reject", act.Type)
	}
}

// The verdict call carries the secret, so it must never follow HTTP_PROXY, which
// a sidecar's environment may well set.
func TestVerdictCallNeverUsesAProxy(t *testing.T) {
	srv, _, _ := verdictServer(t, 0, `{"state":"decided","verdict":"allow"}`)
	if g := gate(t, `{"verdict_url":"`+srv.URL+`"}`); g.transport.Proxy != nil {
		t.Error("the verdict client's transport has a proxy function")
	}
}

// A client that hangs up during the hold is its own outcome: no verdict failed,
// so the gate records nothing and the refusal says the request was cancelled.
func TestClientGoneDuringTheHoldIsNotAVerdictError(t *testing.T) {
	srv, _, _ := verdictServer(t, 300*time.Millisecond, `{"state":"decided","verdict":"allow"}`)
	pctx := outbound("outside.example", stamped())
	before := len(pctx.Extensions.Invocations.Outbound)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	act := gate(t, `{"verdict_url":"`+srv.URL+`"}`).OnRequest(ctx, pctx)
	if act.Type != pipeline.Reject || act.Violation.Code != "pipeline.cancelled" {
		t.Fatalf("action = %+v, want Reject pipeline.cancelled", act)
	}
	if got := len(pctx.Extensions.Invocations.Outbound); got != before {
		t.Errorf("the gate recorded %d invocations, want none", got-before)
	}
}

// A verdict service that is down, slow past the budget, or answering garbage
// is the same unknown — never a silent allow.
func TestVerdictFailuresAreUnknown(t *testing.T) {
	slow, _, _ := verdictServer(t, 2*time.Second, `{"state":"decided","verdict":"allow"}`)
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(bad.Close)
	down := httptest.NewServer(http.NotFoundHandler())
	downURL := down.URL
	down.Close()

	for name, raw := range map[string]string{
		"slow": `{"verdict_url":"` + slow.URL + `","wait_ms":100}`,
		"5xx":  `{"verdict_url":"` + bad.URL + `"}`,
		"down": `{"verdict_url":"` + downURL + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			pctx := outbound("outside.example", stamped())
			start := time.Now()
			act := gate(t, raw).OnRequest(context.Background(), pctx)
			if act.Type != pipeline.Reject {
				t.Fatalf("action = %v, want Reject", act.Type)
			}
			if inv := lastInvocation(t, pctx); inv.Reason != "verdict_error" {
				t.Errorf("reason = %q, want verdict_error", inv.Reason)
			}
			if name == "slow" && time.Since(start) > time.Second {
				t.Errorf("held %v, want about wait_ms + grace", time.Since(start))
			}
		})
	}
}

// Without the lineage stamp there is no key to ask by: unknown, without a call.
func TestMissingKeyIsUnknown(t *testing.T) {
	srv, calls, _ := verdictServer(t, 0, `{"state":"decided","verdict":"allow"}`)
	g := gate(t, `{"verdict_url":"`+srv.URL+`"}`)
	noStamp := http.Header{}
	noStamp.Set("traceparent", "00-"+traceID+"-b7ad6b7169203331-01")
	badStamp := stamped()
	badStamp.Set("tracestate", "lineage-parent=zz")
	for name, h := range map[string]http.Header{"none": {}, "no stamp": noStamp, "bad stamp": badStamp} {
		pctx := outbound("outside.example", h)
		if act := g.OnRequest(context.Background(), pctx); act.Type != pipeline.Reject {
			t.Errorf("%s: action = %v, want Reject", name, act.Type)
		}
		if inv := lastInvocation(t, pctx); inv.Reason != "no_exchange_key" {
			t.Errorf("%s: reason = %q, want no_exchange_key", name, inv.Reason)
		}
	}
	if calls.Load() != 0 {
		t.Errorf("verdict calls = %d, want 0", calls.Load())
	}
}

// A CONNECT is never judged and never refused: whether the tunnel will be
// decrypted is decided after the pipeline runs on it, and a bridged tunnel's
// requests are judged one by one when they come through again. The CONNECT
// is recorded unjudged (kind=tunnel), without a call — even when lineage did not stamp it; a listed host is a pass as for any
// request.
func TestConnectIsUnjudgedAndContinues(t *testing.T) {
	srv, calls, _ := verdictServer(t, 0, `{"state":"decided","verdict":"block"}`)
	tunnel := func(host string, stampedByLineage bool) *pipeline.Context {
		pctx := &pipeline.Context{Direction: pipeline.Outbound, Method: http.MethodConnect, Scheme: "tcp", Host: host, Headers: stamped()}
		if stampedByLineage {
			lineageStamped(pctx)
		}
		return pctx
	}
	for name, tc := range map[string]struct {
		raw     string
		stamped bool
	}{
		"stamped":          {`{"verdict_url":"` + srv.URL + `"}`, true},
		"no lineage stamp": {`{"verdict_url":"` + srv.URL + `"}`, false},
	} {
		pctx := tunnel("api.peer.example:443", tc.stamped)
		if act := gate(t, tc.raw).OnRequest(context.Background(), pctx); act.Type != pipeline.Continue {
			t.Errorf("%s: action = %v, want Continue", name, act.Type)
		}
		inv := lastInvocation(t, pctx)
		if inv.Action != pipeline.ActionAllow || inv.Reason != "unjudged" || inv.Details["kind"] != "tunnel" {
			t.Errorf("%s: invocation = %s/%s %v, want allow/unjudged kind=tunnel", name, inv.Action, inv.Reason, inv.Details)
		}
	}
	pctx := tunnel("api.trusted.example:443", true)
	g := gate(t, `{"verdict_url":"`+srv.URL+`","pass_hosts":["api.trusted.example"]}`)
	if act := g.OnRequest(context.Background(), pctx); act.Type != pipeline.Continue {
		t.Fatalf("listed tunnel: action = %v, want Continue", act.Type)
	}
	if inv := lastInvocation(t, pctx); inv.Reason != "pass_host" {
		t.Errorf("listed tunnel: reason = %q, want pass_host", inv.Reason)
	}
	if calls.Load() != 0 {
		t.Errorf("verdict calls = %d, want 0", calls.Load())
	}
}

func TestInboundSkipped(t *testing.T) {
	srv, calls, _ := verdictServer(t, 0, `{"state":"decided","verdict":"block"}`)
	pctx := &pipeline.Context{Direction: pipeline.Inbound, Host: "me.example", Headers: stamped()}
	if act := gate(t, `{"verdict_url":"`+srv.URL+`"}`).OnRequest(context.Background(), pctx); act.Type != pipeline.Continue {
		t.Fatalf("action = %v, want Continue", act.Type)
	}
	if calls.Load() != 0 {
		t.Errorf("verdict calls = %d, want 0", calls.Load())
	}
}

func TestConfigRefusals(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		`{}`,
		`{"verdict_url":"ftp://x"}`,
		`{"verdict_url":"http://x","wait_ms":0}`,
		`{"verdict_url":"http://x","wait_ms":3001}`,       // above the verdict service's cap: refused, not clamped
		`{"verdict_url":"http://x","on_unknown":"allow"}`, // not a key of this config
		`{"verdict_url":"http://x","deny_on":[]}`,
		`{"verdict_url":"http://x","pass_hosts":["["]}`,
		`{"verdict_url":"http://x","wait":5}`,
		`{"verdict_url":"http://x","verdict_secret":"a b"}`,
		`{"verdict_url":"http://x","verdict_secret":"ab\n"}`,
		`{"verdict_url":"http://x","verdict_secret":"s","verdict_secret_file":"/f"}`,
		`{"verdict_url":"http://x","verdict_secret_file":"/does/not/exist"}`,
		`{"verdict_url":"http://x","verdict_secret_file":"` + empty + `"}`,
	} {
		if err := New().Configure(json.RawMessage(raw)); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	// The cap itself is a valid budget.
	if err := New().Configure(json.RawMessage(`{"verdict_url":"http://x","wait_ms":3000}`)); err != nil {
		t.Errorf("wait_ms 3000 refused: %v", err)
	}
	// Each end of the range names its own cause: only above the cap is it the
	// verdict service's.
	for raw, cause := range map[string]string{
		`{"verdict_url":"http://x","wait_ms":0}`:    "no time for a verdict",
		`{"verdict_url":"http://x","wait_ms":-5}`:   "no time for a verdict",
		`{"verdict_url":"http://x","wait_ms":3001}`: "the verdict service refuses a longer wait",
	} {
		if err := New().Configure(json.RawMessage(raw)); err == nil || !strings.Contains(err.Error(), cause) {
			t.Errorf("%s: error %v, want one naming %q", raw, err, cause)
		}
	}
}

// The description is the one line agentop's panes show (≤80 characters).
func TestDescriptionFitsOneLine(t *testing.T) {
	if d := New().Capabilities().Description; len([]rune(d)) > 80 {
		t.Errorf("description is %d characters, want ≤80: %q", len([]rune(d)), d)
	}
}

// A refused secret is never quoted back: the error lands in the reload status.
func TestConfigErrorDoesNotQuoteTheSecret(t *testing.T) {
	err := New().Configure(json.RawMessage(`{"verdict_url":"http://x","verdict_secret":"hunter2 hunter2"}`))
	if err == nil {
		t.Fatal("accepted a secret with a space")
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Errorf("error quotes the secret: %v", err)
	}
}

// The secret goes on the verdict call as a bearer token, and only there; with
// none configured no Authorization header is sent. A file secret is read and
// trimmed as a mounted Secret leaves it.
func TestVerdictSecretHeader(t *testing.T) {
	var auth atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth.Store(r.Header.Values("Authorization"))
		fmt.Fprint(w, `{"state":"decided","verdict":"allow"}`)
	}))
	t.Cleanup(srv.Close)
	file := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(file, []byte("from-file-0123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		extra string
		want  []string
	}{
		"inline": {`,"verdict_secret":"s3cr3t-hex"`, []string{"Bearer s3cr3t-hex"}},
		"file":   {`,"verdict_secret_file":"` + file + `"`, []string{"Bearer from-file-0123"}},
		"none":   {``, nil},
	} {
		auth.Store([]string(nil))
		g := gate(t, `{"verdict_url":"`+srv.URL+`"`+tc.extra+`}`)
		pctx := outbound("outside.example", stamped())
		if act := g.OnRequest(context.Background(), pctx); act.Type != pipeline.Continue {
			t.Fatalf("%s: action = %v, want Continue", name, act.Type)
		}
		if got := auth.Load().([]string); strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("%s: Authorization = %q, want %q", name, got, tc.want)
		}
		// The request the gate forwards upstream is the app's; the secret is
		// never written onto it.
		if pctx.Headers.Get("Authorization") != "" {
			t.Errorf("%s: the gate wrote Authorization onto the forwarded request", name)
		}
	}
}

// The secret is never in a record and never in a config echo: the session
// API's /v1/pipeline and the stats server's /config both pass raw config
// through redact.JSON, which masks it by its key name.
func TestSecretNeverRecordedOrEchoed(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	unauthorized := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"unauthorized"}`)
	}))
	t.Cleanup(unauthorized.Close)
	down := httptest.NewServer(http.NotFoundHandler())
	downURL := down.URL
	down.Close()

	for _, base := range []string{unauthorized.URL, downURL} {
		raw := `{"verdict_url":"` + base + `","verdict_secret":"` + secret + `"}`
		pctx := outbound("outside.example", stamped())
		gate(t, raw).OnRequest(context.Background(), pctx)
		inv := lastInvocation(t, pctx)
		for k, v := range inv.Details {
			if strings.Contains(v, secret) {
				t.Errorf("%s: detail %s carries the secret", inv.Reason, k)
			}
		}
		if echoed := string(redact.JSON(json.RawMessage(raw))); strings.Contains(echoed, secret) {
			t.Errorf("config echo carries the secret: %s", echoed)
		}
	}
}

// Each answer of the verdict service maps to one fact: a refusal of the
// caller, a full waiter cap, and a decided record with no verdict are unknowns
// of their own, distinguishable in the record; anything else that is not a
// decided verdict is verdict_error. None is an allow.
func TestAnswerMapping(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		reason string
	}{
		{"401", http.StatusUnauthorized, `{"error":"unauthorized"}`, "verdict_unauthorized"},
		{"503 busy", http.StatusServiceUnavailable, `{"error":"verdict_busy"}`, "verdict_busy"},
		{"503 other", http.StatusServiceUnavailable, `{"error":"db down"}`, "verdict_error"},
		{"400", http.StatusBadRequest, `{"error":"wait_ms_too_large","max":3000}`, "verdict_error"},
		{"302", http.StatusFound, ``, "verdict_error"},
		{"decided empty", http.StatusOK, `{"state":"decided","verdict":""}`, "verdict_empty"},
		{"decided blank", http.StatusOK, `{"state":"decided","verdict":"  "}`, "verdict_empty"},
		{"unknown state", http.StatusOK, `{"state":"thinking"}`, "verdict_error"},
		{"no state", http.StatusOK, `{}`, "verdict_error"},
		{"pending", http.StatusOK, `{"state":"pending","waited_ms":3000}`, "verdict_pending"},
		{"unjudged allow", http.StatusOK, `{"state":"unjudged","verdict":"allow","reason":"body_not_captured"}`, "verdict_unjudged"},
		{"unjudged truncated", http.StatusOK, `{"state":"unjudged","verdict":"allow","reason":"body_truncated"}`, "verdict_unjudged"},
		{"unjudged empty", http.StatusOK, `{"state":"unjudged","verdict":""}`, "verdict_empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.status == http.StatusFound {
					w.Header().Set("Location", "http://elsewhere.example/")
				}
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			t.Cleanup(srv.Close)

			pctx := outbound("outside.example", stamped())
			act := gate(t, `{"verdict_url":"`+srv.URL+`"}`).OnRequest(context.Background(), pctx)
			if act.Type != pipeline.Reject {
				t.Fatalf("action = %v, want Reject", act.Type)
			}
			if status, _, _ := act.Violation.Render(); status != http.StatusServiceUnavailable {
				t.Errorf("status = %d, want 503 (nothing was judged)", status)
			}
			inv := lastInvocation(t, pctx)
			if inv.Action != pipeline.ActionDeny || inv.Reason != tc.reason {
				t.Errorf("invocation = %s/%s, want deny/%s", inv.Action, inv.Reason, tc.reason)
			}
			if tc.status != http.StatusOK && inv.Reason == "verdict_error" && inv.Details["status"] != strconv.Itoa(tc.status) {
				t.Errorf("details = %v, want status %d", inv.Details, tc.status)
			}
		})
	}
}

// The verdict client is the gate's own: a reload's Shutdown of the old gate,
// and a second Configure of the same one, close its idle connections instead
// of leaving them to the idle timeout.
func TestShutdownAndReconfigureCloseIdleConnections(t *testing.T) {
	closed := make(chan struct{}, 8)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"state":"decided","verdict":"allow"}`)
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateClosed {
			closed <- struct{}{}
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	raw := `{"verdict_url":"` + srv.URL + `"}`

	waitClosed := func(what string) {
		t.Helper()
		select {
		case <-closed:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: the idle verdict connection was not closed", what)
		}
	}
	g := gate(t, raw)
	g.OnRequest(context.Background(), outbound("outside.example", stamped()))
	if err := g.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	waitClosed("Shutdown")

	g = gate(t, raw)
	g.OnRequest(context.Background(), outbound("outside.example", stamped()))
	if err := g.Configure(json.RawMessage(raw)); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	waitClosed("re-Configure")
	if g.transport == http.DefaultTransport {
		t.Error("the gate uses the shared default transport")
	}
}

// The ordering rule lives in the capabilities, so a chain that puts the gate
// before lineage-telemetry fails at build instead of gating on a missing key.
func TestRequiresLineageEarlier(t *testing.T) {
	caps := New().Capabilities()
	if len(caps.Requires) != 1 || caps.Requires[0] != "lineage-telemetry" {
		t.Fatalf("Requires = %v, want [lineage-telemetry]", caps.Requires)
	}
	if !strings.Contains(caps.Description, "verdict") {
		t.Errorf("description %q does not say what the plugin does", caps.Description)
	}
}

// A stamp lineage did not write this pass — lineage skipped (not ready, a
// bypass) or only observed — is not this exchange's key: unknown, no call.
func TestStampNotWrittenThisPassIsUnknown(t *testing.T) {
	srv, calls, _ := verdictServer(t, 0, `{"state":"decided","verdict":"allow"}`)
	g := gate(t, `{"verdict_url":"`+srv.URL+`"}`)
	for name, rec := range map[string]*pipeline.Invocation{
		"no record": nil,
		"skipped":   {Plugin: "lineage-telemetry", Phase: pipeline.InvocationPhaseRequest, Action: pipeline.ActionSkip, Reason: "not_ready"},
		"observed":  {Plugin: "lineage-telemetry", Phase: pipeline.InvocationPhaseRequest, Action: pipeline.ActionObserve, Reason: "recorded_request"},
	} {
		pctx := &pipeline.Context{Direction: pipeline.Outbound, Host: "outside.example", Headers: stamped()}
		if rec != nil {
			pctx.Record(*rec)
		}
		if act := g.OnRequest(context.Background(), pctx); act.Type != pipeline.Reject {
			t.Errorf("%s: action = %v, want Reject", name, act.Type)
		}
		if inv := lastInvocation(t, pctx); inv.Reason != "no_lineage_stamp" {
			t.Errorf("%s: reason = %q, want no_lineage_stamp", name, inv.Reason)
		}
	}
	if calls.Load() != 0 {
		t.Errorf("verdict calls = %d, want 0", calls.Load())
	}
}

// A refusal is one message for a model and the raw facts for a program, in both shapes the
// framework renders. The record keeps the facts and not the text.
func TestRefusalIsOneMessage(t *testing.T) {
	const text = `{\"drug\": \"x\", \"ssn\": \"[person.govID]\"}`
	const opening = "Sentry gate (data governance) refused this request to outside.example. Nothing was delivered."
	const offer = "\nTo deliver the rest, make the same call again now with the marked parts removed, then answer. It will be judged again."
	for _, tc := range []struct {
		name       string
		answer     string
		wantStatus int
		wantCode   string
		wantMsg    string
		want       map[string]any
		wantRecord map[string]string
	}{
		{
			name:       "decided block",
			answer:     `{"state":"decided","verdict":"block","version":3,"exchange_id":"e","rules":["DG-001","DG-004"],"labels":["person.govID"],"redacted_payload":"` + text + `"}`,
			wantStatus: http.StatusForbidden, wantCode: "policy.content-blocked",
			wantMsg:    opening + "\nFlagged parts are marked [category]:\n" + `{"drug": "x", "ssn": "[person.govID]"}` + offer,
			want:       map[string]any{"state": "decided", "verdict": "block", "exchange_id": exchangeID, "rules": []any{"DG-001", "DG-004"}, "labels": []any{"person.govID"}, "redacted_payload": `{"drug": "x", "ssn": "[person.govID]"}`},
			wantRecord: map[string]string{"rules": "DG-001,DG-004", "labels": "person.govID", "verdict": "block", "version": "3", "exchange_id": exchangeID},
		},
		{
			name:       "a block with labels and no text lists them, and offers nothing",
			answer:     `{"state":"decided","verdict":"block","rules":["DG-001"],"labels":["a","b"]}`,
			wantStatus: http.StatusForbidden, wantCode: "policy.content-blocked",
			wantMsg: opening + "\nFlagged: a, b.",
			want:    map[string]any{"state": "decided", "verdict": "block", "exchange_id": exchangeID, "rules": []any{"DG-001"}, "labels": []any{"a", "b"}},
		},
		{
			name:       "a block with text and nothing flagged shows no text",
			answer:     `{"state":"decided","verdict":"block","rules":["DG-001"],"labels":[],"redacted_payload":"plain"}`,
			wantStatus: http.StatusForbidden, wantCode: "policy.content-blocked",
			wantMsg: opening,
			want:    map[string]any{"state": "decided", "verdict": "block", "exchange_id": exchangeID, "rules": []any{"DG-001"}, "labels": []any{}, "redacted_payload": "plain"},
		},
		{
			name:       "unjudged block",
			answer:     `{"state":"unjudged","verdict":"block","reason":"body_truncated","rules":["DG-001"],"labels":["a"],"redacted_payload":"cut"}`,
			wantStatus: http.StatusForbidden, wantCode: "policy.content-blocked",
			wantMsg: opening + " Only part of it could be judged.\nFlagged parts are marked [category]:\ncut" + offer,
			want:    map[string]any{"state": "unjudged", "verdict": "block", "reason": "body_truncated", "exchange_id": exchangeID, "rules": []any{"DG-001"}, "labels": []any{"a"}, "redacted_payload": "cut"},
		},
		{
			name:       "unjudged, nothing denied",
			answer:     `{"state":"unjudged","verdict":"allow","reason":"body_truncated","rules":[],"labels":["a"],"redacted_payload":"not for an allow"}`,
			wantStatus: http.StatusServiceUnavailable, wantCode: "policy.verdict-unavailable",
			wantMsg:    opening + " Only part of it could be judged.\nFlagged: a.",
			want:       map[string]any{"state": "unjudged", "verdict": "allow", "reason": "body_truncated", "exchange_id": exchangeID, "rules": []any{}, "labels": []any{"a"}},
			wantRecord: map[string]string{"unread": "body_truncated", "labels": "a"},
		},
		{
			name:       "pending",
			answer:     `{"state":"pending","exchange_id":"e","waited_ms":2000}`,
			wantStatus: http.StatusServiceUnavailable, wantCode: "policy.verdict-unavailable",
			wantMsg: opening + " No verdict was given, so nothing was judged and nothing is flagged.",
			want:    map[string]any{"reason": "verdict_pending", "exchange_id": exchangeID},
		},
		{
			name:       "malformed rules, labels and text: the block stands",
			answer:     `{"state":"decided","verdict":"block","rules":"DG-001","labels":[{"category":"a"}],"redacted_payload":{"x":1}}`,
			wantStatus: http.StatusForbidden, wantCode: "policy.content-blocked",
			wantMsg:    opening,
			want:       map[string]any{"state": "decided", "verdict": "block", "exchange_id": exchangeID, "rules": []any{}, "labels": []any{}},
			wantRecord: map[string]string{"rules_error": "not a list of strings", "labels_error": "not a list of strings", "redacted_payload_error": "not a string"},
		},
		{
			name:       "null rules, labels and text: the block stands",
			answer:     `{"state":"decided","verdict":"block","rules":null,"labels":null,"redacted_payload":null}`,
			wantStatus: http.StatusForbidden, wantCode: "policy.content-blocked",
			wantMsg: opening,
			want:    map[string]any{"state": "decided", "verdict": "block", "exchange_id": exchangeID, "rules": []any{}, "labels": []any{}},
		},
		{
			name:       "a fact missing from an older service",
			answer:     `{"state":"decided","verdict":"block"}`,
			wantStatus: http.StatusForbidden, wantCode: "policy.content-blocked",
			wantMsg: opening,
			want:    map[string]any{"state": "decided", "verdict": "block", "exchange_id": exchangeID, "rules": []any{}, "labels": []any{}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _, _ := verdictServer(t, 0, tc.answer)
			pctx := outbound("outside.example:8000", stamped())
			act := gate(t, `{"verdict_url":"`+srv.URL+`"}`).OnRequest(context.Background(), pctx)
			if act.Type != pipeline.Reject {
				t.Fatalf("action = %v, want Reject", act.Type)
			}
			act.Violation.PluginName = pluginName // the framework stamps it

			status, _, raw := act.Violation.Render()
			if status != tc.wantStatus {
				t.Errorf("status = %d, want %d", status, tc.wantStatus)
			}
			var envelope struct {
				Error, Message, Plugin string
				Details                map[string]any
			}
			if err := json.Unmarshal(raw, &envelope); err != nil {
				t.Fatalf("envelope %s: %v", raw, err)
			}

			var frame struct {
				JSONRPC string `json:"jsonrpc"`
				ID      any    `json:"id"`
				Error   struct {
					Code    int    `json:"code"`
					Message string `json:"message"`
					Data    struct {
						Error, Plugin string
						Details       map[string]any
					} `json:"data"`
				} `json:"error"`
			}
			if err := json.Unmarshal(httpx.MarshalMCPRejectionBody(act, 7), &frame); err != nil {
				t.Fatalf("frame: %v", err)
			}
			if frame.JSONRPC != "2.0" || frame.ID != float64(7) || frame.Error.Code != -32000 {
				t.Errorf("frame = %+v", frame)
			}

			for shape, got := range map[string]struct {
				code, message, plugin string
				details               map[string]any
			}{
				"envelope": {envelope.Error, envelope.Message, envelope.Plugin, envelope.Details},
				"frame":    {frame.Error.Data.Error, frame.Error.Message, frame.Error.Data.Plugin, frame.Error.Data.Details},
			} {
				if got.code != tc.wantCode || got.message != tc.wantMsg || got.plugin != pluginName {
					t.Errorf("%s: code %q, message %q, plugin %q", shape, got.code, got.message, got.plugin)
				}
				// Exactly these raw facts, and how long the gate waited.
				if _, ok := got.details["waited_ms"].(float64); !ok {
					t.Errorf("%s: waited_ms = %#v", shape, got.details["waited_ms"])
				}
				delete(got.details, "waited_ms")
				if !reflect.DeepEqual(got.details, tc.want) {
					t.Errorf("%s: details = %#v, want %#v", shape, got.details, tc.want)
				}
			}

			inv := lastInvocation(t, pctx)
			for k, want := range tc.wantRecord {
				if inv.Details[k] != want {
					t.Errorf("record[%s] = %q, want %q", k, inv.Details[k], want)
				}
			}
			if _, ok := inv.Details["redacted_payload"]; ok {
				t.Error("the record keeps the redacted payload")
			}
		})
	}
}

// Each protocol gets the reply its stock client hands on, with the message as the text a
// model reads and the raw facts beside it.
func TestRefusalIsTheReplyTheClientHandsOn(t *testing.T) {
	const answer = `{"state":"decided","verdict":"block","rules":["DG-001"],"labels":["a"],"redacted_payload":"[a]"}`
	const message = "Sentry gate (data governance) refused this request to outside.example. Nothing was delivered.\nFlagged parts are marked [category]:\n[a]\n" + sendWithoutMarked
	block := func(t *testing.T, set func(*pipeline.Context)) pipeline.Action {
		t.Helper()
		srv, _, _ := verdictServer(t, 0, answer)
		pctx := outbound("outside.example:8000", stamped())
		set(pctx)
		act := gate(t, `{"verdict_url":"`+srv.URL+`"}`).OnRequest(context.Background(), pctx)
		if act.Type != pipeline.Reject {
			t.Fatalf("action = %v, want Reject", act.Type)
		}
		return act
	}
	checkFacts := func(t *testing.T, facts map[string]any) {
		t.Helper()
		details, _ := facts["details"].(map[string]any)
		if facts["error"] != "policy.content-blocked" || facts["plugin"] != pluginName || details["redacted_payload"] != "[a]" {
			t.Errorf("facts = %v", facts)
		}
	}

	t.Run("a tools/call gets a result with isError", func(t *testing.T) {
		act := block(t, func(p *pipeline.Context) {
			p.Extensions.MCP = &pipeline.MCPExtension{Method: "tools/call", RPCID: float64(7)}
		})
		var frame struct {
			ID     any             `json:"id"`
			Error  json.RawMessage `json:"error"`
			Result struct {
				IsError           bool             `json:"isError"`
				Content           []map[string]any `json:"content"`
				StructuredContent map[string]any   `json:"structuredContent"`
			} `json:"result"`
		}
		if err := json.Unmarshal(httpx.MarshalMCPRejectionBody(act, float64(7)), &frame); err != nil {
			t.Fatal(err)
		}
		if frame.ID != float64(7) || frame.Error != nil || !frame.Result.IsError {
			t.Errorf("frame = %+v", frame)
		}
		if len(frame.Result.Content) != 1 || frame.Result.Content[0]["type"] != "text" || frame.Result.Content[0]["text"] != message {
			t.Errorf("content = %v", frame.Result.Content)
		}
		checkFacts(t, frame.Result.StructuredContent)
	})

	t.Run("another MCP method keeps the error frame", func(t *testing.T) {
		act := block(t, func(p *pipeline.Context) {
			p.Extensions.MCP = &pipeline.MCPExtension{Method: "resources/read", RPCID: float64(7)}
		})
		if act.Violation.RPCResult != nil {
			t.Errorf("RPCResult = %v", act.Violation.RPCResult)
		}
	})

	for _, tc := range []struct {
		method, wantType, prefix, suffix string
	}{
		{"message/send", "application/json", "", ""},
		{"message/stream", "text/event-stream", "data: ", "\n\n"},
	} {
		t.Run("an A2A "+tc.method+" gets an agent message at 200", func(t *testing.T) {
			act := block(t, func(p *pipeline.Context) { p.Extensions.A2A = &pipeline.A2AExtension{Method: tc.method, RPCID: "r1"} })
			status, headers, raw := act.Violation.Render()
			if status != http.StatusOK || headers.Get("Content-Type") != tc.wantType {
				t.Errorf("status %d, type %q", status, headers.Get("Content-Type"))
			}
			text := string(raw)
			if !strings.HasPrefix(text, tc.prefix) || !strings.HasSuffix(text, tc.suffix) {
				t.Fatalf("body = %q", text)
			}
			var frame struct {
				ID     any `json:"id"`
				Result struct {
					Kind, MessageID, Role string
					Parts                 []map[string]any
					Metadata              map[string]map[string]any
				} `json:"result"`
			}
			if err := json.Unmarshal([]byte(strings.TrimSuffix(strings.TrimPrefix(text, tc.prefix), tc.suffix)), &frame); err != nil {
				t.Fatal(err)
			}
			if frame.ID != "r1" || frame.Result.Kind != "message" || frame.Result.Role != "agent" || frame.Result.MessageID != "sentry-gate-refusal-"+exchangeID {
				t.Errorf("frame = %+v", frame)
			}
			if len(frame.Result.Parts) != 1 || frame.Result.Parts[0]["kind"] != "text" || frame.Result.Parts[0]["text"] != message {
				t.Errorf("parts = %v", frame.Result.Parts)
			}
			checkFacts(t, frame.Result.Metadata[pluginName])
		})
	}

	t.Run("anything else keeps the envelope and its status", func(t *testing.T) {
		act := block(t, func(*pipeline.Context) {})
		if status, _, _ := act.Violation.Render(); status != http.StatusForbidden || act.Violation.RPCResult != nil {
			t.Errorf("status %d, RPCResult %v", status, act.Violation.RPCResult)
		}
	})
}

// Two refusals given before the gate had an exchange id are still two messages.
func TestA2ARefusalsWithoutAKeyGetTheirOwnIDs(t *testing.T) {
	ids := map[string]bool{}
	for range 2 {
		pctx := &pipeline.Context{Direction: pipeline.Outbound, Host: "outside.example", Headers: http.Header{}}
		pctx.Extensions.A2A = &pipeline.A2AExtension{Method: "message/send", RPCID: "r1"}
		act := gate(t, `{"verdict_url":"http://127.0.0.1:1"}`).OnRequest(context.Background(), pctx)
		if act.Type != pipeline.Reject || lastInvocation(t, pctx).Reason != "no_lineage_stamp" {
			t.Fatalf("action = %v, record %v", act.Type, lastInvocation(t, pctx))
		}
		var frame struct {
			Result struct{ MessageID string }
		}
		if err := json.Unmarshal(act.Violation.Body, &frame); err != nil {
			t.Fatal(err)
		}
		if frame.Result.MessageID == "" || ids[frame.Result.MessageID] {
			t.Errorf("message id %q seen before: %v", frame.Result.MessageID, ids)
		}
		ids[frame.Result.MessageID] = true
	}
}

// A refusal's text never says what a failed call said: it can carry the internal
// URL and the key.
func TestRefusalLeavesServiceErrorsInTheRecord(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing answers: the transport error names the URL

	pctx := outbound("outside.example", stamped())
	act := gate(t, `{"verdict_url":"`+url+`"}`).OnRequest(context.Background(), pctx)
	_, _, raw := act.Violation.Render()
	if strings.Contains(string(raw), strings.TrimPrefix(url, "http://")) || strings.Contains(string(raw), traceID) {
		t.Errorf("the refusal leaks the call: %s", raw)
	}
	inv := lastInvocation(t, pctx)
	if inv.Reason != "verdict_error" || !strings.Contains(inv.Details["error"], strings.TrimPrefix(url, "http://")) {
		t.Errorf("the record lost the error: %v", inv)
	}
	var body struct{ Details map[string]any }
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if body.Details["reason"] != "verdict_error" || body.Details["exchange_id"] != exchangeID {
		t.Errorf("details = %v", body.Details)
	}
}

// Refused before any key was read, a refusal names no exchange.
func TestRefusalWithNoKeyNamesNoExchange(t *testing.T) {
	pctx := &pipeline.Context{Direction: pipeline.Outbound, Host: "outside.example", Headers: stamped()}
	act := gate(t, `{"verdict_url":"http://verdict.invalid"}`).OnRequest(context.Background(), pctx)
	if act.Type != pipeline.Reject {
		t.Fatalf("action = %v, want Reject", act.Type)
	}
	if _, ok := act.Violation.Details["exchange_id"]; ok || act.Violation.Details["reason"] != "no_lineage_stamp" {
		t.Errorf("details = %v", act.Violation.Details)
	}
}

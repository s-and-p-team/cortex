package forwardproxy

// The Sentry gate never judges a tunnel, and that rule rests on how this
// listener runs one: the outbound pipeline runs on the CONNECT itself, before
// the bridge decision (handleConnect), and again on every request a bridged
// tunnel decrypts (bridgedHandler → serveOutbound). These tests pin both halves
// with the real gate: an opaque tunnel to an unlisted host opens and carries its
// bytes with a block verdict waiting, and a bridged tunnel's request, a CONNECT
// sent inside it included, is judged by its own lineage stamp and refused,
// without reaching the origin.

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rossoctl/cortex/core/pipeline"
	"github.com/rossoctl/cortex/core/plugins/sentrygate"
	"github.com/rossoctl/cortex/core/tlsbridge"
)

const gateTrace = "4bf92f3577b34da6a3ce929d0e0e4736"

// lineageStamper stands in for lineage-telemetry: the same name (the gate's
// Requires and its stamp rule both key on it), a fresh stamp per pass written
// into the forwarded tracestate, and the modify/stamped_tracestate record
// lineage leaves when it wrote.
type lineageStamper struct {
	n      atomic.Int32
	mu     sync.Mutex
	stamps map[string]string // method → the stamp written on its pass
}

func (s *lineageStamper) Name() string { return "lineage-telemetry" }
func (s *lineageStamper) Capabilities() pipeline.PluginCapabilities {
	return pipeline.PluginCapabilities{}
}
func (s *lineageStamper) OnRequest(_ context.Context, pctx *pipeline.Context) pipeline.Action {
	stamp := fmt.Sprintf("%016x", 0xa0+s.n.Add(1))
	pctx.Headers.Set("traceparent", "00-"+gateTrace+"-"+stamp+"-01")
	pctx.Headers.Set("tracestate", "lineage-parent="+stamp)
	pctx.Modify("stamped_tracestate")
	s.mu.Lock()
	s.stamps[pctx.Method] = stamp
	s.mu.Unlock()
	return pipeline.Action{Type: pipeline.Continue}
}
func (s *lineageStamper) OnResponse(context.Context, *pipeline.Context) pipeline.Action {
	return pipeline.Action{Type: pipeline.Continue}
}

// gateRecordProbe runs after the gate and keeps the gate's record of each pass
// it let through, by method.
type gateRecordProbe struct {
	mu   sync.Mutex
	seen map[string]pipeline.Invocation
}

func (p *gateRecordProbe) Name() string { return "gate-record-probe" }
func (p *gateRecordProbe) Capabilities() pipeline.PluginCapabilities {
	return pipeline.PluginCapabilities{}
}
func (p *gateRecordProbe) OnRequest(_ context.Context, pctx *pipeline.Context) pipeline.Action {
	if inv := pctx.Extensions.Invocations; inv != nil {
		for _, rec := range inv.Outbound {
			if rec.Plugin == "sentry-gate" {
				p.mu.Lock()
				p.seen[pctx.Method] = rec
				p.mu.Unlock()
			}
		}
	}
	return pipeline.Action{Type: pipeline.Continue}
}
func (p *gateRecordProbe) OnResponse(context.Context, *pipeline.Context) pipeline.Action {
	return pipeline.Action{Type: pipeline.Continue}
}

// gatedChain is [stamper, sentry-gate, probe] with a verdict service that
// answers block to everything and records what it was asked.
func gatedChain(t *testing.T) (*pipeline.Pipeline, *lineageStamper, *gateRecordProbe, *atomic.Value, *atomic.Int32) {
	t.Helper()
	var asked atomic.Value
	asked.Store("")
	var calls atomic.Int32
	verdicts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		asked.Store(r.URL.Path)
		fmt.Fprint(w, `{"state":"decided","verdict":"block","interaction_id":"i-1","version":1}`)
	}))
	t.Cleanup(verdicts.Close)
	gate := sentrygate.New()
	if err := gate.Configure(json.RawMessage(`{"verdict_url":"` + verdicts.URL + `","wait_ms":1000}`)); err != nil {
		t.Fatalf("gate Configure: %v", err)
	}
	stamper := &lineageStamper{stamps: map[string]string{}}
	probe := &gateRecordProbe{seen: map[string]pipeline.Invocation{}}
	p, err := pipeline.New([]pipeline.Plugin{stamper, gate, probe})
	if err != nil {
		t.Fatalf("pipeline.New: %v", err)
	}
	return p, stamper, probe, &asked, &calls
}

// connect issues a CONNECT to target through the proxy and returns the conn
// positioned after the 200, with the reader that consumed it.
func connect(t *testing.T, proxyURL, target string) (net.Conn, *bufio.Reader) {
	t.Helper()
	u, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	req, err := http.NewRequest(http.MethodConnect, "//"+target, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host, req.URL.Host = target, target
	if err := req.Write(conn); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200: the gate must never refuse a tunnel", resp.StatusCode)
	}
	return conn, br
}

func TestSentryGate_OpaqueTunnelIsUnjudgedAndOpens(t *testing.T) {
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = origin.Close() })
	go func() {
		c, err := origin.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("opaque-bytes"))
		_ = c.Close()
	}()

	p, _, probe, _, calls := gatedChain(t)
	srv := &Server{OutboundPipeline: pipeline.NewHolder(p), Client: http.DefaultClient} // no TLS bridge: opaque
	proxy := httptest.NewServer(srv.Handler())
	t.Cleanup(proxy.Close)

	_, br := connect(t, proxy.URL, origin.Addr().String())
	got := make([]byte, len("opaque-bytes"))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	if string(got) != "opaque-bytes" {
		t.Errorf("tunnel carried %q, want the origin's bytes", got)
	}
	if calls.Load() != 0 {
		t.Errorf("verdict calls = %d, want 0: a CONNECT is never judged", calls.Load())
	}
	probe.mu.Lock()
	rec := probe.seen[http.MethodConnect]
	probe.mu.Unlock()
	if rec.Action != pipeline.ActionAllow || rec.Reason != "unjudged" || rec.Details["kind"] != "tunnel" {
		t.Errorf("gate record on the CONNECT = %s/%s %v, want allow/unjudged kind=tunnel", rec.Action, rec.Reason, rec.Details)
	}
}

func TestSentryGate_BridgedRequestIsJudgedAsARequest(t *testing.T) {
	bridgedRequestIsJudged(t, http.MethodPost)
}

// A CONNECT sent inside a decrypted tunnel opens nothing: the bridge would carry
// it to the origin, so it is judged like any other request.
func TestSentryGate_ConnectInsideABridgedTunnelIsJudged(t *testing.T) {
	bridgedRequestIsJudged(t, http.MethodConnect)
}

func bridgedRequestIsJudged(t *testing.T, method string) {
	t.Helper()
	// The bridge's own HEAD probe (upstream verification before it forges a
	// certificate) reaches the origin by design; the gated request must not.
	var reached atomic.Bool
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			reached.Store(true)
		}
		_, _ = w.Write([]byte("OK"))
	}))
	t.Cleanup(origin.Close)
	originCAPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw})
	originURL, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	target := originURL.Host

	src, err := tlsbridge.NewEphemeralSource()
	if err != nil {
		t.Fatalf("NewEphemeralSource: %v", err)
	}
	up, err := tlsbridge.NewUpstreamClient(originCAPEM, false)
	if err != nil {
		t.Fatalf("NewUpstreamClient: %v", err)
	}
	engine := &tlsbridge.Engine{
		Decision: mustBridgeDecision(t, portOf(target)),
		Term:     tlsbridge.NewTerminator(tlsbridge.NewMinter(src, tlsbridge.MinterOpts{})),
		Skip:     tlsbridge.NewSkipSet(),
		Upstream: up,
		CAPEM:    src.CACertPEM(),
	}

	p, stamper, probe, asked, calls := gatedChain(t)
	srv := &Server{OutboundPipeline: pipeline.NewHolder(p), Client: http.DefaultClient, TLSBridge: engine}
	proxy := httptest.NewServer(srv.Handler())
	t.Cleanup(proxy.Close)

	conn, br := connect(t, proxy.URL, target)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(engine.CAPEM) {
		t.Fatal("append bridge CA")
	}
	tconn := tls.Client(&bufferedConn{Conn: conn, r: br}, &tls.Config{
		ServerName: hostOnly(target), RootCAs: pool, NextProtos: []string{"http/1.1"},
	})
	_ = tconn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tconn.Handshake(); err != nil {
		t.Fatalf("handshake through the bridge: %v", err)
	}
	req, err := http.NewRequest(method, "https://"+target+"/report", nil)
	if err != nil {
		t.Fatal(err)
	}
	writeErr := make(chan error, 1)
	go func() { writeErr <- req.Write(tconn) }()
	resp, err := http.ReadResponse(bufio.NewReader(tconn), req)
	if err != nil {
		t.Fatalf("read bridged response: %v", err)
	}
	_ = resp.Body.Close()
	if werr := <-writeErr; werr != nil {
		t.Fatalf("write bridged request: %v", werr)
	}

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("bridged request status = %d, want 403 (block verdict)", resp.StatusCode)
	}
	if reached.Load() {
		t.Error("the bridged request reached the origin: it was not gated")
	}
	if calls.Load() != 1 {
		t.Errorf("verdict calls = %d, want 1 (the decrypted request, not the CONNECT)", calls.Load())
	}
	if method == http.MethodConnect {
		return // the assertions below tell the two passes apart by method
	}
	stamper.mu.Lock()
	postStamp, connectStamp := stamper.stamps[http.MethodPost], stamper.stamps[http.MethodConnect]
	stamper.mu.Unlock()
	if want := "/verdicts/" + gateTrace + "/" + postStamp; asked.Load() != want {
		t.Errorf("asked %v, want %s (the decrypted request's own stamp, not the CONNECT's %s)", asked.Load(), want, connectStamp)
	}
	probe.mu.Lock()
	rec := probe.seen[http.MethodConnect]
	probe.mu.Unlock()
	if rec.Reason != "unjudged" {
		t.Errorf("gate record on the CONNECT = %s/%s, want allow/unjudged", rec.Action, rec.Reason)
	}
}

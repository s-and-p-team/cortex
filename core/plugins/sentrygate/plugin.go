// Package sentrygate provides the sentry-gate plugin: it holds an outbound
// request to a destination outside its pass list until a verdict service has
// answered for that exchange, and rejects the request when the answer says so.
//
// The plugin decides nothing about content. The verdict is the verdict
// service's (a governance record keyed by the exchange), and the plugin knows
// the destination host, the exchange's key, how long it may wait, and what
// lineage-telemetry recorded for this pass. That keeps the sidecar a carrier of
// facts: the meaning — which payloads may leave for which destination — lives
// where the facts are read.
//
// The exchange key is the lineage wire contract's own: the trace id of the
// forwarded traceparent and the request span id the lineage-telemetry plugin
// stamps into the forwarded tracestate (member "lineage-parent") before the
// request leaves. The gate reads those two values off the outbound headers,
// exactly as the peer's inbound sidecar would, so the key depends on the
// published wire shape. Whether the stamp is this pass's, and whether capture is
// off, come from lineage's invocation record (stamped_tracestate and its
// capture_io detail), which sentrygate_key_test.go pins against the real plugin.
// That is also why the gate must run after lineage-telemetry
// (Capabilities.Requires enforces it at build): lineage records the request
// span on sight, so an exchange the gate rejects is still in the record — a
// request span, and a response span whose lineage.outcome is "denied" and
// lineage.denied_by names this plugin.
//
// Waiting is selective. A request to a host on the pass list (pass_hosts, and
// with pass_single_label a cluster short name) continues at once and asks
// nothing; every other outbound request waits up to wait_ms (at most 3000,
// the verdict service's own cap).
//
// When no verdict arrives from a slow or dead service (slowOrDead), the fallback
// setting decides: deny, the default, refuses with a 503 (fail closed), so the
// verdict service is a dependency of every gated egress; allow delivers unjudged.
// Either is recorded as the setting's outcome. A fail_mode row for the request's host
// replaces wait_ms, fallback or both for that host, and a slice under sources does so
// for the requests of one source workload, which lineage's record names (self_id).
// Any other missing verdict is a fault and is refused whatever the setting, and so is
// a body lineage marked as cut at max_payload_bytes or not captured: its verdict would
// have said unjudged.
//
// A tunnel is never judged. The forward proxy runs the pipeline on the
// CONNECT before it decides whether tls-bridge will decrypt the tunnel, and a
// bridged tunnel's decrypted requests run the pipeline again, where each is
// judged like any other request. What an opaque tunnel may carry is the
// listener's tls_bridge policy, not a verdict's: there is no payload to ask
// about. So the CONNECT continues and is recorded as not_inspected (kind=tunnel). A
// CONNECT sent inside a decrypted tunnel opens nothing: the bridge re-originates
// it with its body, and it is judged like any other request.
//
// The transparent listener (the redirect that captures egress the app sent
// without the proxy) hands the pipeline each captured connection as a
// synthetic CONNECT, plaintext HTTP on port 80 included. So what the gate
// judges is a request sent through the forward proxy (HTTP_PROXY) and a
// request inside a tunnel tls-bridge decrypts; a transparently captured
// connection tls-bridge does not decrypt is recorded not_inspected (kind=tunnel),
// and its bytes, readable or not, leave without a verdict.
//
// A message that carries no data continues at once, with nothing asked: an agent
// card fetch, and the MCP handshake messages with nothing in them beyond what the
// handshake needs (carriesNoData). Without this an agent could not start against, or
// connect to, a peer or a tool outside its pass list.
//
// A body lineage does not capture is never read, so the service answers
// "unjudged". With capture_io off the operator gave up judging bodies, and such
// a request continues, recorded as unread_capture_off; lineage's record of this
// pass says whether capture is off, so the same answer with capture on (a binary
// body, a parser's nothing) stays refused, as does any body cut at
// max_payload_bytes. capture_io defaults to off, and the gate cannot see that
// until a request shows it, so it warns on the first such body it lets through.
//
// A refusal has two readers. A model reads one message, the processed text: what
// happened, which parts were flagged, and on a block with marked text that the rest
// can be sent again. A program reads the raw facts beside it, what the service
// answered and how long the gate waited. It reaches the app in the reply that app's
// stock client hands to its caller rather than raises on: a tools/call gets an MCP
// result with isError, an A2A send gets an agent message at 200, and anything else
// gets the framework's rejection envelope. Whether to send again is the caller's: a
// new request is judged like any other. A rules, labels or redacted_payload value of
// the wrong shape is dropped and noted in the record; the refusal stands. The text of
// a service or transport error stays in the record, because it can carry the internal
// URL.
//
// The verdict call carries verdict_secret (or the contents of
// verdict_secret_file) as an Authorization bearer token. The plugin never logs
// it or puts it in an invocation record, and the config echoes (/v1/pipeline,
// the stats server's /config) mask it by its key name.
package sentrygate

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/rossoctl/cortex/core/config"
	"github.com/rossoctl/cortex/core/pipeline"
	"github.com/rossoctl/cortex/core/plugins"
)

const pluginName = "sentry-gate"

// stampKey is the lineage wire contract's tracestate member: on an outbound
// request lineage-telemetry has forwarded, its value is this exchange's
// request span id (lineage.exchange.id). Read here, never written.
const stampKey = "lineage-parent"

// verdictGrace is how much longer than wait_ms the HTTP call may take: the
// verdict service answers "pending" at wait_ms, and the answer needs time to
// arrive.
const verdictGrace = 500 * time.Millisecond

// maxWaitMS is the longest hold the verdict service accepts; it answers 400
// above it. A config asking for more is refused at decode rather than clamped
// somewhere the operator cannot see.
const maxWaitMS = 3000

// maxIdlePerHost sizes the verdict client's idle pool to the verdict
// service's cap on concurrent waiters, so a burst of held requests reuses
// connections instead of opening one per wait (the stock pool keeps two).
const maxIdlePerHost = 64

// bodyNotCaptured is the verdict service's reason for a record that saw none of
// the request body.
const bodyNotCaptured = "body_not_captured"

// refusedOpening opens every refusal's message, so whoever reads one, a model
// included, knows who refused and that nothing left.
const refusedOpening = "Sentry gate (data governance) refused this request to %s. Nothing was delivered."

// sendWithoutMarked closes a message that shows marked text. A model acts on it only
// when it reads as a next step; it says the new request is judged, because nothing
// promises it passes.
const sendWithoutMarked = "To deliver the rest, make the same call again now with the marked parts removed, then answer. It will be judged again."

// noDataBodyMax bounds a body carriesNoData reads. The longest real one, initialize, is
// about 150 bytes.
const noDataBodyMax = 256

// noDataIDDigits bounds a JSON-RPC id in a message that carries no data: the id is
// the client's counter, and a longer number is room for a value.
const noDataIDDigits = 6

// The values initialize may hold and still carry no data, raw JSON with their quotes.
var (
	protocolVersion = regexp.MustCompile(`^"[0-9]{4}-[0-9]{2}-[0-9]{2}"$`)
	clientName      = regexp.MustCompile(`^"[A-Za-z0-9._-]{1,32}"$`)
	clientVersion   = regexp.MustCompile(`^"[A-Za-z0-9._-]{1,16}"$`)
)

func init() {
	plugins.RegisterPlugin(pluginName, func() pipeline.Plugin { return New() })
}

// Config is the plugin's local config.
type Config struct {
	VerdictURL      string   `json:"verdict_url" required:"true" description:"Base URL of the verdict service; the plugin GETs {verdict_url}/verdicts/{trace_id}/{exchange_id}?wait_ms=N."`
	PassHosts       []string `json:"pass_hosts" description:"Outbound host globs (path.Match, port stripped, case folded) that never wait for a verdict."`
	PassSingleLabel bool     `json:"pass_single_label" description:"A cluster short name (one DNS label, not a number) never waits." default:"true"`
	WaitMS          int      `json:"wait_ms" description:"Longest an outbound request is held for its verdict, 1..3000; a fail_mode row or a slice under sources can set its own." default:"2000"`
	DenyOn          []string `json:"deny_on" description:"Verdicts that reject the request." default:"block"`
	Fallback        string   `json:"fallback" description:"What a request gets when no verdict arrives from a slow or dead service: deny, or allow (deliver unjudged)." default:"deny"`
	// The secret's key ends in "secret" so redact.JSON masks it wherever the
	// raw config is echoed; renaming it would put the value on /v1/pipeline.
	VerdictSecret     string `json:"verdict_secret" description:"Shared secret sent as an Authorization bearer token on every verdict call; empty sends no header."`
	VerdictSecretFile string `json:"verdict_secret_file" description:"File holding the shared secret (a mounted Secret), read when the plugin is configured; exclusive with verdict_secret."`
	// fail_mode and sources, and once decoded the unnamed slice and the slices by source.
	FailMode []FailModeRow    `json:"fail_mode" description:"Rows {destination, wait_ms?, fallback?} replacing wait_ms and fallback for one host name, whatever the request's port or case."`
	Sources  map[string]Slice `json:"sources" description:"Slices by source workload (lineage's self_id), each {wait_ms?, fallback?, fail_mode?} for its requests; a default left out is the top-level key."`
	unnamed  failSlice
	sources  map[string]failSlice
}

func defaultConfig() Config {
	return Config{
		PassSingleLabel: true,
		WaitMS:          2000,
		DenyOn:          []string{"block"},
		Fallback:        "deny",
	}
}

func decodeConfig(raw json.RawMessage) (Config, error) {
	cfg := defaultConfig()
	if len(raw) > 0 {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&cfg); err != nil {
			return Config{}, fmt.Errorf("sentry-gate config: %w", err)
		}
	}
	u, err := url.Parse(cfg.VerdictURL)
	if cfg.VerdictURL == "" || err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return Config{}, fmt.Errorf("sentry-gate config: verdict_url %q must be an http(s) URL", cfg.VerdictURL)
	}
	cfg.VerdictURL = strings.TrimRight(cfg.VerdictURL, "/")
	if cfg.WaitMS <= 0 {
		return Config{}, fmt.Errorf("sentry-gate config: wait_ms %d must be 1..%d (a hold of 0 ms or less leaves no time for a verdict)", cfg.WaitMS, maxWaitMS)
	}
	if cfg.WaitMS > maxWaitMS {
		return Config{}, fmt.Errorf("sentry-gate config: wait_ms %d must be 1..%d (the verdict service refuses a longer wait)", cfg.WaitMS, maxWaitMS)
	}
	if cfg.Fallback != "deny" && cfg.Fallback != "allow" {
		return Config{}, fmt.Errorf("sentry-gate config: fallback %q must be deny or allow", cfg.Fallback)
	}
	if err = decodeSlices(&cfg); err != nil {
		return Config{}, err
	}
	if len(cfg.DenyOn) == 0 {
		return Config{}, errors.New("sentry-gate config: deny_on is empty, so no verdict could ever reject; remove the plugin instead")
	}
	for i, entry := range cfg.PassHosts {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if _, err := path.Match(entry, ""); err != nil || entry == "" {
			return Config{}, fmt.Errorf("sentry-gate config: invalid pass_hosts glob %q", cfg.PassHosts[i])
		}
		cfg.PassHosts[i] = entry
	}
	if cfg.VerdictSecret != "" && cfg.VerdictSecretFile != "" {
		return Config{}, errors.New("sentry-gate config: set verdict_secret or verdict_secret_file, not both")
	}
	if cfg.VerdictSecretFile != "" {
		secret, err := config.ReadCredentialFile(cfg.VerdictSecretFile)
		if err != nil {
			return Config{}, fmt.Errorf("sentry-gate config: verdict_secret_file: %w", err)
		}
		cfg.VerdictSecret = secret
	}
	// Never quote the value in an error: it would land in the reload status.
	if !isToken(cfg.VerdictSecret) {
		return Config{}, errors.New("sentry-gate config: the verdict secret must be one token, with no whitespace or control characters")
	}
	return cfg, nil
}

// isToken reports whether s can go on the wire as a bearer token as is:
// visible ASCII only. Empty is a token (no header is sent).
func isToken(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

// Gate is the sentry-gate plugin.
type Gate struct {
	cfg    Config
	denyOn map[string]bool
	client *http.Client
	// transport is the client's own, never http.DefaultTransport, so closing
	// its idle connections touches no one else's.
	transport *http.Transport
	// warnUnread warns once per gate, so a reload that builds a new one warns
	// again: the reload may be what turned capture off.
	warnUnread sync.Once
}

// New returns an unconfigured gate.
func New() *Gate { return &Gate{} }

func (g *Gate) Name() string { return pluginName }

func (g *Gate) ConfigSchema() []pipeline.FieldSchema { return pipeline.SchemaOf(Config{}) }

func (g *Gate) Capabilities() pipeline.PluginCapabilities {
	return pipeline.PluginCapabilities{
		// The key the gate asks by is the stamp lineage-telemetry writes into
		// the forwarded tracestate; earlier in the chain or no key at all.
		Requires: []string{"lineage-telemetry"},
		// No body capability, on purpose, as lineage: carriesNoData reads the raw body,
		// lineage requires a parser, and a parser has the listener buffer the body.
		// Declaring it would forbid the gate after inference-router.
		Description: "Holds unlisted egress until a verdict service answers; rejects a deny verdict.",
	}
}

func (g *Gate) Configure(raw json.RawMessage) error {
	cfg, err := decodeConfig(raw)
	if err != nil {
		return err
	}
	g.cfg = cfg
	g.denyOn = make(map[string]bool, len(cfg.DenyOn))
	for _, v := range cfg.DenyOn {
		g.denyOn[strings.ToLower(strings.TrimSpace(v))] = true
	}
	g.closeIdle()
	g.transport = newTransport()
	g.client = &http.Client{
		Transport: g.transport,
		// A redirect is an answer that is not a verdict (verdict_error), and
		// following one would carry the secret to wherever it points.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return nil
}

// Shutdown releases the verdict client's idle connections. A reload builds a
// new gate and stops the old pipeline after its drain window; without this
// the old gate's pooled connections stayed open until the idle timeout.
func (g *Gate) Shutdown(context.Context) error {
	g.closeIdle()
	return nil
}

func (g *Gate) closeIdle() {
	if g.transport != nil {
		g.transport.CloseIdleConnections()
	}
}

// newTransport is the stock transport with a pool sized for concurrent waits
// and no proxy: the sidecar's own call must never go back through a proxy,
// itself included.
func newTransport() *http.Transport {
	t := &http.Transport{MaxIdleConnsPerHost: maxIdlePerHost}
	if dt, ok := http.DefaultTransport.(*http.Transport); ok {
		t = dt.Clone()
		t.MaxIdleConnsPerHost = maxIdlePerHost
	}
	t.Proxy = nil
	return t
}

// verdict is the verdict service's answer. State is "decided" once a record
// for the exchange exists, "pending" when wait_ms passed without one, and
// "unjudged" when a record exists but the request body was not read whole, so
// Reason says why and Verdict covers only what was read. Rules, Labels and
// RedactedPayload stay raw: their shape is read apart, so a bad one cannot turn a
// judged block into an error.
type verdict struct {
	State           string          `json:"state"`
	Verdict         string          `json:"verdict"`
	Reason          string          `json:"reason"`
	Version         int             `json:"version"`
	Rules           json.RawMessage `json:"rules"`
	Labels          json.RawMessage `json:"labels"`
	RedactedPayload json.RawMessage `json:"redacted_payload"`
}

func (g *Gate) OnRequest(ctx context.Context, pctx *pipeline.Context) pipeline.Action {
	if pctx.Direction != pipeline.Outbound {
		pctx.Skip("inbound")
		return pipeline.Action{Type: pipeline.Continue}
	}
	if g.passes(pctx.Host) {
		pctx.Skip("pass_host")
		return pipeline.Action{Type: pipeline.Continue}
	}
	// A tunnel is never judged (package doc): if tls-bridge decrypts it, each
	// request in it comes through here again and is judged; if not, there is
	// nothing to ask a verdict about. Recorded, never refused. Only a request the
	// listener re-originates is redirectable, so a CONNECT that is redirectable
	// was sent inside a decrypted tunnel, and it carries a body like any other.
	if pctx.Method == http.MethodConnect && !pctx.Redirectable() {
		pctx.Record(pipeline.Invocation{Action: pipeline.ActionAllow, Reason: "not_inspected", Details: map[string]string{"kind": "tunnel"}})
		return pipeline.Action{Type: pipeline.Continue}
	}
	if kind, ok := carriesNoData(pctx.Method, pctx.Path, pctx.Body); ok {
		pctx.Record(pipeline.Invocation{Action: pipeline.ActionAllow, Reason: "no_data", Details: map[string]string{"kind": kind}})
		return pipeline.Action{Type: pipeline.Continue}
	}
	// The stamp names THIS exchange only when lineage-telemetry wrote it in
	// this same pass. When lineage skipped the exchange (not ready yet, a
	// bypass_paths or bypass_hosts match) the header still carries what the
	// app propagated — in a mesh, the stamp of the inbound exchange that
	// caused this call — and asking by it would judge the wrong exchange.
	// Lineage's own record of the pass is the one fact that says it wrote.
	rec, stamped := lineageStampThisPass(pctx)
	if !stamped {
		return g.fault(pctx, "no_lineage_stamp", "", 0, nil)
	}
	traceID, exchangeID, ok := exchangeKey(ctx, pctx.Headers)
	if !ok {
		return g.fault(pctx, "no_exchange_key", "", 0, nil)
	}

	row := g.failRowFor(rec.Details["self_id"], pctx.Host)
	start := time.Now()
	v, reason, extra := g.ask(ctx, traceID, exchangeID, row.waitMS)
	waited := time.Since(start)
	if reason != "" {
		if reason == "verdict_error" && ctx.Err() != nil {
			return pipeline.Deny("pipeline.cancelled", "request cancelled while waiting for a verdict")
		}
		if slowOrDead(reason, v, extra) {
			for _, mark := range []string{"body_cut", "body_not_captured"} {
				if rec.Details[mark] == "true" {
					return g.markedBody(pctx, mark, reason, exchangeID, waited, extra)
				}
			}
			return g.fallback(pctx, row, reason, exchangeID, waited, extra)
		}
		return g.fault(pctx, reason, exchangeID, waited, extra)
	}

	// The service's value as it came, compared as deny_on is decoded: trimmed
	// and case-folded, so " Block " is a block and never an allow.
	name := strings.ToLower(strings.TrimSpace(v.Verdict))
	waitedMS := waited.Milliseconds()
	details := map[string]string{
		"verdict":     name,
		"exchange_id": exchangeID,
		"version":     strconv.Itoa(v.Version),
		"waited_ms":   strconv.FormatInt(waitedMS, 10),
	}
	refusal := map[string]any{"state": v.State, "verdict": name, "exchange_id": exchangeID, "waited_ms": waitedMS}
	labels := readCaught(v, details, refusal)
	note := ""
	if v.State == "unjudged" {
		refusal["reason"] = v.Reason
		note = " Only part of it could be judged."
	}
	if g.denyOn[name] {
		marked := readRedactedPayload(v, details, refusal)
		pctx.Record(pipeline.Invocation{Action: pipeline.ActionDeny, Reason: "verdict_" + name, Details: details})
		return refuse(pctx, "policy.content-blocked", http.StatusForbidden, refusalMessage(pctx.Host, note, labels, marked), refusal)
	}
	// A deny on what was read is a deny; anything else says nothing about the
	// part of the body nobody read, so nothing was judged.
	if v.State == "unjudged" {
		details["unread"] = v.Reason
		if v.Reason == bodyNotCaptured && rec.Details["capture_io"] == "false" {
			g.warnUnread.Do(func() {
				slog.Warn("sentry-gate: lineage-telemetry has capture_io off, so request bodies leave unread; " +
					"set capture_io to have them judged")
			})
			pctx.Record(pipeline.Invocation{Action: pipeline.ActionAllow, Reason: "unread_capture_off", Details: details})
			return pipeline.Action{Type: pipeline.Continue}
		}
		pctx.Record(pipeline.Invocation{Action: pipeline.ActionDeny, Reason: "verdict_unjudged", Details: details})
		return refuse(pctx, "policy.verdict-unavailable", http.StatusServiceUnavailable, refusalMessage(pctx.Host, note, labels, ""), refusal)
	}
	pctx.Record(pipeline.Invocation{Action: pipeline.ActionAllow, Reason: "verdict_" + name, Details: details})
	return pipeline.Action{Type: pipeline.Continue}
}

func (g *Gate) OnResponse(context.Context, *pipeline.Context) pipeline.Action {
	return pipeline.Action{Type: pipeline.Continue}
}

// carriesNoData reports whether a request can carry no data, and names it: a GET of
// an agent card with no body, or a POST of an MCP handshake message whose raw body
// holds its own name, a small id and, for initialize, the client's short name and
// version, and nothing else. It reads the raw body rather
// than mcp-parser's result, because a parser's result does not show what it left out.
func carriesNoData(method, path string, body []byte) (string, bool) {
	switch method {
	case http.MethodGet:
		if len(body) == 0 && (path == "/.well-known/agent-card.json" || path == "/.well-known/agent.json") {
			return "agent_card", true
		}
	case http.MethodPost:
		return noDataRPC(body)
	}
	return "", false
}

func noDataRPC(body []byte) (string, bool) {
	if len(body) == 0 || len(body) > noDataBodyMax {
		return "", false
	}
	fields, ok := exactFields(body)
	if !ok {
		return "", false
	}
	method := string(fields["method"])
	switch method {
	case `"notifications/initialized"`, `"ping"`, `"tools/list"`:
		if p, has := fields["params"]; has && string(p) != `{}` && string(p) != `null` {
			return "", false
		}
	case `"initialize"`:
		if !isClientHello(fields["params"]) {
			return "", false
		}
	default:
		return "", false
	}
	if string(fields["jsonrpc"]) != `"2.0"` {
		return "", false
	}
	if id, has := fields["id"]; has && !isSmallCount(id) {
		return "", false
	}
	for name := range fields {
		switch name {
		case "jsonrpc", "id", "method", "params":
		default:
			return "", false
		}
	}
	return strings.Trim(method, `"`), true
}

// isClientHello reports whether raw params are initialize's and nothing more: a
// date-shaped protocolVersion, no capabilities, and a short client name and version.
func isClientHello(raw []byte) bool {
	params, ok := exactFields(raw)
	if !ok || len(params) != 3 || !protocolVersion.Match(params["protocolVersion"]) || string(params["capabilities"]) != `{}` {
		return false
	}
	client, ok := exactFields(params["clientInfo"])
	return ok && len(client) == 2 && clientName.Match(client["name"]) && clientVersion.Match(client["version"])
}

// exactFields decodes a JSON object whose values stay raw and compact. It refuses a
// field given twice, which decodes as its last value and may be read as its first
// elsewhere: the object must hold exactly the fields decoded.
func exactFields(raw []byte) (map[string]json.RawMessage, bool) {
	var compact bytes.Buffer
	if json.Compact(&compact, raw) != nil {
		return nil, false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(compact.Bytes(), &fields) != nil || fields == nil {
		return nil, false
	}
	decoded, err := json.Marshal(fields)
	return fields, err == nil && compact.Len() == len(decoded)
}

// isSmallCount reports whether a raw JSON value is a plain number of at most
// noDataIDDigits digits.
func isSmallCount(raw []byte) bool {
	if len(raw) == 0 || len(raw) > noDataIDDigits {
		return false
	}
	for _, c := range raw {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// tlsSetupFault says the TLS setup failed: a certificate the gate does not trust, a
// handshake alert from either side (the service wants a client certificate, or no
// version or cipher is shared), or a plain-HTTP answer on an https URL. A remote
// alert reaches the gate only as a "remote error" net.OpError.
func tlsSetupFault(err error) bool {
	var badCert *tls.CertificateVerificationError
	var alert tls.AlertError
	var header tls.RecordHeaderError
	var op *net.OpError
	return errors.As(err, &badCert) || errors.As(err, &alert) || errors.As(err, &header) ||
		errors.Is(err, http.ErrSchemeMismatch) || (errors.As(err, &op) && op.Op == "remote error")
}

// slowOrDead says the service was slow or dead, so the fallback setting decides: a
// pending answer, a busy one, a 5xx, a decided answer naming no verdict, or a call
// that got no answer. Any other status below 500, an answer that is not a verdict, a
// TLS setup that failed and an unjudged answer are faults.
func slowOrDead(reason string, v verdict, extra map[string]string) bool {
	status, _ := strconv.Atoi(extra["status"])
	return reason == "verdict_pending" || reason == "verdict_busy" ||
		(reason == "verdict_empty" && v.State == "decided") ||
		(reason == "verdict_error" && (extra["error_kind"] == "transport" || status >= 500))
}

// fault refuses a request the gate got no verdict for because something is set up or
// answering wrong, whatever the fallback. A 503 rather than a 403: nothing was judged.
func (g *Gate) fault(pctx *pipeline.Context, reason, exchangeID string, waited time.Duration, extra map[string]string) pipeline.Action {
	details, refusal := noVerdict(reason, exchangeID, waited, extra)
	pctx.Record(pipeline.Invocation{Action: pipeline.ActionDeny, Reason: reason, Details: details})
	return refuse(pctx, "policy.verdict-unavailable", http.StatusServiceUnavailable,
		refusalMessage(pctx.Host, " No verdict was given, so nothing was judged and nothing is flagged.", nil, ""), refusal)
}

// fallback applies the fallback setting to a request a slow or dead service gave no
// verdict for, the row's or the default, recorded as the setting's outcome with the
// cause: allow delivers it unjudged, deny refuses it with a 503.
func (g *Gate) fallback(pctx *pipeline.Context, row failRow, cause, exchangeID string, waited time.Duration, extra map[string]string) pipeline.Action {
	details, refusal := noVerdict(cause, exchangeID, waited, extra)
	details["no_verdict"] = cause
	if row.destination != "" {
		details["fail_mode_destination"], refusal["fail_mode_destination"] = row.destination, row.destination
	}
	if row.source != "" {
		details["fail_mode_source"], refusal["fail_mode_source"] = row.source, row.source
	}
	if row.fallback == "allow" {
		pctx.Record(pipeline.Invocation{Action: pipeline.ActionAllow, Reason: "fallback_allow", Details: details})
		return pipeline.Action{Type: pipeline.Continue}
	}
	pctx.Record(pipeline.Invocation{Action: pipeline.ActionDeny, Reason: "fallback_deny", Details: details})
	refusal["fallback"] = "deny"
	return refuse(pctx, "policy.verdict-unavailable", http.StatusServiceUnavailable,
		refusalMessage(pctx.Host, " No verdict arrived, so nothing was judged and nothing is flagged.", nil, ""), refusal)
}

// markedBody refuses, whatever the fallback, a request a slow or dead service gave no
// verdict for whose body lineage marked as cut (body_cut) or not captured
// (body_not_captured): the verdict would have said unjudged. Recorded under its cause.
func (g *Gate) markedBody(pctx *pipeline.Context, mark, cause, exchangeID string, waited time.Duration, extra map[string]string) pipeline.Action {
	details, refusal := noVerdict(cause, exchangeID, waited, extra)
	details[mark], refusal[mark] = "true", true
	pctx.Record(pipeline.Invocation{Action: pipeline.ActionDeny, Reason: cause, Details: details})
	return refuse(pctx, "policy.verdict-unavailable", http.StatusServiceUnavailable,
		refusalMessage(pctx.Host, " No verdict arrived, and the request body could not be judged in full, so nothing is flagged.", nil, ""), refusal)
}

// noVerdict is the record's details and the refusal's for a request with no verdict.
func noVerdict(reason, exchangeID string, waited time.Duration, extra map[string]string) (map[string]string, map[string]any) {
	details := map[string]string{"waited_ms": strconv.FormatInt(waited.Milliseconds(), 10)}
	for k, v := range extra {
		details[k] = v
	}
	refusal := map[string]any{"reason": reason, "waited_ms": waited.Milliseconds()}
	if exchangeID != "" {
		details["exchange_id"] = exchangeID
		refusal["exchange_id"] = exchangeID
	}
	return details, refusal
}

// refuse renders a refusal in the reply the caller's client hands on. A stock MCP
// client raises on a JSON-RPC error, and a stock A2A client raises on a status with the
// body unread, so in either the refusal would end the turn with nobody having read it.
func refuse(pctx *pipeline.Context, code string, status int, message string, details map[string]any) pipeline.Action {
	action := pipeline.DenyWithDetails(code, message, details)
	action.Violation.Status = status
	facts := map[string]any{"error": code, "plugin": pluginName, "details": details}
	if m := pctx.Extensions.MCP; m != nil && m.Method == "tools/call" && m.RPCID != nil {
		action.Violation.RPCResult = map[string]any{
			"isError":           true,
			"content":           []map[string]any{{"type": "text", "text": message}},
			"structuredContent": facts,
		}
		return action
	}
	if a := pctx.Extensions.A2A; a != nil && a.RPCID != nil && (a.Method == "message/send" || a.Method == "message/stream") {
		body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": a.RPCID, "result": map[string]any{
			"kind":      "message",
			"messageId": refusalMessageID(pctx, details),
			"role":      "agent",
			"parts":     []map[string]any{{"kind": "text", "text": message}},
			"metadata":  map[string]any{pluginName: facts},
		}})
		if err != nil {
			return action
		}
		action.Violation.Status = http.StatusOK
		action.Violation.Body, action.Violation.BodyType = body, "application/json"
		if a.Method == "message/stream" {
			action.Violation.Body, action.Violation.BodyType = []byte("data: "+string(body)+"\n\n"), "text/event-stream"
		}
	}
	return action
}

// refusalMessageID names one A2A refusal: a client that keys messages by id must
// see two refusals in one conversation as two messages. The exchange id is the
// gate's own key for the request; a refusal given before the gate had one (no
// lineage stamp, no key) takes the proxy's request id, unique per request.
func refusalMessageID(pctx *pipeline.Context, details map[string]any) string {
	if ex, _ := details["exchange_id"].(string); ex != "" {
		return "sentry-gate-refusal-" + ex
	}
	return "sentry-gate-refusal-" + pctx.RequestID()
}

// refusalMessage is the one text a refusal gives its reader. Marked text with nothing
// flagged says nothing, so it is shown only beside labels.
func refusalMessage(host, note string, labels []string, marked string) string {
	lines := []string{fmt.Sprintf(refusedOpening, hostOnly(host)) + note}
	switch {
	case len(labels) > 0 && marked != "":
		lines = append(lines, "Flagged parts are marked [category]:", marked, sendWithoutMarked)
	case len(labels) > 0:
		lines = append(lines, "Flagged: "+strings.Join(labels, ", ")+".")
	}
	return strings.Join(lines, "\n")
}

// readCaught puts the answer's rules and labels in the refusal, always as lists, and
// in the record, and returns the labels. A value that is not a list of strings counts
// as none and is noted in the record.
func readCaught(v verdict, details map[string]string, refusal map[string]any) (labels []string) {
	for _, field := range []struct {
		name string
		raw  json.RawMessage
	}{{"rules", v.Rules}, {"labels", v.Labels}} {
		var list []string
		if len(field.raw) > 0 && json.Unmarshal(field.raw, &list) != nil {
			list = nil
			details[field.name+"_error"] = "not a list of strings"
		}
		if list == nil {
			list = []string{}
		}
		refusal[field.name] = list
		if len(list) > 0 {
			details[field.name] = strings.Join(list, ",")
		}
		if field.name == "labels" {
			labels = list
		}
	}
	return labels
}

// readRedactedPayload puts the answer's redacted payload in the refusal and returns it.
// The record does not keep it: the service can render it again from what DG holds. A
// value that is not a string is dropped and noted in the record.
func readRedactedPayload(v verdict, details map[string]string, refusal map[string]any) string {
	if len(v.RedactedPayload) == 0 {
		return ""
	}
	var text *string
	if json.Unmarshal(v.RedactedPayload, &text) != nil || text == nil {
		details["redacted_payload_error"] = "not a string"
		return ""
	}
	refusal["redacted_payload"] = *text
	return *text
}

// ask fetches the verdict for one exchange and reads the answer by the
// interface the verdict service serves. A decided answer naming a verdict
// returns reason ""; every other answer returns the reason the gate records
// and what the service or the transport said. The secret travels in a header
// only, so no detail can carry it.
//
// A read with no body — the key is the path — so a plain GET, safe and
// idempotent, which the gate may repeat. The call may take waitMS + verdictGrace.
func (g *Gate) ask(ctx context.Context, traceID, exchangeID string, waitMS int) (v verdict, reason string, extra map[string]string) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(waitMS)*time.Millisecond+verdictGrace)
	defer cancel()
	u := fmt.Sprintf("%s/verdicts/%s/%s?wait_ms=%d", g.cfg.VerdictURL, traceID, exchangeID, waitMS)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return verdict{}, "verdict_error", map[string]string{"error": err.Error()}
	}
	if g.cfg.VerdictSecret != "" {
		req.Header.Set("Authorization", "Bearer "+g.cfg.VerdictSecret)
	}
	// error_kind tells a call that got no answer (transport) from an answer that is
	// not a verdict (answer) and a TLS setup that failed (tls), a fault that never
	// clears.
	resp, err := g.client.Do(req)
	if err != nil {
		if tlsSetupFault(err) {
			return verdict{}, "verdict_error", map[string]string{"error": err.Error(), "error_kind": "tls"}
		}
		return verdict{}, "verdict_error", map[string]string{"error": err.Error(), "error_kind": "transport"}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return verdict{}, "verdict_error", map[string]string{"error": err.Error(), "error_kind": "transport"}
	}
	if resp.StatusCode != http.StatusOK {
		return verdict{}, statusReason(resp.StatusCode, body), statusDetails(resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return verdict{}, "verdict_error", map[string]string{"error": "verdict body: " + err.Error(), "error_kind": "answer"}
	}
	switch {
	case v.State == "pending":
		return v, "verdict_pending", nil
	case v.State != "decided" && v.State != "unjudged":
		return verdict{}, "verdict_error", map[string]string{"error": fmt.Sprintf("verdict state %.32q", v.State), "error_kind": "answer"}
	case strings.TrimSpace(v.Verdict) == "":
		// A record with no verdict is not an allow: nothing was judged.
		return v, "verdict_empty", nil
	}
	return v, "", nil
}

// serviceError is the verdict service's {"error": "..."} field, "" when the
// body has none.
func serviceError(body []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) != nil {
		return ""
	}
	return e.Error
}

// statusReason names a non-200 answer. 401 and the 503 the service marks
// verdict_busy (its waiter cap is full) are facts of their own; any other
// status is verdict_error.
func statusReason(status int, body []byte) string {
	switch {
	case status == http.StatusUnauthorized:
		return "verdict_unauthorized"
	case status == http.StatusServiceUnavailable && serviceError(body) == "verdict_busy":
		return "verdict_busy"
	}
	return "verdict_error"
}

func statusDetails(status int, body []byte) map[string]string {
	d := map[string]string{"status": strconv.Itoa(status)}
	if e := serviceError(body); e != "" {
		d["error"] = fmt.Sprintf("%.128s", e)
	}
	return d
}

func (g *Gate) passes(host string) bool {
	h := strings.ToLower(hostOnly(host))
	if h == "" {
		return false
	}
	if g.cfg.PassSingleLabel && isShortName(h) {
		return true
	}
	for _, pattern := range g.cfg.PassHosts {
		if ok, _ := path.Match(pattern, h); ok {
			return true
		}
	}
	return false
}

// isShortName reports whether a lowercased host is a cluster short name: one
// plain DNS label. The test is what the label is made of, not the absence of a
// dot: the transport maps a non-ASCII dot (U+3002) to a dot and dials the result,
// and a resolver may read 134744072 or 0x08080808 as an address. An IPv6 literal
// has colons.
func isShortName(h string) bool {
	if h == "" || h[0] == '-' || h[len(h)-1] == '-' {
		return false
	}
	numeric, hexadecimal := true, strings.HasPrefix(h, "0x")
	for i := 0; i < len(h); i++ {
		c := h[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'z':
			numeric = false
			if c > 'f' && i != 1 {
				hexadecimal = false
			}
		case c == '-':
			numeric, hexadecimal = false, false
		default:
			return false
		}
	}
	return !numeric && !hexadecimal
}

// exchangeKey reads the exchange's key off the forwarded headers: the trace id
// of a valid traceparent and the lineage stamp in its tracestate.
func exchangeKey(ctx context.Context, h http.Header) (traceID, exchangeID string, ok bool) {
	sc := trace.SpanContextFromContext(propagation.TraceContext{}.Extract(ctx, propagation.HeaderCarrier(h)))
	if !sc.IsValid() {
		return "", "", false
	}
	sid, err := trace.SpanIDFromHex(sc.TraceState().Get(stampKey))
	if err != nil || !sid.IsValid() {
		return "", "", false
	}
	return sc.TraceID().String(), sid.String(), true
}

// lineageStampThisPass returns lineage-telemetry's record of this request pass,
// and whether it says lineage rewrote the forwarded tracestate: action modify,
// reason stamped_tracestate. A skip, an observe (pure-observer config, a refused
// stamp) or no record at all means the header's stamp is not this exchange's.
func lineageStampThisPass(pctx *pipeline.Context) (pipeline.Invocation, bool) {
	inv := pctx.Extensions.Invocations
	if inv == nil {
		return pipeline.Invocation{}, false
	}
	for i := len(inv.Outbound) - 1; i >= 0; i-- {
		rec := inv.Outbound[i]
		if rec.Plugin != "lineage-telemetry" || rec.Phase != pipeline.InvocationPhaseRequest {
			continue
		}
		return rec, rec.Action == pipeline.ActionModify && rec.Reason == "stamped_tracestate"
	}
	return pipeline.Invocation{}, false
}

// hostOnly is the host without its port, and an IPv6 literal without its
// brackets whether or not a port follows ("[::1]" and "[::1]:80" are "::1").
func hostOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	if len(host) > 1 && host[0] == '[' && host[len(host)-1] == ']' {
		return host[1 : len(host)-1]
	}
	return host
}

var (
	_ pipeline.Plugin         = (*Gate)(nil)
	_ pipeline.Configurable   = (*Gate)(nil)
	_ pipeline.SchemaProvider = (*Gate)(nil)
	_ pipeline.Shutdowner     = (*Gate)(nil)
)

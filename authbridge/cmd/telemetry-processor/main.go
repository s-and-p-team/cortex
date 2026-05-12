package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	ext_procv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	otelcodes "go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.30.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var otelTracer trace.Tracer
var otelEnabled bool
var agentServiceName string
var localPodIP string

// inboundEntry holds the trace context and conversation ID of an active inbound span.
// sessionID is written once after request body parsing (before the agent makes any outbound
// calls, guaranteed by Envoy's BUFFERED request body mode) and read by outbound streams.
type inboundEntry struct {
	ctx         context.Context
	sessionID   string
	principalID string // original authorizing principal (from JWT sub), propagated immutably
	startTime   time.Time // for TTL eviction and recency ordering
}

// pendingInbounds holds all currently in-flight inbound requests keyed by a sidecar-generated
// UUID. An entry lives from handleInbound until the inbound response stream ends (or TTL).
// For OTel-instrumented agents the traceInbound map takes precedence (see handleOutbound).
// For non-OTel agents, pickPendingInbound selects the best candidate from this set, which is
// deterministic when exactly one request is in-flight and heuristic (most-recent) otherwise.
const pendingInboundTTL = 5 * time.Minute

var (
	activeInboundMu sync.Mutex
	pendingInbounds = make(map[string]*inboundEntry)          // keyed by sidecar UUID
	traceInbound    = make(map[trace.TraceID]*inboundEntry)   // OTel path: keyed by trace-id
)

// pickPendingInbound returns the best candidate inbound entry for a non-OTel outbound call.
// Must be called with activeInboundMu held.
// Returns the single entry if unambiguous, the most-recently-started entry if concurrent,
// or nil if no in-flight inbound exists.
func pickPendingInbound() *inboundEntry {
	switch len(pendingInbounds) {
	case 0:
		return nil
	case 1:
		for _, e := range pendingInbounds {
			return e
		}
	}
	var best *inboundEntry
	for _, e := range pendingInbounds {
		if best == nil || e.startTime.After(best.startTime) {
			best = e
		}
	}
	return best
}

// startPendingInboundTTL launches a background goroutine that evicts zombie entries
// (requests that never completed, e.g. due to agent crash or timeout).
func startPendingInboundTTL() {
	go func() {
		ticker := time.NewTicker(pendingInboundTTL)
		defer ticker.Stop()
		for range ticker.C {
			cutoff := time.Now().Add(-pendingInboundTTL)
			activeInboundMu.Lock()
			for id, e := range pendingInbounds {
				if e.startTime.Before(cutoff) {
					delete(pendingInbounds, id)
					log.Printf("[OTEL] Evicted zombie pending inbound %s (age > %v)", id, pendingInboundTTL)
				}
			}
			activeInboundMu.Unlock()
		}
	}()
}

const maxResponseBodyBytes = 1 * 1024 * 1024

// filteringExporter wraps an sdktrace.SpanExporter and drops spans that carry
// the telemetry.lifecycle=true attribute. These are MCP lifecycle calls
// (initialize, notifications/*, etc.) that fire at agent startup before any
// inbound request is in-flight and would otherwise appear as orphan root spans.
type filteringExporter struct {
	inner sdktrace.SpanExporter
}

func (f *filteringExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	filtered := spans[:0]
	for _, s := range spans {
		drop := false
		for _, a := range s.Attributes() {
			if a.Key == "telemetry.lifecycle" && a.Value.AsBool() {
				drop = true
				break
			}
		}
		if !drop {
			filtered = append(filtered, s)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return f.inner.ExportSpans(ctx, filtered)
}

func (f *filteringExporter) Shutdown(ctx context.Context) error {
	return f.inner.Shutdown(ctx)
}

func initOTEL(endpoint string) (func(), error) {
	ctx := context.Background()

	hostPort := strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")

	otlpExp, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint(hostPort),
		otlptracehttp.WithInsecure(),
	)
	if err != nil {
		return nil, fmt.Errorf("create OTLP HTTP exporter: %w", err)
	}
	exp := &filteringExporter{inner: otlpExp}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName("otel-sidecar"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("create OTEL resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	otelTracer = tp.Tracer("otel-sidecar")

	shutdown := func() {
		if err := tp.Shutdown(context.Background()); err != nil {
			log.Printf("[OTEL] Shutdown error: %v", err)
		}
	}
	return shutdown, nil
}

func initLocalPodIP() {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				localPodIP = ipnet.IP.String()
				return
			}
		}
	}
}

// shortServiceName extracts the Kubernetes short service name from an authority header.
// For k8s FQDNs like "svc.namespace.svc.cluster.local:port" it returns "svc".
// For other hostnames (e.g. "host.docker.internal") it returns the host without port.
func shortServiceName(authority string) string {
	host := authority
	if h, _, err := net.SplitHostPort(authority); err == nil {
		host = h
	}
	if net.ParseIP(host) != nil {
		return host
	}
	if strings.Contains(host, ".svc.") {
		if idx := strings.IndexByte(host, '.'); idx > 0 {
			return host[:idx]
		}
	}
	return host
}

// isMCPNonToolMethod returns true for MCP JSON-RPC methods that are not tool
// invocations. These are session lifecycle and discovery calls (initialize,
// list_tools, ping, notifications/*) that should not produce telemetry spans.
func isMCPNonToolMethod(method string) bool {
	switch method {
	case "initialize", "tools/list", "resources/list", "prompts/list",
		"ping", "roots/list", "sampling/createMessage":
		return true
	}
	return strings.HasPrefix(method, "notifications/")
}

// llmPathHints maps well-known LLM inference paths to a provider hint.
// Paths that belong to a single provider return that provider name;
// OpenAI-compatible paths (shared by many providers) return "".
var llmPathHints = map[string]string{
	"/v1/chat/completions": "",         // OpenAI-compatible: OpenAI, vLLM, LiteLLM, Ollama, etc.
	"/v1/completions":      "",         // OpenAI legacy
	"/v1/embeddings":       "",         // OpenAI-compatible embeddings
	"/v1/messages":         "anthropic", // Anthropic-only path
	"/api/chat":            "ollama",   // Ollama native
	"/api/generate":        "ollama",   // Ollama native
}

// llmPathSystem returns (isLLM, providerHint) for a request path.
// providerHint is non-empty only for paths that uniquely identify a provider.
func llmPathSystem(path string) (bool, string) {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	hint, ok := llmPathHints[path]
	return ok, hint
}

// llmRegistryEntry maps a hostname pattern or model name pattern to an LLM provider name.
// Hostname entries use Suffix or Contains; model fallback entries use ModelContains.
type llmRegistryEntry struct {
	Suffix        string `json:"suffix,omitempty"`
	Contains      string `json:"contains,omitempty"`
	ModelContains string `json:"model_contains,omitempty"`
	System        string `json:"system"`
}

var llmRegistry []llmRegistryEntry

// defaultLLMRegistry is the built-in fallback used when no external registry is configured.
// Entries are evaluated in order; the first match wins.
// Hostname entries: "suffix" or "contains" matched against the request :authority.
// Model fallback entries: "model_contains" matched against the model name in the request body.
var defaultLLMRegistry = []llmRegistryEntry{
	{Suffix: ".openai.com", System: "openai"},
	{Suffix: ".anthropic.com", System: "anthropic"},
	{Suffix: ".amazonaws.com", System: "bedrock"},
	{Suffix: ".googleapis.com", System: "google"},
	{Contains: "ollama", System: "ollama"},
	{Contains: "host.docker.internal", System: "ollama"}, // local Ollama on macOS/Kind
	{Contains: "localhost", System: "ollama"},            // local Ollama via localhost
	{ModelContains: ":", System: "ollama"},               // Ollama model tags (e.g. qwen2.5:3b)
}

func initLLMRegistry() {
	llmRegistry = defaultLLMRegistry
}

// llmSystem returns the provider name for an authority header by walking hostname entries.
func llmSystem(authority string) string {
	host := authority
	if h, _, err := net.SplitHostPort(authority); err == nil {
		host = h
	}
	for _, e := range llmRegistry {
		if e.Suffix != "" && strings.HasSuffix(host, e.Suffix) {
			return e.System
		}
		if e.Contains != "" && strings.Contains(host, e.Contains) {
			return e.System
		}
	}
	return ""
}

// llmSystemFromModel returns the provider name by matching a model name against registry entries.
// Only consulted when hostname and path did not resolve a provider.
func llmSystemFromModel(model string) string {
	for _, e := range llmRegistry {
		if e.ModelContains != "" && strings.Contains(model, e.ModelContains) {
			return e.System
		}
	}
	return ""
}

// extractLLMText parses OpenAI-compatible and Ollama NDJSON streaming responses.
func extractLLMText(data []byte) string {
	// Non-streaming: try single JSON object
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err == nil {
		// Ollama non-streaming: {"message":{"content":"..."}}
		if msg, ok := obj["message"].(map[string]interface{}); ok {
			if content, ok := msg["content"].(string); ok && content != "" {
				return content
			}
		}
		// OpenAI non-streaming: {"choices":[{"message":{"content":"..."}}]}
		if choices, ok := obj["choices"].([]interface{}); ok && len(choices) > 0 {
			if choice, ok := choices[0].(map[string]interface{}); ok {
				if msg, ok := choice["message"].(map[string]interface{}); ok {
					if content, ok := msg["content"].(string); ok && content != "" {
						return content
					}
				}
			}
		}
	}
	// Streaming: accumulate content across NDJSON lines or SSE data: lines
	var buf strings.Builder
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "data:") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		}
		if line == "" || line == "[DONE]" {
			continue
		}
		var chunk map[string]interface{}
		if err := json.Unmarshal([]byte(line), &chunk); err != nil {
			continue
		}
		// Ollama NDJSON delta: {"message":{"content":"..."}}
		if msg, ok := chunk["message"].(map[string]interface{}); ok {
			if content, ok := msg["content"].(string); ok {
				buf.WriteString(content)
			}
		}
		// OpenAI SSE delta: {"choices":[{"delta":{"content":"..."}}]}
		if choices, ok := chunk["choices"].([]interface{}); ok && len(choices) > 0 {
			if choice, ok := choices[0].(map[string]interface{}); ok {
				if delta, ok := choice["delta"].(map[string]interface{}); ok {
					if content, ok := delta["content"].(string); ok {
						buf.WriteString(content)
					}
				}
			}
		}
	}
	return buf.String()
}

func resolveAgentServiceName() string {
	if name := os.Getenv("TELEMETRY_SERVICE_NAME"); name != "" {
		return name
	}
	hostname := os.Getenv("HOSTNAME")
	if hostname == "" {
		return ""
	}
	parts := strings.Split(hostname, "-")
	if len(parts) <= 2 {
		return hostname
	}
	return strings.Join(parts[:len(parts)-2], "-")
}

type otelStreamState struct {
	span          trace.Span
	ctx           context.Context
	bodyBuf       bytes.Buffer
	isInbound     bool
	isLLM         bool
	isA2A         bool          // true for outbound A2A peer calls (/message/…)
	destName      string        // short destination service name (e.g. "travel-advisor")
	hasDestName   bool          // true when destination.name was resolved from path hint or registry
	hasSystemName bool          // true when gen_ai.system was resolved from path hint or registry
	inboundEntry  *inboundEntry // non-nil for inbound streams; shared pointer for session.id propagation
	pendingID     string        // key in pendingInbounds; used for cleanup on response-end or stream close
}

func truncateString(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	b := []byte(s[:maxBytes])
	for len(b) > 0 {
		r := b[len(b)-1]
		if r < 0x80 || r >= 0xC0 {
			break
		}
		b = b[:len(b)-1]
	}
	return string(b) + "…"
}

func jsonGet(obj map[string]interface{}, keys ...string) (interface{}, bool) {
	var cur interface{} = obj
	for _, k := range keys {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return nil, false
		}
		cur, ok = m[k]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// decodeJWTPayload base64-decodes the JWT payload section without signature verification.
// Used to extract enduser.id claims without requiring Keycloak configuration.
func decodeJWTPayload(tokenString string) map[string]interface{} {
	parts := strings.SplitN(tokenString, ".", 3)
	if len(parts) != 3 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil
	}
	return claims
}

func getHeaderValue(headers []*core.HeaderValue, key string) string {
	for _, header := range headers {
		if strings.EqualFold(header.Key, key) {
			return string(header.RawValue)
		}
	}
	return ""
}

type processor struct {
	v3.UnimplementedExternalProcessorServer
}

// headerCarrier adapts an Envoy HeaderValue slice to propagation.TextMapCarrier.
// Get reads from the existing headers; Set collects injected headers in the
// injected map for later use in HeaderMutation.SetHeaders.
type headerCarrier struct {
	headers  []*core.HeaderValue
	injected map[string]string
}

func (h *headerCarrier) Get(key string) string {
	return getHeaderValue(h.headers, strings.ToLower(key))
}
func (h *headerCarrier) Set(key, val string) { h.injected[strings.ToLower(key)] = val }
func (h *headerCarrier) Keys() []string      { return nil }

// handleInbound always passes the request through and starts an OTEL span for
// inbound A2A POST requests. JWT is decoded without validation for enduser.id.
func (p *processor) handleInbound(headers *core.HeaderMap) (*v3.ProcessingResponse, *otelStreamState) {
	// For non-telemetered requests (health checks, non-POST, etc.) override the base
	// BUFFERED/STREAMED body modes back to NONE so we don't waste ext_proc calls.
	passthrough := &v3.ProcessingResponse{
		Response: &v3.ProcessingResponse_RequestHeaders{
			RequestHeaders: &v3.HeadersResponse{},
		},
		ModeOverride: &ext_procv3.ProcessingMode{
			RequestBodyMode:    ext_procv3.ProcessingMode_NONE,
			ResponseBodyMode:   ext_procv3.ProcessingMode_NONE,
			ResponseHeaderMode: ext_procv3.ProcessingMode_SKIP,
		},
	}

	httpMethod := getHeaderValue(headers.Headers, ":method")
	requestPath := getHeaderValue(headers.Headers, ":path")

	if !otelEnabled || otelTracer == nil || httpMethod != "POST" || (requestPath != "/" && requestPath != "") {
		return passthrough, nil
	}

	var userID, sourceService, principalID string
	authHeader := getHeaderValue(headers.Headers, "authorization")
	if authHeader != "" {
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		tokenString = strings.TrimPrefix(tokenString, "bearer ")
		if claims := decodeJWTPayload(tokenString); claims != nil {
			if pu, ok := claims["preferred_username"].(string); ok && pu != "" {
				userID = pu
			} else if sub, ok := claims["sub"].(string); ok {
				userID = sub
			}
			if sub, ok := claims["sub"].(string); ok && sub != "" {
				principalID = sub
			}
			// Fall back to preferred_username when sub is absent (e.g., certain Keycloak clients)
			if principalID == "" && userID != "" {
				principalID = userID
			}
			if azp, ok := claims["azp"].(string); ok {
				sourceService = azp
			}
		}
	}
	// x-telemetry-caller is injected by the sending sidecar (see handleOutbound) and is
	// infrastructure-owned. Use it as source.name when JWT azp is not present.
	// Fall back to X-Kagenti-From, which the A2A client interceptor stamps on every
	// outbound message/send and message/sendSubscribe call. It is app-level (not
	// infrastructure-owned) but sufficient for telemetry when the sidecar header is absent.
	callerHeader := getHeaderValue(headers.Headers, "x-telemetry-caller")
	if callerHeader == "" {
		callerHeader = getHeaderValue(headers.Headers, "x-kagenti-from")
	}
	if callerHeader != "" && sourceService == "" {
		sourceService = callerHeader
	}
	// If an upstream sidecar already stamped x-principal-id, propagate it unchanged.
	// callerHeader presence indicates the request came from a peer sidecar (not a raw client),
	// making the incoming principal trustworthy for propagation purposes.
	if incomingPID := getHeaderValue(headers.Headers, "x-principal-id"); incomingPID != "" && callerHeader != "" {
		principalID = incomingPID
	}
	// x-caller-id is the trust-facing sender identity (see handleOutbound).
	// Fall back to x-telemetry-caller which carries the equivalent value.
	callerID := getHeaderValue(headers.Headers, "x-caller-id")
	if callerID == "" {
		callerID = callerHeader
	}

	// Extract traceparent + W3C baggage (upstream sidecar may have injected session.id).
	prop := propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{})
	carrier := &headerCarrier{headers: headers.Headers, injected: make(map[string]string)}
	parentCtx := prop.Extract(context.Background(), carrier)

	spanName := "telemetry.inbound"
	if agentServiceName != "" {
		spanName = "telemetry.inbound " + agentServiceName
	}
	spanCtx, span := otelTracer.Start(
		parentCtx,
		spanName,
		trace.WithSpanKind(trace.SpanKindServer),
	)

	attrs := []attribute.KeyValue{
		attribute.String("openinference.span.kind", "AGENT"),
		attribute.String("http.method", httpMethod),
		attribute.String("http.target", requestPath),
	}
	if userID != "" {
		attrs = append(attrs, attribute.String("enduser.id", userID))
	}
	if sourceService != "" {
		attrs = append(attrs, attribute.String("source.name", sourceService))
	}
	if agentServiceName != "" {
		attrs = append(attrs, attribute.String("destination.name", agentServiceName))
	}
	if authority := getHeaderValue(headers.Headers, ":authority"); authority != "" {
		attrs = append(attrs, attribute.String("destination.address", authority))
	}
	if src := getHeaderValue(headers.Headers, "x-telemetry-source-address"); src != "" {
		// Injected by the Lua filter from Envoy's downstream peer address (most accurate).
		attrs = append(attrs, attribute.String("source.address", src))
	} else if src := getHeaderValue(headers.Headers, "x-source-address"); src != "" {
		attrs = append(attrs, attribute.String("source.address", src))
	} else if xff := getHeaderValue(headers.Headers, "x-forwarded-for"); xff != "" {
		sourceAddr := strings.SplitN(xff, ",", 2)[0]
		attrs = append(attrs, attribute.String("source.address", strings.TrimSpace(sourceAddr)))
	}
	span.SetAttributes(attrs...)

	// Trust provenance attributes consumed by the lineage service.
	var trustAttrs []attribute.KeyValue
	if principalID != "" {
		trustAttrs = append(trustAttrs, attribute.String("trust.principal_id", principalID))
	}
	if callerID != "" {
		trustAttrs = append(trustAttrs, attribute.String("trust.caller_id", callerID))
	}
	if agentServiceName != "" {
		trustAttrs = append(trustAttrs, attribute.String("trust.target_id", agentServiceName))
	}
	if callerID == "" {
		trustAttrs = append(trustAttrs, attribute.String("trust.hop_kind", "principal_to_agent"))
	} else {
		trustAttrs = append(trustAttrs, attribute.String("trust.hop_kind", "agent_to_agent"))
	}
	if len(trustAttrs) > 0 {
		span.SetAttributes(trustAttrs...)
	}

	entry := &inboundEntry{ctx: spanCtx, principalID: principalID, startTime: time.Now()}
	// Upstream sidecar may have injected session.id via W3C Baggage; pick it up immediately
	// so outbound calls made before body parsing can already carry the session ID.
	if m := baggage.FromContext(parentCtx).Member("session.id"); m.Key() != "" {
		entry.sessionID = m.Value()
		span.SetAttributes(
			attribute.String("gen_ai.conversation.id", m.Value()),
			attribute.String("session.id", m.Value()),
		)
	}
	pendingID := uuid.New().String()
	traceID := span.SpanContext().TraceID()
	activeInboundMu.Lock()
	traceInbound[traceID] = entry
	pendingInbounds[pendingID] = entry
	activeInboundMu.Unlock()

	otelState := &otelStreamState{span: span, ctx: spanCtx, isInbound: true, inboundEntry: entry, pendingID: pendingID}
	log.Printf("[OTEL] Started span %s for user %q (pendingID=%s)", spanName, userID, pendingID)

	// Inject our traceparent into the inbound request so OTel-instrumented agents inherit
	// this trace-id. handleOutbound can then look up the inbound entry by trace-id, giving
	// correct session.id under concurrent requests without relying on timing.
	injectCarrier := &headerCarrier{headers: headers.Headers, injected: make(map[string]string)}
	propagation.TraceContext{}.Inject(spanCtx, injectCarrier)
	var injectHeaders []*core.HeaderValueOption
	for k, v := range injectCarrier.injected {
		injectHeaders = append(injectHeaders, &core.HeaderValueOption{
			Header: &core.HeaderValue{Key: k, RawValue: []byte(v)},
		})
	}
	// Stamp sidecar-owned trust headers. We always strip first (RemoveHeaders below) then
	// re-inject so that app-supplied values cannot be forwarded to downstream services.
	if principalID != "" {
		injectHeaders = append(injectHeaders, &core.HeaderValueOption{
			Header: &core.HeaderValue{Key: "x-principal-id", RawValue: []byte(principalID)},
		})
	}

	return &v3.ProcessingResponse{
		Response: &v3.ProcessingResponse_RequestHeaders{
			RequestHeaders: &v3.HeadersResponse{
				Response: &v3.CommonResponse{
					HeaderMutation: &v3.HeaderMutation{
						SetHeaders: injectHeaders,
						// Strip sidecar-to-sidecar headers before forwarding to the app.
						// x-principal-id is stripped then re-injected above (our value wins).
						RemoveHeaders: []string{"x-telemetry-caller", "x-principal-id", "x-caller-id"},
					},
				},
			},
		},
	}, otelState
}

// isObservabilityEndpoint returns true for hosts that are telemetry infrastructure
// (OTEL collectors, Prometheus, Jaeger, etc.) that should not be traced as agent calls.
func isObservabilityEndpoint(authority string) bool {
	host := authority
	if h, _, err := net.SplitHostPort(authority); err == nil {
		host = h
	}
	return strings.Contains(host, "otel-collector") ||
		strings.Contains(host, "jaeger") ||
		strings.Contains(host, "zipkin") ||
		strings.Contains(host, "prometheus")
}

func (p *processor) handleOutbound(headers *core.HeaderMap) (*v3.ProcessingResponse, *otelStreamState) {
	method := getHeaderValue(headers.Headers, ":method")
	authority := getHeaderValue(headers.Headers, ":authority")
	// Non-telemetered requests opt out of body processing to avoid buffering overhead.
	passthrough := &v3.ProcessingResponse{
		Response: &v3.ProcessingResponse_RequestHeaders{
			RequestHeaders: &v3.HeadersResponse{},
		},
		ModeOverride: &ext_procv3.ProcessingMode{
			RequestBodyMode:    ext_procv3.ProcessingMode_NONE,
			ResponseBodyMode:   ext_procv3.ProcessingMode_NONE,
			ResponseHeaderMode: ext_procv3.ProcessingMode_SKIP,
		},
	}
	if !otelEnabled || otelTracer == nil {
		return passthrough, nil
	}
	if method != "POST" {
		return passthrough, nil
	}
	// Skip span creation for telemetry infrastructure — these are not agent calls.
	if isObservabilityEndpoint(authority) {
		return passthrough, nil
	}

	// Prefer traceparent propagated by the agent (OTel-instrumented agents do this
	// automatically), which gives correct parenting under concurrent requests.
	// Fall back to the timing-based active inbound context for non-OTel agents.
	extractProp := propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{})
	extractCarrier := &headerCarrier{headers: headers.Headers, injected: make(map[string]string)}
	extractedCtx := extractProp.Extract(context.Background(), extractCarrier)

	var parentCtx context.Context
	var sessionID string
	var principalID string
	activeInboundMu.Lock()
	if sc := trace.SpanFromContext(extractedCtx).SpanContext(); sc.IsValid() {
		if e, ok := traceInbound[sc.TraceID()]; ok {
			// Agent's traceparent belongs to our trace — use the inbound span itself as
			// parent so outbound spans appear as direct children of telemetry.inbound,
			// matching the flat network-level view rather than nesting under SDK spans.
			parentCtx = e.ctx
			sessionID = e.sessionID
			principalID = e.principalID
		} else if e := pickPendingInbound(); e != nil {
			// Agent's traceparent is from a foreign trace (e.g. MLflow auto-instrumentation) →
			// re-parent to the best pending inbound (deterministic when unambiguous).
			parentCtx = e.ctx
			sessionID = e.sessionID
			principalID = e.principalID
		} else {
			parentCtx = extractedCtx
		}
	} else if e := pickPendingInbound(); e != nil {
		// Non-OTel agent: use pending inbound set — deterministic when exactly one request
		// is in-flight, heuristic (most-recent) under true concurrency.
		parentCtx = e.ctx
		sessionID = e.sessionID
		principalID = e.principalID
	}
	activeInboundMu.Unlock()
	// Baggage session.id from upstream sidecar (2nd+ agent in chain) takes highest precedence.
	if m := baggage.FromContext(extractedCtx).Member("session.id"); m.Key() != "" {
		sessionID = m.Value()
	}
	if parentCtx == nil {
		parentCtx = context.Background()
	}

	targetName := getHeaderValue(headers.Headers, ":authority")
	if targetName == "" {
		targetName = getHeaderValue(headers.Headers, "host")
	}
	requestPath := getHeaderValue(headers.Headers, ":path")
	llm, pathHint := llmPathSystem(requestPath)
	isA2A := !llm && strings.HasPrefix(requestPath, "/message/")
	destShortName := shortServiceName(targetName)
	spanName := "telemetry.outbound"
	if agentServiceName != "" {
		spanName = "telemetry.outbound " + agentServiceName
	}
	if isA2A && destShortName != "" {
		spanName = destShortName
	}
	spanCtx, span := otelTracer.Start(parentCtx, spanName, trace.WithSpanKind(trace.SpanKindClient))

	spanKind := "TOOL"
	if llm {
		spanKind = "LLM"
	} else if isA2A {
		spanKind = "AGENT"
	}
	attrs := []attribute.KeyValue{
		attribute.String("openinference.span.kind", spanKind),
		attribute.String("http.method", "POST"),
	}
	hasSystemName := false
	if llm {
		// Path hint takes precedence; registry provides fallback for ambiguous paths.
		sys := pathHint
		if sys == "" {
			sys = llmSystem(targetName)
		}
		if sys != "" {
			attrs = append(attrs, attribute.String("gen_ai.system", sys))
			hasSystemName = true
		}
	}
	hasDestName := false
	if targetName != "" {
		destName := shortServiceName(targetName)
		if llm && hasSystemName {
			sys := pathHint
			if sys == "" {
				sys = llmSystem(targetName)
			}
			destName = sys
			hasDestName = true
		}
		attrs = append(attrs, attribute.String("destination.name", destName))
		attrs = append(attrs, attribute.String("destination.address", targetName))
	}
	if agentServiceName != "" {
		attrs = append(attrs, attribute.String("source.name", agentServiceName))
	}
	if localPodIP != "" {
		attrs = append(attrs, attribute.String("source.address", localPodIP))
	}
	span.SetAttributes(attrs...)
	if sessionID != "" {
		span.SetAttributes(
			attribute.String("gen_ai.conversation.id", sessionID),
			attribute.String("session.id", sessionID),
		)
	}

	// Trust provenance attributes consumed by the lineage service.
	var trustHopKind string
	switch spanKind {
	case "LLM":
		trustHopKind = "agent_to_llm"
	case "TOOL":
		trustHopKind = "agent_to_tool"
	default:
		trustHopKind = "agent_to_agent"
	}
	var outboundTrustAttrs []attribute.KeyValue
	if principalID != "" {
		outboundTrustAttrs = append(outboundTrustAttrs, attribute.String("trust.principal_id", principalID))
	}
	if agentServiceName != "" {
		outboundTrustAttrs = append(outboundTrustAttrs, attribute.String("trust.caller_id", agentServiceName))
	}
	if destShortName != "" {
		outboundTrustAttrs = append(outboundTrustAttrs, attribute.String("trust.target_id", destShortName))
	}
	outboundTrustAttrs = append(outboundTrustAttrs, attribute.String("trust.hop_kind", trustHopKind))
	span.SetAttributes(outboundTrustAttrs...)

	var injectCtx context.Context = spanCtx
	if sessionID != "" {
		if m, err := baggage.NewMember("session.id", sessionID); err == nil {
			if bag, err := baggage.New(m); err == nil {
				injectCtx = baggage.ContextWithBaggage(spanCtx, bag)
			}
		}
	}
	prop := propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{})
	carrier := &headerCarrier{headers: headers.Headers, injected: make(map[string]string)}
	prop.Inject(injectCtx, carrier)

	var setHeaders []*core.HeaderValueOption
	for k, v := range carrier.injected {
		setHeaders = append(setHeaders, &core.HeaderValueOption{
			Header: &core.HeaderValue{Key: k, RawValue: []byte(v)},
		})
	}
	// Stamp the sender's identity on every outbound request. These headers are infrastructure-owned
	// (injected by the sidecar, not the app) and stripped by the receiving sidecar's inbound
	// handler before forwarding to the target app, so they cannot be forged by app code.
	if agentServiceName != "" {
		setHeaders = append(setHeaders, &core.HeaderValueOption{
			Header: &core.HeaderValue{Key: "x-telemetry-caller", RawValue: []byte(agentServiceName)},
		})
		setHeaders = append(setHeaders, &core.HeaderValueOption{
			Header: &core.HeaderValue{Key: "x-caller-id", RawValue: []byte(agentServiceName)},
		})
	}
	if principalID != "" {
		setHeaders = append(setHeaders, &core.HeaderValueOption{
			Header: &core.HeaderValue{Key: "x-principal-id", RawValue: []byte(principalID)},
		})
	}

	return &v3.ProcessingResponse{
		Response: &v3.ProcessingResponse_RequestHeaders{
			RequestHeaders: &v3.HeadersResponse{
				Response: &v3.CommonResponse{
					HeaderMutation: &v3.HeaderMutation{SetHeaders: setHeaders},
				},
			},
		},
	}, &otelStreamState{span: span, ctx: spanCtx, isLLM: llm, isA2A: isA2A, destName: destShortName, hasDestName: hasDestName, hasSystemName: hasSystemName}
}

func (p *processor) handleRequestBody(body *v3.HttpBody, state *otelStreamState) *v3.ProcessingResponse {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[OTEL] Recovered from panic in handleRequestBody: %v", r)
		}
	}()

	if body != nil && len(body.Body) > 0 {
		var rpc map[string]interface{}
		if err := json.Unmarshal(body.Body, &rpc); err != nil {
			log.Printf("[OTEL] Request body is not valid JSON: %v", err)
		} else if state.isLLM {
			if model, ok := rpc["model"].(string); ok {
				attrs := []attribute.KeyValue{
					attribute.String("llm.model_name", model),
					attribute.String("gen_ai.request.model", model),
				}
				if !state.hasSystemName {
					if sys := llmSystemFromModel(model); sys != "" {
						attrs = append(attrs, attribute.String("gen_ai.system", sys))
						if !state.hasDestName {
							attrs = append(attrs, attribute.String("destination.name", sys))
						}
					} else if !state.hasDestName {
						attrs = append(attrs, attribute.String("destination.name", model))
					}
				} else if !state.hasDestName {
					attrs = append(attrs, attribute.String("destination.name", model))
				}
				state.span.SetAttributes(attrs...)
			}
			if messages, ok := rpc["messages"].([]interface{}); ok {
				for i := len(messages) - 1; i >= 0; i-- {
					if msg, ok := messages[i].(map[string]interface{}); ok {
						if role, _ := msg["role"].(string); role == "user" {
							if content, ok := msg["content"].(string); ok && content != "" {
								state.span.SetAttributes(
									attribute.String("input.value", truncateString(content, 4096)),
									attribute.String("gen_ai.prompt", truncateString(content, 4096)),
								)
								log.Printf("[OTEL] Captured LLM input.value (%d chars)", len(content))
							}
							break
						}
					}
				}
			}
		} else {
			if method, ok := rpc["method"].(string); ok {
				if !state.isInbound {
					isA2AMethod := method == "message/stream" || method == "message/send"
					if isA2AMethod && !state.isA2A {
						// Body-time A2A detection: Python a2a SDK sends POST to base URL "/"
						// so the path-based isA2A check in handleOutbound never fires.
						state.isA2A = true
						state.span.SetAttributes(attribute.String("openinference.span.kind", "AGENT"))
						if state.destName != "" {
							state.span.SetName(state.destName)
						}
						log.Printf("[OTEL] A2A call detected (body): dest=%q", state.destName)
					} else if !state.isA2A {
						state.span.SetName(method)
						// MCP lifecycle methods (initialize, notifications/*, etc.) fire at
						// agent startup before any inbound is in-flight, making them orphan
						// root spans. Mark them so the filtering exporter can suppress them.
						if isMCPNonToolMethod(method) {
							state.span.SetAttributes(attribute.Bool("telemetry.lifecycle", true))
							log.Printf("[OTEL] Marked lifecycle span for suppression: %q", method)
						} else {
							log.Printf("[OTEL] Outbound action: %q", method)
						}
					}
				}
				state.span.SetAttributes(attribute.String("a2a.method", method))

				// For tools/call, extract tool name and arguments as input.value
				// and rename span to "tools/call: <toolname>" for Phoenix trace clarity.
				if method == "tools/call" && !state.isInbound {
					if params, ok := rpc["params"].(map[string]interface{}); ok {
						toolName, _ := params["name"].(string)
						if toolName != "" {
							state.span.SetName("tools/call: " + toolName)
							state.span.SetAttributes(attribute.String("tool.name", toolName))
						}
						inputMap := map[string]interface{}{}
						if toolName != "" {
							inputMap["tool"] = toolName
						}
						if args, ok := params["arguments"]; ok {
							inputMap["arguments"] = args
						}
						if len(inputMap) > 0 {
							if b, err := json.Marshal(inputMap); err == nil {
								state.span.SetAttributes(attribute.String("input.value", truncateString(string(b), 4096)))
								log.Printf("[OTEL] Captured tools/call input: tool=%q", toolName)
							}
						}
					}
				}
			}
			if state.isInbound {
				state.span.SetAttributes(attribute.String("gen_ai.operation.name", "invoke_agent"))
			}
			if msg, ok := jsonGet(rpc, "params", "message"); ok {
				if msgMap, ok := msg.(map[string]interface{}); ok {
					if ctxID, ok := msgMap["contextId"].(string); ok && ctxID != "" {
						state.span.SetAttributes(
							attribute.String("gen_ai.conversation.id", ctxID),
							attribute.String("session.id", ctxID),
						)
						if state.inboundEntry != nil {
							activeInboundMu.Lock()
							state.inboundEntry.sessionID = ctxID
							activeInboundMu.Unlock()
						}
					}
					if msgID, ok := msgMap["messageId"].(string); ok && msgID != "" {
						state.span.SetAttributes(attribute.String("a2a.message_id", msgID))
					}
					if parts, ok := msgMap["parts"].([]interface{}); ok && len(parts) > 0 {
						if part, ok := parts[0].(map[string]interface{}); ok {
							if text, ok := part["text"].(string); ok && text != "" {
								state.span.SetAttributes(
									attribute.String("input.value", truncateString(text, 4096)),
									attribute.String("gen_ai.prompt", truncateString(text, 4096)),
								)
								log.Printf("[OTEL] Captured input.value (%d chars)", len(text))
							}
						}
					}
				}
			}
		}
	}

	return &v3.ProcessingResponse{
		Response: &v3.ProcessingResponse_RequestBody{
			RequestBody: &v3.BodyResponse{
				Response: &v3.CommonResponse{},
			},
		},
	}
}

func extractTextAndContextFromA2AResponse(data []byte) (text, contextID string) {
	var rpc map[string]interface{}
	if err := json.Unmarshal(data, &rpc); err == nil {
		if t := extractArtifactText(rpc); t != "" {
			text = t
		}
		if result, ok := rpc["result"].(map[string]interface{}); ok {
			if cid, ok := result["contextId"].(string); ok {
				contextID = cid
			}
		}
		if text != "" {
			return
		}
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		var evt map[string]interface{}
		if err := json.Unmarshal([]byte(payload), &evt); err != nil {
			continue
		}
		if t := extractArtifactText(evt); t != "" {
			text = t
		}
		if contextID == "" {
			if result, ok := evt["result"].(map[string]interface{}); ok {
				if cid, ok := result["contextId"].(string); ok {
					contextID = cid
				}
			}
		}
	}
	return
}

func extractArtifactText(rpc map[string]interface{}) string {
	result, ok := rpc["result"].(map[string]interface{})
	if !ok {
		return ""
	}

	if artifacts, ok := result["artifacts"].([]interface{}); ok && len(artifacts) > 0 {
		return extractPartsText(artifacts)
	}

	if art, ok := result["artifact"].(map[string]interface{}); ok {
		if parts, ok := art["parts"].([]interface{}); ok {
			if text := extractTextFromParts(parts); text != "" {
				return text
			}
		}
	}

	if statusObj, ok := result["status"].(map[string]interface{}); ok {
		// Extract text from any terminal or interactive status that carries a message
		// (completed, input-required, failed, etc.) — not just input-required.
		if msg, ok := statusObj["message"].(map[string]interface{}); ok {
			if parts, ok := msg["parts"].([]interface{}); ok {
				if text := extractTextFromParts(parts); text != "" {
					return text
				}
			}
		}
	}

	// MCP tools/call response: result.content[].text
	if content, ok := result["content"].([]interface{}); ok && len(content) > 0 {
		if text := extractTextFromParts(content); text != "" {
			return text
		}
	}

	return ""
}

func extractPartsText(artifacts []interface{}) string {
	var buf strings.Builder
	for _, art := range artifacts {
		artMap, ok := art.(map[string]interface{})
		if !ok {
			continue
		}
		parts, ok := artMap["parts"].([]interface{})
		if !ok {
			continue
		}
		buf.WriteString(extractTextFromParts(parts))
	}
	return buf.String()
}

func extractTextFromParts(parts []interface{}) string {
	var buf strings.Builder
	for _, p := range parts {
		pMap, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		if text, ok := pMap["text"].(string); ok && text != "" {
			buf.WriteString(text)
		}
	}
	return buf.String()
}

func (p *processor) handleResponseBody(body *v3.HttpBody, state *otelStreamState) *v3.ProcessingResponse {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[OTEL] Recovered from panic in handleResponseBody: %v", r)
		}
	}()

	if body != nil && len(body.Body) > 0 {
		if state.bodyBuf.Len() < maxResponseBodyBytes {
			remaining := maxResponseBodyBytes - state.bodyBuf.Len()
			if len(body.Body) <= remaining {
				state.bodyBuf.Write(body.Body)
			} else {
				state.bodyBuf.Write(body.Body[:remaining])
				log.Printf("[OTEL] Response body truncated at %d bytes", maxResponseBodyBytes)
			}
		}
	}

	if body != nil && body.EndOfStream {
		if state.bodyBuf.Len() > 0 {
			if state.isLLM {
				if text := extractLLMText(state.bodyBuf.Bytes()); text != "" {
					truncated := truncateString(text, 4096)
					state.span.SetAttributes(
						attribute.String("output.value", truncated),
						attribute.String("gen_ai.completion", truncated),
					)
					log.Printf("[OTEL] Captured LLM output.value (%d chars)", len(text))
				}
			} else {
				outputText, contextID := extractTextAndContextFromA2AResponse(state.bodyBuf.Bytes())
				if outputText != "" {
					truncated := truncateString(outputText, 4096)
					state.span.SetAttributes(
						attribute.String("output.value", truncated),
						attribute.String("gen_ai.completion", truncated),
					)
					log.Printf("[OTEL] Captured output.value (%d chars)", len(outputText))
				}
				if contextID != "" {
					state.span.SetAttributes(
						attribute.String("gen_ai.conversation.id", contextID),
						attribute.String("session.id", contextID),
					)
				}
			}
		}
		state.span.SetStatus(otelcodes.Ok, "")
		state.span.End()
		log.Println("[OTEL] Span ended")
		if state.isInbound {
			activeInboundMu.Lock()
			delete(traceInbound, state.span.SpanContext().TraceID())
			if state.pendingID != "" {
				delete(pendingInbounds, state.pendingID)
			}
			activeInboundMu.Unlock()
		}
	}

	return &v3.ProcessingResponse{
		Response: &v3.ProcessingResponse_ResponseBody{
			ResponseBody: &v3.BodyResponse{
				Response: &v3.CommonResponse{},
			},
		},
	}
}

func (p *processor) Process(stream v3.ExternalProcessor_ProcessServer) error {
	log.Printf("[OTEL] Process() stream started")
	ctx := stream.Context()
	var otelState *otelStreamState

	defer func() {
		if otelState != nil {
			if otelState.span.IsRecording() {
				// Stream closed without EndOfStream (e.g. SSE response completed, client
				// disconnect, or timeout). Flush any buffered response body and mark OK —
				// reaching here means the request completed without an explicit error.
				if otelState.bodyBuf.Len() > 0 {
					if otelState.isLLM {
						if text := extractLLMText(otelState.bodyBuf.Bytes()); text != "" {
							truncated := truncateString(text, 4096)
							otelState.span.SetAttributes(
								attribute.String("output.value", truncated),
								attribute.String("gen_ai.completion", truncated),
							)
						}
					} else {
						outputText, contextID := extractTextAndContextFromA2AResponse(otelState.bodyBuf.Bytes())
						if outputText != "" {
							truncated := truncateString(outputText, 4096)
							otelState.span.SetAttributes(
								attribute.String("output.value", truncated),
								attribute.String("gen_ai.completion", truncated),
							)
						}
						if contextID != "" {
							otelState.span.SetAttributes(
								attribute.String("gen_ai.conversation.id", contextID),
								attribute.String("session.id", contextID),
							)
						}
					}
				}
				otelState.span.SetStatus(otelcodes.Ok, "")
				otelState.span.End()
			}
			if otelState.isInbound {
				activeInboundMu.Lock()
				delete(traceInbound, otelState.span.SpanContext().TraceID())
				if otelState.pendingID != "" {
					delete(pendingInbounds, otelState.pendingID)
				}
				activeInboundMu.Unlock()
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		req, err := stream.Recv()
		if err != nil {
			return status.Errorf(codes.Unknown, "cannot receive stream request: %v", err)
		}

		resp := &v3.ProcessingResponse{}

		switch r := req.Request.(type) {
		case *v3.ProcessingRequest_RequestHeaders:
			headers := r.RequestHeaders.Headers
			direction := getHeaderValue(headers.Headers, "x-telemetry-direction")
			log.Printf("[OTEL] RequestHeaders: direction=%q authority=%q method=%q",
				direction,
				getHeaderValue(headers.Headers, ":authority"),
				getHeaderValue(headers.Headers, ":method"))
			if direction == "inbound" {
				resp, otelState = p.handleInbound(headers)
			} else {
				resp, otelState = p.handleOutbound(headers)
			}

		case *v3.ProcessingRequest_RequestBody:
			if otelState != nil {
				resp = p.handleRequestBody(r.RequestBody, otelState)
			} else {
				resp = &v3.ProcessingResponse{
					Response: &v3.ProcessingResponse_RequestBody{
						RequestBody: &v3.BodyResponse{
							Response: &v3.CommonResponse{},
						},
					},
				}
			}

		case *v3.ProcessingRequest_ResponseHeaders:
			if otelState != nil {
				headers := r.ResponseHeaders.Headers
				if headers != nil {
					if statusStr := getHeaderValue(headers.Headers, ":status"); statusStr != "" {
						if code, err := strconv.Atoi(statusStr); err == nil {
							otelState.span.SetAttributes(attribute.Int("http.status_code", code))
						}
					}
				}
			}
			resp = &v3.ProcessingResponse{
				Response: &v3.ProcessingResponse_ResponseHeaders{
					ResponseHeaders: &v3.HeadersResponse{},
				},
			}

		case *v3.ProcessingRequest_ResponseBody:
			if otelState != nil {
				resp = p.handleResponseBody(r.ResponseBody, otelState)
			} else {
				resp = &v3.ProcessingResponse{
					Response: &v3.ProcessingResponse_ResponseBody{
						ResponseBody: &v3.BodyResponse{
							Response: &v3.CommonResponse{},
						},
					},
				}
			}

		default:
			log.Printf("Unknown request type: %T\n", r)
		}

		if err := stream.Send(resp); err != nil {
			return status.Errorf(codes.Unknown, "cannot send stream response: %v", err)
		}
	}
}

func main() {
	log.Println("=== Telemetry Processor Starting ===")

	otelEndpoint := os.Getenv("TELEMETRY_OTEL_ENDPOINT")
	if otelEndpoint == "" {
		otelEndpoint = "http://otel-collector.kagenti-system.svc.cluster.local:8335"
		log.Printf("[OTEL] TELEMETRY_OTEL_ENDPOINT not set, using default: %s", otelEndpoint)
	}
	if otelEndpoint != "disabled" {
		shutdownOTEL, err := initOTEL(otelEndpoint)
		if err != nil {
			log.Printf("[OTEL] Failed to initialize (continuing without OTEL): %v", err)
		} else {
			otelEnabled = true
			defer shutdownOTEL()
			agentServiceName = resolveAgentServiceName()
			initLocalPodIP()
			initLLMRegistry()
			startPendingInboundTTL()
			log.Printf("[OTEL] Enabled, exporting spans to %s (service: otel-sidecar, agent: %s, podIP: %s)", otelEndpoint, agentServiceName, localPodIP)
		}
	} else {
		log.Println("[OTEL] TELEMETRY_OTEL_ENDPOINT=disabled, OTEL skipped")
	}

	port := ":9091"
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	v3.RegisterExternalProcessorServer(grpcServer, &processor{})

	log.Printf("Starting telemetry processor on %s", port)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

package extproc

import (
	"context"
	"fmt"
	"testing"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/rossoctl/cortex/authbridge/authlib/pipeline"
)

// Envoy's ext_proc filter does not recompute Content-Length after a
// BodyMutation in BUFFERED mode with headers sent; it validates the
// existing header against the mutated body and fails the stream on a
// mismatch. Both mutation paths must therefore emit content-length
// themselves. These tests pin that contract for a body whose length
// differs from the original.

// responseBodyMutatorPlugin declares WritesBody and rewrites the
// response body via SetResponseBody.
type responseBodyMutatorPlugin struct {
	newBody []byte
}

func (p *responseBodyMutatorPlugin) Name() string { return "response-body-mutator" }
func (p *responseBodyMutatorPlugin) Capabilities() pipeline.PluginCapabilities {
	return pipeline.PluginCapabilities{WritesBody: true}
}
func (p *responseBodyMutatorPlugin) OnRequest(_ context.Context, _ *pipeline.Context) pipeline.Action {
	return pipeline.Action{Type: pipeline.Continue}
}
func (p *responseBodyMutatorPlugin) OnResponse(_ context.Context, pctx *pipeline.Context) pipeline.Action {
	pctx.SetResponseBody(p.newBody)
	return pipeline.Action{Type: pipeline.Continue}
}

func mutatedHeaderValue(hm *extprocv3.HeaderMutation, key string) (string, bool) {
	if hm == nil {
		return "", false
	}
	for _, h := range hm.SetHeaders {
		if h.GetHeader().GetKey() == key {
			return string(h.GetHeader().GetRawValue()), true
		}
	}
	return "", false
}

func TestExtProc_RequestBodyMutation_SetsContentLength(t *testing.T) {
	mutator := &bodyMutatorPlugin{newBody: []byte(`{"rewritten":"a much longer payload than before"}`)}
	inbound, err := pipeline.New([]pipeline.Plugin{mutator})
	if err != nil {
		t.Fatal(err)
	}
	outbound, err := pipeline.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{InboundPipeline: pipeline.NewHolder(inbound), OutboundPipeline: pipeline.NewHolder(outbound)}

	body := []byte(`{"original":"payload"}`)
	stream := &mockStream{
		ctx: context.Background(),
		requests: []*extprocv3.ProcessingRequest{
			inboundRequest(makeHeaders(
				"x-authbridge-direction", "inbound",
				":method", "POST",
				":path", "/mcp",
				"content-length", fmt.Sprintf("%d", len(body)),
			)),
			{Request: &extprocv3.ProcessingRequest_RequestBody{
				RequestBody: &extprocv3.HttpBody{Body: body},
			}},
		},
	}
	_ = srv.Process(stream)

	if len(stream.responses) != 2 {
		t.Fatalf("expected 2 responses, got %d", len(stream.responses))
	}
	rb := stream.responses[1].GetRequestBody()
	if rb == nil || rb.Response == nil || rb.Response.BodyMutation == nil {
		t.Fatalf("expected RequestBody.Response.BodyMutation, got %+v", stream.responses[1])
	}
	got, ok := mutatedHeaderValue(rb.Response.HeaderMutation, "content-length")
	if !ok {
		t.Fatalf("content-length not in SetHeaders: %+v", rb.Response.HeaderMutation)
	}
	if want := fmt.Sprintf("%d", len(mutator.newBody)); got != want {
		t.Errorf("content-length = %q, want %q", got, want)
	}
}

func TestExtProc_ResponseBodyMutation_SetsContentLength(t *testing.T) {
	mutator := &responseBodyMutatorPlugin{newBody: []byte(`{"redacted":true,"padding":"none needed"}`)}
	inbound, err := pipeline.New([]pipeline.Plugin{mutator})
	if err != nil {
		t.Fatal(err)
	}
	outbound, err := pipeline.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{InboundPipeline: pipeline.NewHolder(inbound), OutboundPipeline: pipeline.NewHolder(outbound)}

	body := []byte(`{"secret":"x"}`)
	stream := &mockStream{
		ctx: context.Background(),
		requests: []*extprocv3.ProcessingRequest{
			inboundRequest(makeHeaders(
				"x-authbridge-direction", "inbound",
				":method", "GET",
				":path", "/mcp",
			)),
			{Request: &extprocv3.ProcessingRequest_ResponseHeaders{
				ResponseHeaders: &extprocv3.HttpHeaders{Headers: makeHeaders(
					":status", "200",
					"content-type", "application/json",
					"content-length", fmt.Sprintf("%d", len(body)),
				)},
			}},
			{Request: &extprocv3.ProcessingRequest_ResponseBody{
				ResponseBody: &extprocv3.HttpBody{Body: body, EndOfStream: true},
			}},
		},
	}
	_ = srv.Process(stream)

	if len(stream.responses) != 3 {
		t.Fatalf("expected 3 responses, got %d", len(stream.responses))
	}
	rb := stream.responses[2].GetResponseBody()
	if rb == nil || rb.Response == nil || rb.Response.BodyMutation == nil {
		t.Fatalf("expected ResponseBody.Response.BodyMutation, got %+v", stream.responses[2])
	}
	if got := rb.Response.BodyMutation.GetBody(); string(got) != string(mutator.newBody) {
		t.Errorf("BodyMutation.Body = %q, want %q", got, mutator.newBody)
	}
	got, ok := mutatedHeaderValue(rb.Response.HeaderMutation, "content-length")
	if !ok {
		t.Fatalf("content-length not in SetHeaders: %+v", rb.Response.HeaderMutation)
	}
	if want := fmt.Sprintf("%d", len(mutator.newBody)); got != want {
		t.Errorf("content-length = %q, want %q", got, want)
	}
}

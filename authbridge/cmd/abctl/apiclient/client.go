// Package apiclient talks to AuthBridge's session events HTTP API at
// :9094 by default. It owns the wire protocol so the TUI only deals in
// domain types.
package apiclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/kagenti/kagenti-extensions/authbridge/authlib/pipeline"
	"github.com/kagenti/kagenti-extensions/authbridge/authlib/session"
)

// Client is a handle to a session API endpoint. Safe for concurrent use.
//
// Two http.Clients share a single Transport: `http` has a 10s timeout for
// short REST calls, `httpStream` has no timeout for SSE. Sharing the
// Transport keeps the idle-connection pool warm across reconnects so a
// long session doesn't leak Transports.
type Client struct {
	endpoint   string
	http       *http.Client
	httpStream *http.Client
}

// New returns a Client pointed at endpoint (e.g. "http://localhost:9094").
// Trailing slash is tolerated.
func New(endpoint string) *Client {
	// Clone the default transport rather than reuse it so tests / multiple
	// Clients don't share connection pools.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	return &Client{
		endpoint: trimSlash(endpoint),
		http: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
		httpStream: &http.Client{
			Transport: transport,
		},
	}
}

// Endpoint returns the server's base URL. Used by the TUI to display context.
func (c *Client) Endpoint() string { return c.endpoint }

// ListSessions fetches /v1/sessions.
func (c *Client) ListSessions(ctx context.Context) ([]session.SessionSummary, error) {
	var body struct {
		Sessions []session.SessionSummary `json:"sessions"`
	}
	if err := c.getJSON(ctx, "/v1/sessions", &body); err != nil {
		return nil, err
	}
	return body.Sessions, nil
}

// GetSession fetches /v1/sessions/{id}. Returns an error whose Unwrap chain
// includes ErrNotFound if the server returned 404.
func (c *Client) GetSession(ctx context.Context, id string) (*pipeline.SessionView, error) {
	var view pipeline.SessionView
	path := "/v1/sessions/" + url.PathEscape(id)
	if err := c.getJSON(ctx, path, &view); err != nil {
		return nil, err
	}
	return &view, nil
}

// ErrNotFound is returned when the server responds 404.
var ErrNotFound = fmt.Errorf("apiclient: not found")

// PipelineView is the decoded shape of GET /v1/pipeline.
type PipelineView struct {
	Inbound  []PipelinePlugin `json:"inbound"`
	Outbound []PipelinePlugin `json:"outbound"`
}

// PipelinePlugin describes one plugin's position, direction, and
// capabilities. Mirrors the server's pipelinePluginView exactly.
type PipelinePlugin struct {
	Name       string   `json:"name"`
	Direction  string   `json:"direction"`
	Position   int      `json:"position"`
	BodyAccess bool     `json:"bodyAccess"`
	Writes     []string `json:"writes"`
	Reads      []string `json:"reads"`
}

// GetPipeline fetches /v1/pipeline.
func (c *Client) GetPipeline(ctx context.Context) (*PipelineView, error) {
	var view PipelineView
	if err := c.getJSON(ctx, "/v1/pipeline", &view); err != nil {
		return nil, err
	}
	return &view, nil
}

func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.endpoint+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("%s: %w", path, ErrNotFound)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: unexpected status %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("%s: decode: %w", path, err)
	}
	return nil
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

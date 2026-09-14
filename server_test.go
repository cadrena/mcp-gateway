package mcpgateway_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gw "github.com/cadrena/mcp-gateway"
	"github.com/cadrena/mcp-gateway/transport"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type fixtureHeaders struct{ token string }

func (h fixtureHeaders) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", h.token)
	r.Header.Set("Idempotency-Key", nextID())
	r.Header.Set("X-User", "alice") // Must never override the authenticated user.
	return http.DefaultTransport.RoundTrip(r)
}

func TestHTTPGatewayToRemoteMCP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	config, _, _, _ := fixture(t)
	var calls atomic.Int32
	remote := mcp.NewServer(&mcp.Implementation{Name: "refund-fixture", Version: "1"}, nil)
	remote.AddTool(&mcp.Tool{Name: "refund_remote", InputSchema: json.RawMessage(refundSchema)}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		calls.Add(1)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "fixture accepted"}}}, nil
	})
	upstream := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return remote }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true}))
	defer upstream.Close()
	u, err := url.Parse(upstream.URL)
	must(t, err)
	client, err := transport.New(transport.Config{Endpoint: upstream.URL, AllowedHostPort: u.Host, AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, AllowLoopbackHTTP: true})
	must(t, err)
	config.Tools[0].Upstream = client
	g, err := gw.New(config)
	must(t, err)
	ts := httptest.NewUnstartedServer(nil)
	handler, err := gw.NewHTTPHandler(g, gw.HTTPConfig{AllowedHosts: []string{ts.Listener.Addr().String()}, Authenticate: func(r *http.Request) (gw.Identity, error) {
		switch r.Header.Get("Authorization") {
		case "fixture-alice":
			return identity(t, "alice", "agent1", "task1"), nil
		case "fixture-bob":
			return identity(t, "bob", "agent1", "task1"), nil
		}
		return gw.Identity{}, errors.New("invalid credential")
	}})
	must(t, err)
	ts.Config.Handler = handler
	ts.Start()
	defer ts.Close()
	for _, actor := range []string{"alice", "bob"} {
		c := mcp.NewClient(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
		session, err := c.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: ts.URL, HTTPClient: &http.Client{Transport: fixtureHeaders{"fixture-" + actor}}, DisableStandaloneSSE: true, MaxRetries: -1}, nil)
		must(t, err)
		listed, err := session.ListTools(ctx, nil)
		must(t, err)
		if len(listed.Tools) != 1 || listed.Tools[0].Name != "refund" {
			t.Fatal("unexpected catalog")
		}
		for _, amount := range []int{10000, 10001, 50000, 50001} {
			before := calls.Load()
			result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "refund", Arguments: map[string]any{"customer": "customer1", "amount": amount}})
			must(t, err)
			allowed := actor == "alice" && amount == 10000
			if allowed {
				if result.IsError || calls.Load() != before+1 {
					t.Fatal("allow did not dispatch once")
				}
			} else if !result.IsError || calls.Load() != before {
				t.Fatal("blocked call reached upstream")
			}
		}
		before := calls.Load()
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "refund", Arguments: map[string]any{"customer": "customer1", "amount": 1, "user_id": "alice"}})
		if err == nil && !result.IsError {
			t.Fatal("spoofed argument accepted")
		}
		if calls.Load() != before {
			t.Fatal("spoofed argument dispatched")
		}
		must(t, session.Close())
	}
	if calls.Load() != 1 {
		t.Fatal("unexpected total upstream calls")
	}
}

func TestHTTPBoundaryRejectsInvalidRequests(t *testing.T) {
	config, upstream, _, _ := fixture(t)
	g, err := gw.New(config)
	must(t, err)
	handler, err := gw.NewHTTPHandler(g, gw.HTTPConfig{AllowedHosts: []string{"gateway.test"}, AllowedOrigins: []string{"https://panel.test"}, Authenticate: func(r *http.Request) (gw.Identity, error) {
		if r.Header.Get("Authorization") != "fixture" {
			return gw.Identity{}, errors.New("denied")
		}
		return identity(t, "alice", "agent1", "task1"), nil
	}})
	must(t, err)
	valid := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2026-07-28","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`
	for _, tc := range []struct {
		name, body string
		status     int
		change     func(*http.Request)
	}{
		{"credential", valid, 401, func(r *http.Request) { r.Header.Del("Authorization") }},
		{"host", valid, 403, func(r *http.Request) { r.Host = "evil.test" }},
		{"origin", valid, 403, func(r *http.Request) { r.Header.Set("Origin", "https://evil.test") }},
		{"duplicate origin", valid, 403, func(r *http.Request) {
			r.Header.Add("Origin", "https://panel.test")
			r.Header.Add("Origin", "https://panel.test")
		}},
		{"legacy", strings.ReplaceAll(valid, "2026-07-28", "2025-11-25"), 400, nil},
		{"duplicate key", strings.Replace(valid, `"method":"initialize"`, `"method":"tools/call","method":"initialize"`, 1), 400, nil},
		{"trailing", valid + `{}`, 400, nil},
		{"oversize", string(bytes.Repeat([]byte(" "), 65537)), 413, nil},
		{"missing version", `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`, 400, nil},
		{"duplicate version", valid, 400, func(r *http.Request) {
			r.Header.Add("MCP-Protocol-Version", gw.ProtocolVersion)
			r.Header.Add("MCP-Protocol-Version", gw.ProtocolVersion)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "http://gateway.test", strings.NewReader(tc.body))
			r.Header.Set("Authorization", "fixture")
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Accept", "application/json, text/event-stream")
			if tc.change != nil {
				tc.change(r)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status %d, want %d", w.Code, tc.status)
			}
		})
	}
	if upstream.calls != 0 {
		t.Fatal("invalid HTTP request reached upstream")
	}
}

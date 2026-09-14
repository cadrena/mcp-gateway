package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cadrena/mcp-gateway/invocation"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestConfigAndClientRedactGenericOutput(t *testing.T) {
	const secret = "redaction-fixture-secret"
	config := Config{Endpoint: "https://" + secret + "@example.invalid", BearerToken: secret}
	client := Client{endpoint: "https://" + secret + "@example.invalid", bearerToken: secret}
	for _, tc := range []struct {
		name  string
		value any
		label string
	}{
		{"config", config, "[upstream config]"},
		{"config-pointer", &config, "[upstream config]"},
		{"client", client, "[upstream client]"},
		{"client-pointer", &client, "[upstream client]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, format := range []string{"%v", "%+v", "%#v"} {
				if got := fmt.Sprintf(format, tc.value); got != tc.label || strings.Contains(got, secret) {
					t.Fatal("generic formatting exposed configuration")
				}
			}
			encoded, err := json.Marshal(map[string]any{"value": tc.value})
			if err != nil || strings.Contains(string(encoded), secret) || !strings.Contains(string(encoded), tc.label) {
				t.Fatal("JSON exposed configuration")
			}
			for _, structured := range []bool{false, true} {
				var output bytes.Buffer
				var handler slog.Handler = slog.NewTextHandler(&output, nil)
				if structured {
					handler = slog.NewJSONHandler(&output, nil)
				}
				slog.New(handler).Info("fixture", "value", tc.value)
				if strings.Contains(output.String(), secret) || !strings.Contains(output.String(), tc.label) {
					t.Fatal("structured logging exposed configuration")
				}
			}
		})
	}
}

func localConfig(t *testing.T, endpoint string) Config {
	t.Helper()
	u, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	return Config{Endpoint: endpoint, AllowedHostPort: u.Host, AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, AllowLoopbackHTTP: true, Timeout: 2 * time.Second}
}

func fixture(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	calls := &atomic.Int32{}
	s := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "echo", Description: "echo"}, func(_ context.Context, _ *mcp.CallToolRequest, in struct {
		Value string `json:"value"`
	}) (*mcp.CallToolResult, struct {
		Value string `json:"value"`
	}, error) {
		calls.Add(1)
		return nil, in, nil
	})
	ts := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true}))
	t.Cleanup(ts.Close)
	return ts, calls
}

func TestAllowlistedFixtureAndImmutableConfig(t *testing.T) {
	ts, calls := fixture(t)
	cfg := localConfig(t, ts.URL)
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AllowedPrefixes[0] = netip.MustParsePrefix("192.0.2.0/24")
	tools, err := c.ListTools(context.Background())
	if err != nil || len(tools) != 1 || tools[0].Name != "echo" {
		t.Fatalf("tools=%v err=%v", tools, err)
	}
	r, err := c.CallTool(context.Background(), "echo", json.RawMessage(`{"value":"ok"}`))
	if err != nil || r.IsError || calls.Load() != 1 {
		t.Fatalf("result=%v err=%v calls=%d", r, err, calls.Load())
	}
}

func TestForbiddenConfiguration(t *testing.T) {
	for _, raw := range []string{"http://example.com", "https://user:secret@example.com", "https://example.com?q=secret", "https://example.com#fragment", "https://metadata.google.internal", "https://169.254.169.254", "https://100.100.100.200", "https://[fd00:ec2::254]"} {
		t.Run(raw, func(t *testing.T) {
			u, _ := url.Parse(raw)
			cfg := Config{Endpoint: raw, AllowedHostPort: u.Hostname() + ":443", AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}}
			if _, err := New(cfg); err == nil {
				t.Fatal("forbidden endpoint accepted")
			}
		})
	}
	ts, _ := fixture(t)
	cfg := localConfig(t, ts.URL)
	cfg.AllowedHostPort = "different.example:443"
	if _, err := New(cfg); err == nil {
		t.Fatal("host mismatch accepted")
	}
}

func TestAddressPolicy(t *testing.T) {
	c := &Client{prefixes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}}
	for _, value := range []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "100.64.0.1", "::1", "fc00::1", "169.254.169.254", "fe80::1", "0.0.0.0", "224.0.0.1", "::ffff:127.0.0.1"} {
		if c.allowed(netip.MustParseAddr(value)) {
			t.Fatalf("default route granted private/special %s", value)
		}
	}
	c.prefixes = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("169.254.0.0/16")}
	if !c.allowed(netip.MustParseAddr("10.0.0.1")) || !c.allowed(netip.MustParseAddr("fd00::1")) {
		t.Fatal("explicit private range rejected")
	}
	for _, value := range []string{"169.254.169.254", "fd00:ec2::254"} {
		if c.allowed(netip.MustParseAddr(value)) {
			t.Fatal("metadata allowed")
		}
	}
}

type resolverFunc func(context.Context, string, string) ([]netip.Addr, error)

func (f resolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

func TestDNSAtDialRejectsRebindingAndMixedAnswers(t *testing.T) {
	ts, calls := fixture(t)
	for _, mixed := range []bool{false, true} {
		t.Run(fmt.Sprint(mixed), func(t *testing.T) {
			cfg := localConfig(t, ts.URL)
			u, _ := url.Parse(ts.URL)
			cfg.Endpoint = "http://fixture.invalid:" + u.Port()
			cfg.AllowedHostPort = "fixture.invalid:" + u.Port()
			var resolutions atomic.Int32
			cfg.Resolver = resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
				n := resolutions.Add(1)
				if mixed {
					return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("169.254.169.254")}, nil
				}
				if n == 1 {
					return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
				}
				return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
			})
			c, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if !mixed {
				conn, err := c.dial(context.Background(), "tcp", c.hostPort)
				if err != nil {
					t.Fatalf("checked IP did not dial: %v", err)
				}
				_ = conn.Close()
			}
			if _, err = c.dial(context.Background(), "tcp", c.hostPort); err == nil {
				t.Fatal("rebound address accepted")
			}
			if calls.Load() != 0 {
				t.Fatal("forbidden target dispatched")
			}
			if !mixed && resolutions.Load() < 2 {
				t.Fatal("DNS not checked again at dial")
			}
		})
	}
}

func TestRedirectAndLegacyProtocolDoNotRetry(t *testing.T) {
	for _, status := range []int{302, 307, 500, 200} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var requests atomic.Int32
			var redirected atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
			defer target.Close()
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if status == 200 {
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"legacy secret"}}`)
					return
				}
				w.Header().Set("Location", target.URL)
				w.WriteHeader(status)
				fmt.Fprint(w, "secret")
			}))
			defer ts.Close()
			c, err := New(localConfig(t, ts.URL))
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.ListTools(context.Background())
			if err == nil {
				t.Fatal("unexpected success")
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatal("raw upstream error exposed")
			}
			if requests.Load() != 1 || redirected.Load() != 0 {
				t.Fatalf("requests=%d redirects=%d", requests.Load(), redirected.Load())
			}
		})
	}
}

func TestBodyAndDeadlineBounds(t *testing.T) {
	for _, mode := range []string{"body", "timeout", "request"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if mode == "timeout" {
					select {
					case <-r.Context().Done():
					case <-time.After(300 * time.Millisecond):
					}
					return
				}
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, strings.Repeat("x", 2048))
			}))
			defer ts.Close()
			cfg := localConfig(t, ts.URL)
			cfg.MaxResponseBytes = 64
			cfg.Timeout = 100 * time.Millisecond
			if mode == "request" {
				cfg.MaxRequestBytes = 1
			}
			c, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = c.ListTools(context.Background()); err == nil {
				t.Fatal("bound ignored")
			}
			if mode == "request" && calls.Load() != 0 {
				t.Fatal("oversized request reached target")
			}
		})
	}
}

func TestInvalidArgumentsNeverConnect(t *testing.T) {
	ts, calls := fixture(t)
	c, err := New(localConfig(t, ts.URL))
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range []string{`null`, `[]`, `{"value":`, `"a"`} {
		if _, err = c.CallTool(context.Background(), "echo", json.RawMessage(args)); !errors.Is(err, ErrProtocol) {
			t.Fatalf("invalid args %s: %v", args, err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid arguments dispatched")
	}
}

func TestHostCredentialNeverFollowsRedirect(t *testing.T) {
	var delivered, forwarded atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded.Add(1) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer host-fixture-secret" {
			delivered.Add(1)
		}
		http.Redirect(w, r, target.URL, 307)
	}))
	defer source.Close()
	cfg := localConfig(t, source.URL)
	cfg.BearerToken = "host-fixture-secret"
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.BearerToken = "other"
	_, err = c.ListTools(context.Background())
	if err == nil || strings.Contains(err.Error(), "host-fixture-secret") {
		t.Fatal("unsafe error")
	}
	if delivered.Load() != 1 || forwarded.Load() != 0 {
		t.Fatalf("delivered=%d forwarded=%d", delivered.Load(), forwarded.Load())
	}
	for _, token := range []string{"a\rb", "a\nb", "a b"} {
		cfg.BearerToken = token
		if _, err := New(cfg); err == nil {
			t.Fatal("invalid token accepted")
		}
	}
}

func TestToolFailureNeverRetries(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
	var calls atomic.Int32
	mcp.AddTool(server, &mcp.Tool{Name: "echo", Description: "echo"}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, struct{}, error) {
		calls.Add(1)
		return nil, struct{}{}, errors.New("fixture-secret")
	})
	ts := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true}))
	defer ts.Close()
	c, err := New(localConfig(t, ts.URL))
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.CallTool(context.Background(), "echo", json.RawMessage(`{}`))
	if err == nil && (result == nil || !result.IsError) {
		t.Fatal("expected tool failure")
	}
	if calls.Load() != 1 {
		t.Fatalf("attempts=%d", calls.Load())
	}
}

func TestToolHTTPFailureMakesOneAttempt(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))
		var envelope struct {
			Method string `json:"method"`
		}
		if err := json.Unmarshal(body, &envelope); err != nil {
			t.Error(err)
			return
		}
		if envelope.Method == "tools/call" {
			calls.Add(1)
			http.Error(w, "provider-secret", 503)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	defer ts.Close()
	c, err := New(localConfig(t, ts.URL))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.CallTool(context.Background(), "refund", json.RawMessage(`{}`))
	if err == nil || strings.Contains(err.Error(), "provider-secret") {
		t.Fatal("unexpected error")
	}
	if calls.Load() != 1 {
		t.Fatalf("HTTP tool attempts=%d", calls.Load())
	}
}

func TestTrustedDispatchKeyUsesMetadataWithoutChangingArguments(t *testing.T) {
	key := strings.Repeat("0123456789abcdef", 4)
	for _, attachKey := range []bool{false, true} {
		t.Run(fmt.Sprint(attachKey), func(t *testing.T) {
			server := mcp.NewServer(&mcp.Implementation{Name: "metadata-fixture", Version: "1"}, nil)
			var calls atomic.Int32
			server.AddTool(&mcp.Tool{Name: "echo", InputSchema: json.RawMessage(`{"type":"object","properties":{"value":{"type":"string"}},"additionalProperties":false}`)}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				calls.Add(1)
				got, exists := request.Params.Meta[invocation.MetadataKey]
				if exists != attachKey || attachKey && got != key {
					t.Error("dispatch metadata did not match the trusted context")
				}
				var args map[string]any
				if err := json.Unmarshal(request.Params.Arguments, &args); err != nil || len(args) != 1 || args["value"] != "unchanged" {
					t.Error("dispatch metadata changed tool arguments")
				}
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil
			})
			ts := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true}))
			defer ts.Close()
			client, err := New(localConfig(t, ts.URL))
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if attachKey {
				ctx, err = invocation.WithKey(ctx, key)
				if err != nil {
					t.Fatal(err)
				}
			}
			args := json.RawMessage(`{"value":"unchanged"}`)
			result, err := client.CallTool(ctx, "echo", args)
			if err != nil || result == nil || result.IsError || calls.Load() != 1 {
				t.Fatalf("dispatch result=%v error=%v calls=%d", result, err, calls.Load())
			}
			if string(args) != `{"value":"unchanged"}` {
				t.Fatal("caller argument buffer changed")
			}
		})
	}
}

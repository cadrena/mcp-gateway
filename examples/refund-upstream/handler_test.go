package refundupstream

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cadrena/mcp-gateway/invocation"
	"github.com/cadrena/mcp-gateway/transport"
)

const gatewayToken = "gateway-fixture-bearer-not-a-user-token"

func adapterServer(t *testing.T, a *Adapter) (*httptest.Server, *transport.Client) {
	t.Helper()
	server := httptest.NewUnstartedServer(nil)
	host := server.Listener.Addr().String()
	h, err := NewHandler(a, HTTPConfig{GatewayBearer: gatewayToken, AllowedHosts: []string{host}, AllowedOrigins: []string{"https://demo.example"}})
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = h
	server.Start()
	t.Cleanup(server.Close)
	client, err := transport.New(transport.Config{Endpoint: server.URL, AllowedHostPort: host, AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, AllowLoopbackHTTP: true, BearerToken: gatewayToken})
	if err != nil {
		t.Fatal(err)
	}
	return server, client
}

func TestHandlerRequiresAuthenticatedMetadata(t *testing.T) {
	var reads, posts atomic.Int32
	a, _ := testAdapter(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			reads.Add(1)
			_ = json.NewEncoder(w).Encode(testCharge())
			return
		}
		posts.Add(1)
		if r.Header.Get("Idempotency-Key") != testKey {
			t.Error("trusted key not forwarded")
		}
		_ = json.NewEncoder(w).Encode(testRefund("pending"))
	})
	_, client := adapterServer(t, a)
	tools, err := client.ListTools(context.Background())
	if err != nil || len(tools) != 1 || tools[0].Name != ToolName {
		t.Fatalf("catalog err=%v", err)
	}
	if reads.Load() != 0 || posts.Load() != 0 {
		t.Fatal("discovery contacted Stripe")
	}
	result, err := client.CallTool(context.Background(), ToolName, json.RawMessage(testArguments))
	if err != nil || !result.IsError {
		t.Fatalf("missing metadata accepted: %v", err)
	}
	if reads.Load() != 0 || posts.Load() != 0 {
		t.Fatal("missing key contacted Stripe")
	}
	ctx, err := invocation.WithKey(context.Background(), testKey)
	if err != nil {
		t.Fatal(err)
	}
	result, err = client.CallTool(ctx, ToolName, json.RawMessage(testArguments))
	if err != nil || result.IsError {
		t.Fatalf("authenticated refund failed: %v", err)
	}
	structured, ok := result.StructuredContent.(map[string]any)
	if !ok || structured["status"] != "pending" {
		t.Fatal("pending status lost")
	}
	if reads.Load() != 1 || posts.Load() != 1 {
		t.Fatal("unexpected Stripe request count")
	}
}

func TestHandlerTrustAndSizeBoundary(t *testing.T) {
	var stripeCalls atomic.Int32
	a, _ := testAdapter(t, func(http.ResponseWriter, *http.Request) { stripeCalls.Add(1) })
	server, _ := adapterServer(t, a)
	for _, mode := range []string{"token", "host", "origin", "body", "method", "protocol", "duplicate-origin", "duplicate-protocol"} {
		t.Run(mode, func(t *testing.T) {
			body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
			if mode == "body" {
				body = strings.Repeat("x", (64<<10)+1)
			}
			req, err := http.NewRequest(http.MethodPost, server.URL, strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+gatewayToken)
			want := http.StatusForbidden
			switch mode {
			case "token":
				req.Header.Set("Authorization", "Bearer agent-token")
				want = http.StatusUnauthorized
			case "host":
				req.Host = "attacker.example"
			case "origin":
				req.Header.Set("Origin", "https://attacker.example")
			case "body":
				want = http.StatusRequestEntityTooLarge
			case "method":
				req.Method = http.MethodGet
				want = http.StatusMethodNotAllowed
			case "protocol":
				req.Header.Set("Mcp-Protocol-Version", "2025-11-25")
				want = http.StatusBadRequest
			case "duplicate-origin":
				req.Header.Add("Origin", "https://demo.example")
				req.Header.Add("Origin", "https://attacker.example")
				want = http.StatusBadRequest
			case "duplicate-protocol":
				req.Header.Add("Mcp-Protocol-Version", "2026-07-28")
				req.Header.Add("Mcp-Protocol-Version", "2025-11-25")
				want = http.StatusBadRequest
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != want {
				t.Fatalf("status=%d want=%d", resp.StatusCode, want)
			}
		})
	}
	if stripeCalls.Load() != 0 {
		t.Fatal("invalid HTTP request reached Stripe")
	}
}

func TestHandlerUnknownIsAnRPCError(t *testing.T) {
	var posts atomic.Int32
	a, _ := testAdapter(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(testCharge())
			return
		}
		posts.Add(1)
		http.Error(w, "secret failure", 500)
	})
	_, client := adapterServer(t, a)
	ctx, err := invocation.WithKey(context.Background(), testKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.CallTool(ctx, ToolName, json.RawMessage(testArguments)); err == nil {
		t.Fatal("unknown outcome became completed result")
	}
	if posts.Load() != 1 {
		t.Fatal("unknown outcome retried")
	}
}

func TestHandlerRejectsMissingTrustConfig(t *testing.T) {
	a, _ := New(Config{APIKey: "sk_test_fixture"})
	for _, cfg := range []HTTPConfig{{}, {GatewayBearer: gatewayToken}, {GatewayBearer: "bad\nbearer", AllowedHosts: []string{"127.0.0.1"}}, {GatewayBearer: gatewayToken, AllowedHosts: []string{"*"}}} {
		if _, err := NewHandler(a, cfg); err == nil {
			t.Fatal("invalid trust config accepted")
		}
	}
}

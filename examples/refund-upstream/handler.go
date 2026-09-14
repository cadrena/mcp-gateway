package refundupstream

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/cadrena/mcp-gateway/invocation"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// HTTPConfig identifies the Gateway and the adapter's permitted HTTP surface.
// An empty origin list permits requests without Origin only.
type HTTPConfig struct {
	GatewayBearer  string
	AllowedHosts   []string
	AllowedOrigins []string
}

func (HTTPConfig) String() string   { return "Refund HTTP configuration [redacted]" }
func (HTTPConfig) GoString() string { return "Refund HTTP configuration [redacted]" }
func (HTTPConfig) LogValue() slog.Value {
	return slog.StringValue("Refund HTTP configuration [redacted]")
}

// NewHandler authenticates every request before it accepts trusted metadata.
// A deployment must isolate this credential from agents and browsers.
func NewHandler(a *Adapter, cfg HTTPConfig) (http.Handler, error) {
	if !a.configured() || len(cfg.GatewayBearer) < 16 || len(cfg.GatewayBearer) > 8192 || len(cfg.AllowedHosts) == 0 {
		return nil, ErrConfig
	}
	for _, c := range cfg.GatewayBearer {
		if c < 33 || c > 126 {
			return nil, ErrConfig
		}
	}
	hosts := map[string]bool{}
	for _, host := range cfg.AllowedHosts {
		if host == "" || strings.ContainsAny(host, "/@?#* \r\n\t") {
			return nil, ErrConfig
		}
		hosts[host] = true
	}
	origins := map[string]bool{}
	for _, origin := range cfg.AllowedOrigins {
		u, err := url.Parse(origin)
		if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") {
			return nil, ErrConfig
		}
		origins[origin] = true
	}
	expected := sha256.Sum256([]byte("Bearer " + cfg.GatewayBearer))
	server := mcp.NewServer(&mcp.Implementation{Name: "stripe-test-refund", Version: "pre-v1"}, &mcp.ServerOptions{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	var schema map[string]any
	if json.Unmarshal([]byte(Schema), &schema) != nil {
		return nil, ErrConfig
	}
	server.AddTool(&mcp.Tool{Name: ToolName, Description: "Refund an existing Stripe test Charge in USD.", InputSchema: schema}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		key, ok := request.Params.Meta[invocation.MetadataKey].(string)
		if !ok || !validKey(key) {
			return toolFailure("trusted_idempotency_key_required"), nil
		}
		result, err := a.Refund(ctx, request.Params.Arguments, key)
		if errors.Is(err, ErrOutcomeUnknown) {
			return nil, ErrOutcomeUnknown
		}
		if err != nil {
			return toolFailure("refund_not_executed"), nil
		}
		return &mcp.CallToolResult{StructuredContent: result, IsError: result.Status == "failed", Content: []mcp.Content{&mcp.TextContent{Text: "Refund status: " + result.Status}}}, nil
	})
	upstream := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, MaxRequestBodyBytes: 64 << 10, PropagateRequestCancellation: true, DisableLocalhostProtection: true})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.Header.Values("Origin")) > 1 || len(r.Header.Values("Mcp-Protocol-Version")) > 1 {
			http.Error(w, "ambiguous request headers", http.StatusBadRequest)
			return
		}
		if !hosts[r.Host] {
			http.Error(w, "host not permitted", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && !origins[origin] {
			http.Error(w, "origin not permitted", http.StatusForbidden)
			return
		}
		authorizations := r.Header.Values("Authorization")
		actual := sha256.Sum256([]byte(r.Header.Get("Authorization")))
		if len(authorizations) != 1 || subtle.ConstantTimeCompare(actual[:], expected[:]) != 1 {
			http.Error(w, "gateway authentication required", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not permitted", http.StatusMethodNotAllowed)
			return
		}
		if version := r.Header.Get("Mcp-Protocol-Version"); version != "" && version != "2026-07-28" {
			http.Error(w, "protocol not supported", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
		_ = r.Body.Close()
		if err != nil {
			http.Error(w, "invalid request size", http.StatusRequestEntityTooLarge)
			return
		}
		var envelope struct {
			Method string `json:"method"`
		}
		if json.Unmarshal(body, &envelope) != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		switch envelope.Method {
		case "server/discover", "tools/list", "tools/call":
		default:
			http.Error(w, "method not supported", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		// The exact Host and Origin checks above replace the SDK's localhost-only check.
		upstream.ServeHTTP(w, r)
	}), nil
}

func toolFailure(code string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: code}}}
}

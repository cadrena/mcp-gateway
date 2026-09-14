package mcpgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/cadrena/mcp-gateway/internal/canonical"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const ProtocolVersion = "2026-07-28"

type identityKey struct{}
type invocationIDKey struct{}

// HTTPConfig configures a stateless MCP endpoint. Authentication runs on every request.
// Authenticate must verify credentials and current agent access using trusted host data.
// It must not derive identity from tool arguments or unsigned identity headers.
type HTTPConfig struct {
	Authenticate   func(*http.Request) (Identity, error)
	AllowedHosts   []string
	AllowedOrigins []string
}

// NewHTTPHandler exposes only configured tools through Streamable HTTP.
// The host supplies TLS, HTTP server timeouts, and persistent journal storage.
func NewHTTPHandler(g *Gateway, config HTTPConfig) (http.Handler, error) {
	if g == nil || config.Authenticate == nil || len(config.AllowedHosts) == 0 {
		return nil, ErrConfiguration
	}
	hosts := make(map[string]bool)
	origins := make(map[string]bool)
	for _, host := range config.AllowedHosts {
		u, err := url.Parse("https://" + host)
		if err != nil || u.Host != host || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return nil, ErrConfiguration
		}
		hosts[host] = true
	}
	for _, origin := range config.AllowedOrigins {
		u, err := url.Parse(origin)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return nil, ErrConfiguration
		}
		origins[origin] = true
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "cadrena-gateway", Version: "w2"}, nil)
	for name, tool := range g.tools {
		server.AddTool(&mcp.Tool{Name: name, InputSchema: append(json.RawMessage(nil), tool.config.Schema...)}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			identity, ok := ctx.Value(identityKey{}).(Identity)
			if !ok {
				return nil, ErrIdentity
			}
			result, err := g.Invoke(ctx, identity, Call{InvocationID: func() string { v, _ := ctx.Value(invocationIDKey{}).(string); return v }(), Tool: request.Params.Name, Arguments: request.Params.Arguments})
			if err != nil {
				return nil, err
			}
			if result.Output != nil {
				return result.Output, nil
			}
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: result.Decision.Decision().String()}}}, nil
		})
	}
	transport := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hosts[r.Host] {
			http.Error(w, "host denied", http.StatusForbidden)
			return
		}
		originHeaders := r.Header.Values("Origin")
		if len(originHeaders) > 1 || (len(originHeaders) == 1 && !origins[originHeaders[0]]) {
			http.Error(w, "origin denied", http.StatusForbidden)
			return
		}
		identity, err := config.Authenticate(r)
		if err != nil {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		if _, err = NewIdentity(identity.actor, identity.agent, identity.task); err != nil {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method denied", http.StatusMethodNotAllowed)
			return
		}
		versions := r.Header.Values("MCP-Protocol-Version")
		if len(versions) > 1 || (len(versions) == 1 && versions[0] != ProtocolVersion) {
			http.Error(w, "protocol denied", http.StatusBadRequest)
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, canonical.MaxBytes))
		if err != nil {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		body, err := canonical.JSON(raw)
		if err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		var envelope struct {
			Method string
			Params json.RawMessage
		}
		if json.Unmarshal(body, &envelope) != nil || envelope.Method == "" {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if envelope.Method == "initialize" {
			var params struct{ ProtocolVersion string }
			if json.Unmarshal(envelope.Params, &params) != nil || params.ProtocolVersion != ProtocolVersion {
				http.Error(w, "protocol denied", http.StatusBadRequest)
				return
			}
		} else if len(versions) != 1 {
			http.Error(w, "protocol required", http.StatusBadRequest)
			return
		}
		requestContext := context.WithValue(r.Context(), identityKey{}, identity)
		if envelope.Method == "tools/call" {
			keys := r.Header.Values("Idempotency-Key")
			if len(keys) != 1 || len(keys[0]) < 16 || len(keys[0]) > 128 || !toolName.MatchString(keys[0]) {
				http.Error(w, "invocation key required", http.StatusBadRequest)
				return
			}
			requestContext = context.WithValue(requestContext, invocationIDKey{}, keys[0])
		}
		ctx, cancel := context.WithTimeout(requestContext, 30*time.Second)
		defer cancel()
		r = r.WithContext(ctx)
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		transport.ServeHTTP(w, r)
	}), nil
}

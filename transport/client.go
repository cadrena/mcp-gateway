// Package transport provides a bounded MCP upstream client.
package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cadrena/mcp-gateway/invocation"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const ProtocolVersion = "2026-07-28"

var (
	ErrConfig   = errors.New("invalid upstream configuration")
	ErrTarget   = errors.New("upstream target is not permitted")
	ErrProtocol = errors.New("upstream protocol is not supported")
	ErrLimit    = errors.New("upstream size limit exceeded")
	ErrUpstream = errors.New("upstream request failed")
)

// Resolver resolves hostnames at the network boundary. Implementations must be
// safe for concurrent use. Nil selects the system resolver.
type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// Config is copied by New. The endpoint has no userinfo, query, or fragment.
// AllowedHostPort includes the effective port, for example api.example:443.
// Every resolved address must match AllowedPrefixes. Private addresses require
// an explicit subnet within the private range; a default route does not suffice.
type Config struct {
	Endpoint          string
	AllowedHostPort   string
	AllowedPrefixes   []netip.Prefix
	AllowLoopbackHTTP bool
	Resolver          Resolver
	Timeout           time.Duration
	MaxRequestBytes   int64
	MaxResponseBytes  int64
	// BearerToken is a host credential, never an incoming request token.
	BearerToken string
}

// Config is a construction input. Generic formatting and serialization omit
// all fields because endpoint and credential values can contain secrets.
func (Config) String() string               { return "[upstream config]" }
func (Config) GoString() string             { return "[upstream config]" }
func (Config) LogValue() slog.Value         { return slog.StringValue("[upstream config]") }
func (Config) MarshalJSON() ([]byte, error) { return []byte(`"[upstream config]"`), nil }

// Client has immutable configuration and supports concurrent calls. Each call
// creates a bounded SDK session. It does not authorize or journal tool calls.
type Client struct {
	endpoint    string
	hostPort    string
	host        string
	plainHTTP   bool
	prefixes    []netip.Prefix
	resolver    Resolver
	timeout     time.Duration
	maxRequest  int64
	maxResponse int64
	bearerToken string
}

// Client never exposes its stored configuration through generic output.
func (Client) String() string               { return "[upstream client]" }
func (Client) GoString() string             { return "[upstream client]" }
func (Client) LogValue() slog.Value         { return slog.StringValue("[upstream client]") }
func (Client) MarshalJSON() ([]byte, error) { return []byte(`"[upstream client]"`), nil }

func New(cfg Config) (*Client, error) {
	if len(cfg.BearerToken) > 8192 || strings.ContainsAny(cfg.BearerToken, "\r\n\t ") {
		return nil, ErrConfig
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u == nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, ErrConfig
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && cfg.AllowLoopbackHTTP) {
		return nil, ErrConfig
	}
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, "%") || strings.HasSuffix(host, ".") || host == "metadata.google.internal" || host == "metadata.goog" {
		return nil, ErrTarget
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return nil, ErrConfig
	}
	hostPort := net.JoinHostPort(host, port)
	if cfg.AllowedHostPort != hostPort || len(cfg.AllowedPrefixes) == 0 {
		return nil, ErrConfig
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 15 * time.Second
	}
	if cfg.MaxRequestBytes == 0 {
		cfg.MaxRequestBytes = 256 << 10
	}
	if cfg.MaxResponseBytes == 0 {
		cfg.MaxResponseBytes = 1 << 20
	}
	if cfg.Timeout < 0 || cfg.Timeout > time.Minute || cfg.MaxRequestBytes < 1 || cfg.MaxRequestBytes > 4<<20 || cfg.MaxResponseBytes < 1 || cfg.MaxResponseBytes > 8<<20 {
		return nil, ErrConfig
	}
	if cfg.Resolver == nil {
		cfg.Resolver = net.DefaultResolver
	}
	c := &Client{endpoint: u.String(), hostPort: hostPort, host: host, plainHTTP: u.Scheme == "http", prefixes: append([]netip.Prefix(nil), cfg.AllowedPrefixes...), resolver: cfg.Resolver, timeout: cfg.Timeout, maxRequest: cfg.MaxRequestBytes, maxResponse: cfg.MaxResponseBytes}
	c.bearerToken = cfg.BearerToken
	for _, p := range c.prefixes {
		if !p.IsValid() || p != p.Masked() {
			return nil, ErrConfig
		}
	}
	if ip, err := netip.ParseAddr(host); err == nil && !c.allowed(ip) {
		return nil, ErrTarget
	}
	return c, nil
}

var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("100.64.0.0/10"),
}

func (c *Client) allowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	if netip.MustParsePrefix("0.0.0.0/8").Contains(ip) || netip.MustParsePrefix("240.0.0.0/4").Contains(ip) {
		return false
	}
	if !ip.IsValid() || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip == netip.MustParseAddr("255.255.255.255") || ip == netip.MustParseAddr("100.100.100.200") || ip == netip.MustParseAddr("fd00:ec2::254") {
		return false
	}
	if c.plainHTTP && !ip.IsLoopback() {
		return false
	}
	for _, p := range c.prefixes {
		if !p.Contains(ip) {
			continue
		}
		private := false
		explicit := false
		for _, r := range privateRanges {
			if r.Contains(ip) {
				private = true
				if r.Contains(p.Addr()) && p.Bits() >= r.Bits() {
					explicit = true
				}
			}
		}
		if !private || explicit {
			return true
		}
	}
	return false
}

func (c *Client) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if address != c.hostPort {
		return nil, ErrTarget
	}
	ips := []netip.Addr{}
	if ip, err := netip.ParseAddr(c.host); err == nil {
		ips = append(ips, ip)
	} else {
		var err error
		ips, err = c.resolver.LookupNetIP(ctx, "ip", c.host)
		if err != nil {
			return nil, ErrTarget
		}
	}
	if len(ips) == 0 {
		return nil, ErrTarget
	}
	for _, ip := range ips {
		if !c.allowed(ip) {
			return nil, ErrTarget
		}
	}
	_, port, _ := net.SplitHostPort(c.hostPort)
	// Dial the checked address, never the hostname. No second DNS resolution or
	// fallback address attempt occurs. TLS still verifies the configured hostname.
	return (&net.Dialer{Timeout: c.timeout}).DialContext(ctx, network, net.JoinHostPort(ips[0].Unmap().String(), port))
}

type boundedTransport struct {
	base                        *http.Transport
	endpoint                    string
	requestLimit, responseLimit int64
	bearerToken                 string
}

func (b *boundedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.String() != b.endpoint || req.Method != http.MethodPost || req.Body == nil {
		return nil, ErrProtocol
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, b.requestLimit+1))
	_ = req.Body.Close()
	if err != nil {
		return nil, ErrUpstream
	}
	if int64(len(body)) > b.requestLimit {
		return nil, ErrLimit
	}
	var envelope struct {
		Method string `json:"method"`
	}
	if json.Unmarshal(body, &envelope) != nil {
		return nil, ErrProtocol
	}
	switch envelope.Method {
	case "server/discover", "tools/list", "tools/call":
	default:
		return nil, ErrProtocol
	}
	clone := req.Clone(req.Context())
	clone.Body = io.NopCloser(bytes.NewReader(body))
	clone.GetBody = nil
	clone.Header.Del("Authorization")
	if b.bearerToken != "" {
		clone.Header.Set("Authorization", "Bearer "+b.bearerToken)
	}
	response, err := b.base.RoundTrip(clone)
	if err != nil {
		return nil, ErrUpstream
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, ErrUpstream
	}
	contentType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		return nil, ErrProtocol
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, b.responseLimit+1))
	if err != nil {
		return nil, ErrUpstream
	}
	if int64(len(data)) > b.responseLimit {
		return nil, ErrLimit
	}
	response.Body = io.NopCloser(bytes.NewReader(data))
	response.ContentLength = int64(len(data))
	return response, nil
}

func (c *Client) session(ctx context.Context) (*mcp.ClientSession, func(), error) {
	base := &http.Transport{Proxy: nil, DialContext: c.dial, DisableKeepAlives: true, ForceAttemptHTTP2: false, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: c.timeout, ResponseHeaderTimeout: c.timeout, MaxResponseHeaderBytes: 32 << 10}
	hc := &http.Client{Transport: &boundedTransport{base: base, endpoint: c.endpoint, requestLimit: c.maxRequest, responseLimit: c.maxResponse, bearerToken: c.bearerToken}, Timeout: c.timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrTarget }}
	client := mcp.NewClient(&mcp.Implementation{Name: "cadrena-gateway", Version: "pre-v1"}, &mcp.ClientOptions{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), MultiRoundTrip: &mcp.MultiRoundTripOptions{Disabled: true}})
	s, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: c.endpoint, HTTPClient: hc, DisableStandaloneSSE: true, MaxRetries: -1}, nil)
	if err != nil {
		base.CloseIdleConnections()
		return nil, func() {}, ErrUpstream
	}
	cleanup := func() { _ = s.Close(); base.CloseIdleConnections() }
	if s.InitializeResult() == nil || s.InitializeResult().ProtocolVersion != ProtocolVersion {
		cleanup()
		return nil, func() {}, ErrProtocol
	}
	return s, cleanup, nil
}

func (c *Client) ListTools(ctx context.Context) ([]*mcp.Tool, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	s, close, err := c.session(ctx)
	if err != nil {
		return nil, err
	}
	defer close()
	var tools []*mcp.Tool
	cursor := ""
	seen := map[string]bool{}
	for range 16 {
		r, err := s.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			return nil, ErrUpstream
		}
		if len(tools)+len(r.Tools) > 256 {
			return nil, ErrLimit
		}
		tools = append(tools, r.Tools...)
		if r.NextCursor == "" {
			return tools, nil
		}
		if seen[r.NextCursor] {
			return nil, ErrProtocol
		}
		seen[r.NextCursor] = true
		cursor = r.NextCursor
	}
	return nil, ErrLimit
}

// CallTool makes one upstream attempt. The caller must complete authorization
// and its durable dispatch gate before it calls this method.
// A trusted invocation key becomes MCP metadata. Calls without a key remain
// available for fixtures; this transport does not enforce the durable gate.
func (c *Client) CallTool(ctx context.Context, name string, args json.RawMessage) (*mcp.CallToolResult, error) {
	if name == "" || len(name) > 128 || int64(len(args)) > c.maxRequest {
		return nil, ErrLimit
	}
	trim := bytes.TrimSpace(args)
	if len(trim) < 2 || trim[0] != '{' || !json.Valid(trim) {
		return nil, ErrProtocol
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	s, close, err := c.session(ctx)
	if err != nil {
		return nil, err
	}
	defer close()
	params := &mcp.CallToolParams{Name: name, Arguments: json.RawMessage(append([]byte(nil), trim...))}
	// Only the trusted host context supplies dispatch metadata. Tool arguments
	// remain unchanged, and no incoming MCP metadata is copied here.
	if key, ok := invocation.Key(ctx); ok {
		params.Meta = mcp.Meta{invocation.MetadataKey: key}
	}
	r, err := s.CallTool(ctx, params)
	if err != nil {
		return nil, ErrUpstream
	}
	return r, nil
}

// Close is a no-op because each method closes its own session.
func (c *Client) Close() error { return nil }

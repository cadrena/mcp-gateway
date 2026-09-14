// Command w2-smoke runs the opt-in Stripe test flow through both MCP endpoints.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/cadrena/dsl"
	gw "github.com/cadrena/mcp-gateway"
	refund "github.com/cadrena/mcp-gateway/examples/refund-upstream"
	journalsqlite "github.com/cadrena/mcp-gateway/journal/sqlite"
	"github.com/cadrena/mcp-gateway/transport"
	pe "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/embedded"
	"github.com/cadrena/policy-engine/store/memory"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type seedAuthorizer struct{}

func (seedAuthorizer) Authorize(_ context.Context, _ pe.Caller, namespace string, capabilities []pe.Capability) (pe.CallerAuthorization, error) {
	grant, err := pe.NewGrant(namespace, capabilities)
	if err != nil {
		return pe.CallerAuthorization{}, err
	}
	return pe.NewCallerAuthorization([]pe.Grant{grant})
}

type authTransport struct{ token, id string }

func (a authTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+a.token)
	r.Header.Set("Idempotency-Key", a.id)
	return http.DefaultTransport.RoundTrip(r)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if os.Getenv("CADRENA_RUN_STRIPE_SMOKE") != "1" {
		return errors.New("set CADRENA_RUN_STRIPE_SMOKE=1 to permit a Stripe test refund")
	}
	for _, name := range []string{"STRIPE_TEST_API_KEY", "STRIPE_TEST_CUSTOMER", "STRIPE_TEST_CHARGE", "CADRENA_JOURNAL_PATH", "CADRENA_INVOCATION_ID"} {
		if os.Getenv(name) == "" {
			return fmt.Errorf("required environment variable: %s", name)
		}
	}
	id := os.Getenv("CADRENA_INVOCATION_ID")
	if len(id) < 16 || len(id) > 128 {
		return errors.New("invocation ID must contain 16 to 128 characters")
	}
	amount := int64(100)
	if text := os.Getenv("STRIPE_TEST_AMOUNT_MINOR"); text != "" {
		n, err := strconv.ParseInt(text, 10, 64)
		if err != nil || n <= 0 {
			return errors.New("invalid smoke amount")
		}
		amount = n
	}
	adapter, err := refund.New(refund.Config{APIKey: os.Getenv("STRIPE_TEST_API_KEY")})
	if err != nil {
		return err
	}
	path := os.Getenv("CADRENA_JOURNAL_PATH")
	if !filepath.IsAbs(path) {
		return errors.New("journal path must be absolute")
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return errors.New("cannot create journal directory")
	}
	journal, err := journalsqlite.Open(path)
	if err != nil {
		return err
	}
	defer journal.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	engine, err := seed(ctx, os.Getenv("STRIPE_TEST_CUSTOMER"))
	if err != nil {
		return err
	}
	remoteListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return errors.New("cannot listen locally")
	}
	defer remoteListener.Close()
	remoteToken := randomToken()
	remoteHandler, err := refund.NewHandler(adapter, refund.HTTPConfig{GatewayBearer: remoteToken, AllowedHosts: []string{remoteListener.Addr().String()}})
	if err != nil {
		return err
	}
	remoteServer := &http.Server{Handler: remoteHandler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second}
	defer remoteServer.Close()
	go func() { _ = remoteServer.Serve(remoteListener) }()
	upstream, err := transport.New(transport.Config{Endpoint: "http://" + remoteListener.Addr().String(), AllowedHostPort: remoteListener.Addr().String(), AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, AllowLoopbackHTTP: true, BearerToken: remoteToken})
	if err != nil {
		return err
	}
	gateway, err := gw.New(gw.Config{Namespace: "demo", CallerID: "gateway", Slot: "active", Engine: engine, Journal: journal, Tools: []gw.Tool{{Name: refund.ToolName, RemoteName: refund.ToolName, ConnectionID: "stripe-test", ConfigVersion: "v1", MappingVersion: "v1", Action: "refund", ResourceType: "customer", ResourceArgument: "customer", Schema: json.RawMessage(refund.Schema), Upstream: upstream}}})
	if err != nil {
		return err
	}
	gatewayListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return errors.New("cannot listen locally")
	}
	defer gatewayListener.Close()
	gatewayToken := randomToken()
	identity, err := gw.NewIdentity("demo-user", "demo-agent", "stripe-smoke")
	if err != nil {
		return err
	}
	handler, err := gw.NewHTTPHandler(gateway, gw.HTTPConfig{AllowedHosts: []string{gatewayListener.Addr().String()}, Authenticate: func(r *http.Request) (gw.Identity, error) {
		if r.Header.Get("Authorization") != "Bearer "+gatewayToken {
			return gw.Identity{}, errors.New("authentication required")
		}
		return identity, nil
	}})
	if err != nil {
		return err
	}
	gatewayServer := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 35 * time.Second, WriteTimeout: 35 * time.Second}
	defer gatewayServer.Close()
	go func() { _ = gatewayServer.Serve(gatewayListener) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "w2-smoke", Version: "1"}, &mcp.ClientOptions{MultiRoundTrip: &mcp.MultiRoundTripOptions{Disabled: true}})
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: "http://" + gatewayListener.Addr().String(), HTTPClient: &http.Client{Transport: authTransport{gatewayToken, id}, Timeout: 35 * time.Second}, DisableStandaloneSSE: true, MaxRetries: -1}, nil)
	if err != nil {
		return errors.New("gateway connection failed")
	}
	defer session.Close()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: refund.ToolName, Arguments: map[string]any{"customer": os.Getenv("STRIPE_TEST_CUSTOMER"), "payment": os.Getenv("STRIPE_TEST_CHARGE"), "amount_minor": amount}})
	if err != nil {
		return errors.New("call failed or replay refused; preserve the journal and do not retry with a new ID")
	}
	if result.IsError {
		return errors.New("refund did not execute successfully; check the journal and policy decision")
	}
	return json.NewEncoder(os.Stdout).Encode(result.StructuredContent)
}

func randomToken() string {
	var token [32]byte
	_, _ = rand.Read(token[:])
	return hex.EncodeToString(token[:])
}

func seed(ctx context.Context, customer string) (pe.Engine, error) {
	store, err := memory.New()
	if err != nil {
		return nil, err
	}
	engine, err := embedded.New(embedded.WithStore(store), embedded.WithCallerAuthorizer(seedAuthorizer{}))
	if err != nil {
		return nil, err
	}
	caller, err := pe.NewCaller("seed", nil)
	if err != nil {
		return nil, err
	}
	request, err := pe.NewPublishRequest("demo", "refund.cdr", []byte(`entity user {}
entity customer { relation operator @user action refund = operator }
guard customer.refund {
 deny when arguments.amount_minor > 50000
 require_approval finance when arguments.amount_minor > 10000
 allow otherwise
}`))
	if err != nil {
		return nil, err
	}
	published, err := engine.Publish(ctx, caller, request)
	if err != nil {
		return nil, err
	}
	activation, err := pe.NewActivateRequest("demo", "active", published.Revision().ID(), pe.NewUnsetSlotExpectation())
	if err != nil {
		return nil, err
	}
	if _, err = engine.Activate(ctx, caller, activation); err != nil {
		return nil, err
	}
	tuple, err := pe.NewRelationshipTuple(dsl.Tuple{Resource: dsl.EntityRef{Type: "customer", ID: customer}, Relation: "operator", Subject: dsl.SubjectRef{Type: "user", ID: "demo-user"}}, nil)
	if err != nil {
		return nil, err
	}
	write, err := pe.NewWriteDataRequest(pe.WriteDataRequestInput{Namespace: "demo", ValidationRevisionID: published.Revision().ID(), IdempotencyKey: "seed", TupleWrites: []pe.RelationshipTuple{tuple}})
	if err != nil {
		return nil, err
	}
	_, err = engine.WriteData(ctx, caller, write)
	return engine, err
}

// Command w2-local-demo runs simulated refunds through two loopback MCP endpoints.
// It never uses Stripe credentials or external service endpoints.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cadrena/dsl"
	gw "github.com/cadrena/mcp-gateway"
	simulator "github.com/cadrena/mcp-gateway/examples/refund-simulator"
	"github.com/cadrena/mcp-gateway/journal"
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

type authTransport struct {
	token, id string
	base      http.RoundTripper
}

func (a authTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+a.token)
	r.Header.Set("Idempotency-Key", a.id)
	return a.base.RoundTrip(r)
}
func randomToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", errors.New("local token generation failed")
	}
	return hex.EncodeToString(b[:]), nil
}

type scenarioResult struct {
	Name           string `json:"name"`
	Decision       string `json:"decision"`
	RefundCount    int64  `json:"refund_count"`
	RemainingMinor int64  `json:"remaining_minor"`
}
type report struct {
	Simulator            bool             `json:"simulator"`
	Status               string           `json:"status"`
	ApprovalContinuation string           `json:"approval_continuation"`
	Cases                []scenarioResult `json:"cases"`
}

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(parent context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("w2-local-demo", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stateDir := flags.String("state-dir", "", "absolute private state directory; preserved between runs")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return errors.New("usage: w2-local-demo --state-dir /absolute/private/directory")
	}
	if !filepath.IsAbs(*stateDir) {
		return errors.New("state-dir must be an explicit absolute path")
	}
	if err := os.MkdirAll(*stateDir, 0700); err != nil {
		return errors.New("cannot create private state directory")
	}
	info, err := os.Lstat(*stateDir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("state-dir must be a private directory without a symlink")
	}
	ctx, cancel := context.WithTimeout(parent, 60*time.Second)
	defer cancel()
	sim, err := simulator.New(filepath.Join(*stateDir, "refunds.sqlite"))
	if err != nil {
		return err
	}
	defer sim.Close()
	cases := []struct {
		name, id, payment, actor string
		amount                   int64
		decision                 string
	}{
		{"allow_boundary", "demo-allow-boundary-v1", "ch_localallow", "demo-user", 10000, "ALLOW"},
		{"approval_lower", "demo-approval-lower-v1", "ch_locallower", "demo-user", 10001, "REQUIRE_APPROVAL"},
		{"approval_upper", "demo-approval-upper-v1", "ch_localupper", "demo-user", 50000, "REQUIRE_APPROVAL"},
		{"deny_upper", "demo-deny-upper-v1", "ch_localdeny", "demo-user", 50001, "DENY"},
		{"deny_foreign_actor", "demo-foreign-actor-v1", "ch_localforeign", "foreign-user", 10000, "DENY"},
	}
	for _, c := range cases {
		if err := sim.Seed(ctx, simulator.Payment{Customer: "cus_localdemo", ID: c.payment, AmountMinor: 100000}); err != nil {
			return err
		}
	}
	before, err := sim.Summary(ctx, cases[0].payment)
	if err != nil {
		return err
	}
	if before.RefundCount != 0 && before.RefundCount != 1 {
		return errors.New("simulated fixture has unexpected history; preserve state for review")
	}
	engine, err := seed(ctx, "cus_localdemo")
	if err != nil {
		return err
	}
	result := report{Simulator: true, Status: "passed", ApprovalContinuation: "not implemented; approval cases remain awaiting approval", Cases: []scenarioResult{}}
	// Each phase opens its own journal and endpoint pair. The second phase proves reopen replay refusal.
	for phase := 0; phase < 2; phase++ {
		err := func() error {
			store, err := journalsqlite.Open(filepath.Join(*stateDir, "journal.sqlite"))
			if err != nil {
				return err
			}
			defer store.Close()
			endpoint, err := startEndpoints(sim, engine, store)
			if err != nil {
				return err
			}
			defer endpoint.close()
			if phase == 0 {
				for _, c := range cases {
					decision, err := endpoint.call(ctx, c.actor, c.id, c.payment, c.amount)
					if err != nil {
						return err
					}
					want := c.decision
					if c.name == "allow_boundary" && before.RefundCount == 1 {
						want = "REPLAY_REFUSED"
					}
					if decision != want {
						return fmt.Errorf("simulated scenario %s expected %s, received %s", c.name, want, decision)
					}
					summary, err := sim.Summary(ctx, c.payment)
					if err != nil {
						return err
					}
					wantCount, wantBalance := int64(0), int64(100000)
					if c.name == "allow_boundary" {
						wantCount, wantBalance = 1, 90000
					}
					if summary.RefundCount != wantCount || summary.RemainingMinor != wantBalance {
						return fmt.Errorf("simulated scenario %s changed an unexpected balance", c.name)
					}
					result.Cases = append(result.Cases, scenarioResult{c.name, decision, summary.RefundCount, summary.RemainingMinor})
				}
				decision, err := endpoint.call(ctx, "demo-user", cases[0].id, cases[0].payment, 10000)
				if err != nil {
					return err
				}
				if decision != "REPLAY_REFUSED" {
					return errors.New("same invocation did not refuse replay")
				}
				result.Cases = append(result.Cases, scenarioResult{"same_invocation", decision, 1, 90000})
				decision, err = endpoint.call(ctx, "demo-user", cases[0].id, cases[0].payment, 9999)
				if err != nil {
					return err
				}
				if decision != "CONFLICT" {
					return errors.New("changed arguments did not conflict")
				}
				result.Cases = append(result.Cases, scenarioResult{"changed_arguments", decision, 1, 90000})
			} else {
				decision, err := endpoint.call(ctx, "demo-user", cases[0].id, cases[0].payment, 10000)
				if err != nil {
					return err
				}
				if decision != "REPLAY_REFUSED" {
					return errors.New("reopened journal did not refuse replay")
				}
				result.Cases = append(result.Cases, scenarioResult{"reopened_journal", decision, 1, 90000})
			}
			summary, err := sim.Summary(ctx, cases[0].payment)
			if err != nil {
				return err
			}
			if summary.RefundCount != 1 || summary.RemainingMinor != 90000 {
				return errors.New("duplicate simulated refund detected")
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return json.NewEncoder(out).Encode(result)
}

type endpoints struct {
	url             string
	tokens          map[string]string
	servers         []*http.Server
	clientTransport *http.Transport
}

func (e *endpoints) close() {
	for _, s := range e.servers {
		_ = s.Close()
	}
	if e.clientTransport != nil {
		e.clientTransport.CloseIdleConnections()
	}
}
func startEndpoints(sim *simulator.Simulator, engine pe.Engine, store journal.Store) (e *endpoints, err error) {
	e = &endpoints{tokens: map[string]string{}, clientTransport: &http.Transport{Proxy: nil}}
	success := false
	cleanup := e
	defer func() {
		if !success {
			cleanup.close()
		}
	}()
	listen := func(build func(string) (http.Handler, error)) (string, error) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return "", errors.New("cannot listen locally")
		}
		handler, err := build(listener.Addr().String())
		if err != nil {
			listener.Close()
			return "", err
		}
		server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second}
		e.servers = append(e.servers, server)
		go func() { _ = server.Serve(listener) }()
		return listener.Addr().String(), nil
	}
	remoteToken, err := randomToken()
	if err != nil {
		return nil, err
	}
	address, err := listen(func(host string) (http.Handler, error) {
		return simulator.NewHandler(sim, simulator.HTTPConfig{GatewayBearer: remoteToken, AllowedHosts: []string{host}})
	})
	if err != nil {
		return nil, err
	}
	upstream, err := transport.New(transport.Config{Endpoint: "http://" + address, AllowedHostPort: address, AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, AllowLoopbackHTTP: true, BearerToken: remoteToken})
	if err != nil {
		return nil, err
	}
	gateway, err := gw.New(gw.Config{Namespace: "demo", CallerID: "gateway", Slot: "active", Engine: engine, Journal: store, Tools: []gw.Tool{{Name: simulator.ToolName, RemoteName: simulator.ToolName, ConnectionID: "local-simulator", ConfigVersion: "v1", MappingVersion: "v1", Action: "refund", ResourceType: "customer", ResourceArgument: "customer", Schema: json.RawMessage(simulator.Schema), Upstream: upstream}}})
	if err != nil {
		return nil, err
	}
	identities := map[string]gw.Identity{}
	for _, actor := range []string{"demo-user", "foreign-user"} {
		token, err := randomToken()
		if err != nil {
			return nil, err
		}
		identity, err := gw.NewIdentity(actor, "demo-agent", "local-refund-demo")
		if err != nil {
			return nil, err
		}
		e.tokens[actor] = token
		identities["Bearer "+token] = identity
	}
	address, err = listen(func(host string) (http.Handler, error) {
		return gw.NewHTTPHandler(gateway, gw.HTTPConfig{AllowedHosts: []string{host}, Authenticate: func(r *http.Request) (gw.Identity, error) {
			identity, ok := identities[r.Header.Get("Authorization")]
			if !ok {
				return gw.Identity{}, errors.New("authentication required")
			}
			return identity, nil
		}})
	})
	if err != nil {
		return nil, err
	}
	e.url = "http://" + address
	success = true
	return e, nil
}
func (e *endpoints) call(ctx context.Context, actor, id, payment string, amount int64) (string, error) {
	client := mcp.NewClient(&mcp.Implementation{Name: "w2-local-demo", Version: "1"}, &mcp.ClientOptions{MultiRoundTrip: &mcp.MultiRoundTripOptions{Disabled: true}})
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: e.url, HTTPClient: &http.Client{Transport: authTransport{e.tokens[actor], id, e.clientTransport}, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, DisableStandaloneSSE: true, MaxRetries: -1}, nil)
	if err != nil {
		return "", errors.New("local gateway connection failed")
	}
	defer session.Close()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: simulator.ToolName, Arguments: map[string]any{"customer": "cus_localdemo", "payment": payment, "amount_minor": amount}})
	if err != nil {
		if strings.Contains(err.Error(), journal.ErrReplay.Error()) {
			return "REPLAY_REFUSED", nil
		}
		if strings.Contains(err.Error(), journal.ErrConflict.Error()) {
			return "CONFLICT", nil
		}
		return "", errors.New("local gateway call failed")
	}
	if !result.IsError {
		var simulated simulator.Result
		raw, marshalErr := json.Marshal(result.StructuredContent)
		if marshalErr != nil || json.Unmarshal(raw, &simulated) != nil || !simulated.Simulator || simulated.Status != "simulated" || simulated.AmountMinor != amount || simulated.Currency != "usd" || !strings.HasPrefix(simulated.RefundID, "sim_") {
			return "", errors.New("unexpected simulator success response")
		}
		return "ALLOW", nil
	}
	for _, content := range result.Content {
		if text, ok := content.(*mcp.TextContent); ok && (text.Text == "DENY" || text.Text == "REQUIRE_APPROVAL") {
			return text.Text, nil
		}
	}
	return "", errors.New("local simulator returned an unexpected failure")
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

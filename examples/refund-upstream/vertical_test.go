package refundupstream

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/cadrena/dsl"
	gw "github.com/cadrena/mcp-gateway"
	"github.com/cadrena/mcp-gateway/journal"
	storesqlite "github.com/cadrena/mcp-gateway/journal/sqlite"
	pe "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/embedded"
	"github.com/cadrena/policy-engine/store/memory"
)

type testAuthorizer struct{}

func (testAuthorizer) Authorize(_ context.Context, _ pe.Caller, namespace string, capabilities []pe.Capability) (pe.CallerAuthorization, error) {
	grant, err := pe.NewGrant(namespace, capabilities)
	if err != nil {
		return pe.CallerAuthorization{}, err
	}
	return pe.NewCallerAuthorization([]pe.Grant{grant})
}

type observedJournal struct {
	journal.Store
	key    [32]byte
	writes int
}

func (s *observedJournal) Authorize(ctx context.Context, r journal.Record) (journal.Lease, error) {
	s.key = r.Key
	s.writes++
	return s.Store.Authorize(ctx, r)
}

func verticalGateway(t *testing.T, adapter *Adapter) (*gw.Gateway, *observedJournal) {
	t.Helper()
	ctx := context.Background()
	store, err := memory.New()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := embedded.New(embedded.WithStore(store), embedded.WithCallerAuthorizer(testAuthorizer{}))
	if err != nil {
		t.Fatal(err)
	}
	caller, err := pe.NewCaller("seed", nil)
	if err != nil {
		t.Fatal(err)
	}
	request, err := pe.NewPublishRequest("demo", "refund.cdr", []byte(`entity user {}
entity customer { relation operator @user action refund = operator }
guard customer.refund {
 deny when arguments.amount_minor > 50000
 require_approval finance when arguments.amount_minor > 10000
 allow otherwise
}`))
	if err != nil {
		t.Fatal(err)
	}
	published, err := engine.Publish(ctx, caller, request)
	if err != nil {
		t.Fatal(err)
	}
	activate, err := pe.NewActivateRequest("demo", "active", published.Revision().ID(), pe.NewUnsetSlotExpectation())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = engine.Activate(ctx, caller, activate); err != nil {
		t.Fatal(err)
	}
	tuple, err := pe.NewRelationshipTuple(dsl.Tuple{Resource: dsl.EntityRef{Type: "customer", ID: "cus_fixture"}, Relation: "operator", Subject: dsl.SubjectRef{Type: "user", ID: "alice"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	write, err := pe.NewWriteDataRequest(pe.WriteDataRequestInput{Namespace: "demo", ValidationRevisionID: published.Revision().ID(), IdempotencyKey: "seed", TupleWrites: []pe.RelationshipTuple{tuple}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = engine.WriteData(ctx, caller, write); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	durable, err := storesqlite.Open(filepath.Join(dir, "journal.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = durable.Close() })
	observed := &observedJournal{Store: durable}
	_, client := adapterServer(t, adapter)
	gateway, err := gw.New(gw.Config{Namespace: "demo", CallerID: "gateway", Slot: "active", Engine: engine, Journal: observed, Tools: []gw.Tool{{Name: ToolName, RemoteName: ToolName, ConnectionID: "stripe-test", ConfigVersion: "v1", MappingVersion: "v1", Action: "refund", ResourceType: "customer", ResourceArgument: "customer", Schema: json.RawMessage(Schema), Upstream: client}}})
	if err != nil {
		t.Fatal(err)
	}
	return gateway, observed
}

func TestGatewayStripeVerticalFlow(t *testing.T) {
	for _, mode := range []string{"succeeded", "pending", "500", "ownership", "balance", "deny", "approval", "access"} {
		t.Run(mode, func(t *testing.T) {
			var reads, posts atomic.Int32
			var postedKey atomic.Value
			adapter, _ := testAdapter(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					reads.Add(1)
					charge := testCharge()
					if mode == "ownership" {
						charge["customer"] = "cus_other"
					}
					if mode == "balance" {
						charge["amount_refunded"] = 95000
					}
					_ = json.NewEncoder(w).Encode(charge)
					return
				}
				posts.Add(1)
				postedKey.Store(r.Header.Get("Idempotency-Key"))
				if mode == "500" {
					http.Error(w, "ambiguous", 500)
					return
				}
				status := "succeeded"
				if mode == "pending" {
					status = "pending"
				}
				_ = json.NewEncoder(w).Encode(testRefund(status))
			})
			gateway, j := verticalGateway(t, adapter)
			actor := "alice"
			if mode == "access" {
				actor = "bob"
			}
			identity, err := gw.NewIdentity(actor, "agent", "refund-task")
			if err != nil {
				t.Fatal(err)
			}
			amount := 10000
			if mode == "deny" {
				amount = 50001
			}
			if mode == "approval" {
				amount = 10001
			}
			call := gw.Call{InvocationID: "fixture-invocation-0001", Tool: ToolName, Arguments: json.RawMessage(fmt.Sprintf(`{"customer":"cus_fixture","payment":"ch_fixture","amount_minor":%d}`, amount))}
			result, err := gateway.Invoke(context.Background(), identity, call)
			switch mode {
			case "deny", "approval", "access":
				want := pe.DecisionDeny
				if mode == "approval" {
					want = pe.DecisionRequireApproval
				}
				if err != nil || result.Decision.Decision() != want || reads.Load() != 0 || posts.Load() != 0 || j.writes != 0 {
					t.Fatalf("policy boundary failed: %v", err)
				}
				return
			case "ownership", "balance":
				if err != nil || result.State != journal.Completed || posts.Load() != 0 || j.writes != 1 {
					t.Fatalf("remote validation failed: %v", err)
				}
			case "500":
				if !errors.Is(err, gw.ErrUpstream) || result.State != journal.OutcomeUnknown {
					t.Fatalf("unknown outcome lost: %v", err)
				}
			default:
				if err != nil || result.State != journal.Completed {
					t.Fatalf("completion failed: %v", err)
				}
			}
			expectedPosts := int32(1)
			if mode == "ownership" || mode == "balance" {
				expectedPosts = 0
			}
			if posts.Load() != expectedPosts || reads.Load() != 1 || (expectedPosts == 1 && postedKey.Load() != hex.EncodeToString(j.key[:])) {
				t.Fatal("wrong dispatch count or journal key")
			}
			record, err := j.Lookup(context.Background(), j.key)
			if err != nil {
				t.Fatal(err)
			}
			want := journal.Success
			if mode == "ownership" || mode == "balance" {
				want = journal.Failure
			}
			if mode == "pending" {
				want = journal.Pending
			}
			if mode == "500" {
				want = journal.Unknown
			}
			if record.Outcome != want {
				t.Fatalf("journal outcome=%v want=%v", record.Outcome, want)
			}
			if _, err = gateway.Invoke(context.Background(), identity, call); !errors.Is(err, gw.ErrReplay) {
				t.Fatalf("repeat accepted: %v", err)
			}
			call.Arguments = json.RawMessage(`{"customer":"cus_fixture","payment":"ch_fixture","amount_minor":9999}`)
			if _, err = gateway.Invoke(context.Background(), identity, call); !errors.Is(err, gw.ErrConflict) {
				t.Fatalf("changed arguments accepted: %v", err)
			}
			if posts.Load() != expectedPosts || reads.Load() != 1 {
				t.Fatal("replay made a new Stripe request")
			}
		})
	}
}

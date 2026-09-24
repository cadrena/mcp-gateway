package mcpgateway_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	journalsqlite "github.com/cadrena/mcp-gateway/journal/sqlite"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/cadrena/dsl"
	gw "github.com/cadrena/mcp-gateway"
	pe "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/embedded"
	"github.com/cadrena/policy-engine/store/memory"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const refundSchema = `{"type":"object","properties":{"customer":{"type":"string","minLength":1},"amount":{"type":"integer","minimum":1},"memo":{"type":"string"}},"required":["customer","amount"],"additionalProperties":false}`

const refundPolicy = `
entity user {}
entity customer {
  relation operator @user
  action refund = operator
}
guard customer.refund {
  deny when arguments.amount > 50000
  require_approval finance when arguments.amount > 10000
  allow otherwise
}
`

type fixtureAuthorizer struct{}

func (fixtureAuthorizer) Authorize(_ context.Context, _ pe.Caller, namespace string, capabilities []pe.Capability) (pe.CallerAuthorization, error) {
	// This fixture grants the requested capabilities. Hosts authenticate callers.
	grant, err := pe.NewGrant(namespace, capabilities)
	if err != nil {
		return pe.CallerAuthorization{}, err
	}
	return pe.NewCallerAuthorization([]pe.Grant{grant})
}

type fixtureUpstream struct {
	tools []*mcp.Tool
	calls int
	name  string
	args  json.RawMessage
}

func (u *fixtureUpstream) ListTools(context.Context) ([]*mcp.Tool, error) { return u.tools, nil }
func (u *fixtureUpstream) CallTool(_ context.Context, name string, args json.RawMessage) (*mcp.CallToolResult, error) {
	u.calls++
	u.name, u.args = name, append(json.RawMessage(nil), args...)
	return &mcp.CallToolResult{StructuredContent: map[string]any{"fixture": true}}, nil
}

type recordingChecker struct {
	inner gw.Checker
	seen  []pe.Caller
	err   error
}

func (c *recordingChecker) Check(ctx context.Context, caller pe.Caller, request pe.CheckRequest) (pe.CheckResponse, error) {
	c.seen = append(c.seen, caller)
	if c.err != nil {
		return pe.CheckResponse{}, c.err
	}
	return c.inner.Check(ctx, caller, request)
}

func (c *recordingChecker) BatchCheck(ctx context.Context, caller pe.Caller, request pe.BatchCheckRequest) (pe.BatchCheckResponse, error) {
	c.seen = append(c.seen, caller)
	if c.err != nil {
		return pe.BatchCheckResponse{}, c.err
	}
	return c.inner.BatchCheck(ctx, caller, request)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func identity(t *testing.T, actor, agent, task string) gw.Identity {
	t.Helper()
	i, err := gw.NewIdentity(actor, agent, task)
	must(t, err)
	return i
}

func fixture(t *testing.T) (gw.Config, *fixtureUpstream, *recordingChecker, string) {
	t.Helper()
	ctx := context.Background()
	storage, err := memory.New()
	must(t, err)
	engine, err := embedded.New(embedded.WithStore(storage), embedded.WithCallerAuthorizer(fixtureAuthorizer{}))
	must(t, err)
	caller, err := pe.NewCaller("seed", nil)
	must(t, err)
	publish, err := pe.NewPublishRequest("tenant", "refund.cdr", []byte(refundPolicy))
	must(t, err)
	published, err := engine.Publish(ctx, caller, publish)
	must(t, err)
	revision := published.Revision().ID()
	activation, err := pe.NewActivateRequest("tenant", "active", revision, pe.NewUnsetSlotExpectation())
	must(t, err)
	_, err = engine.Activate(ctx, caller, activation)
	must(t, err)
	tuple, err := pe.NewRelationshipTuple(dsl.Tuple{Resource: dsl.EntityRef{Type: "customer", ID: "customer1"}, Relation: "operator", Subject: dsl.SubjectRef{Type: "user", ID: "alice"}}, nil)
	must(t, err)
	write, err := pe.NewWriteDataRequest(pe.WriteDataRequestInput{Namespace: "tenant", ValidationRevisionID: revision, IdempotencyKey: "seed", TupleWrites: []pe.RelationshipTuple{tuple}})
	must(t, err)
	_, err = engine.WriteData(ctx, caller, write)
	must(t, err)
	u := &fixtureUpstream{tools: []*mcp.Tool{{Name: "refund_remote", InputSchema: json.RawMessage(refundSchema)}}}
	c := &recordingChecker{inner: engine}
	config := gw.Config{Namespace: "tenant", CallerID: "gateway", Slot: "active", Engine: c, Tools: []gw.Tool{{Name: "refund", RemoteName: "refund_remote", ConnectionID: "stripe", ConfigVersion: "v1", MappingVersion: "v1", Action: "refund", ResourceType: "customer", ResourceArgument: "customer", Schema: json.RawMessage(refundSchema), Upstream: u}}}
	config.Journal = testJournal(t)
	return config, u, c, revision
}

func TestInvokeUsesRealPolicyAndCustomerAccess(t *testing.T) {
	for _, tc := range []struct {
		name, actor, customer string
		amount                int
		decision              pe.Decision
		calls                 int
	}{
		{"below", "alice", "customer1", 9999, pe.DecisionAllow, 1},
		{"allow-boundary", "alice", "customer1", 10000, pe.DecisionAllow, 1},
		{"approval-start", "alice", "customer1", 10001, pe.DecisionRequireApproval, 0},
		{"approval-boundary", "alice", "customer1", 50000, pe.DecisionRequireApproval, 0},
		{"denied-amount", "alice", "customer1", 50001, pe.DecisionDeny, 0},
		{"denied-user", "bob", "customer1", 100, pe.DecisionDeny, 0},
		{"denied-customer", "alice", "customer2", 100, pe.DecisionDeny, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, u, checker, revision := fixture(t)
			gateway, err := gw.New(config)
			must(t, err)
			args := json.RawMessage(fmt.Sprintf(`{"customer":%q,"amount":%d}`, tc.customer, tc.amount))
			result, err := gateway.Invoke(context.Background(), identity(t, tc.actor, "agent", "task"), gw.Call{InvocationID: nextID(), Tool: "refund", Arguments: args})
			must(t, err)
			if result.Decision.Decision() != tc.decision || u.calls != tc.calls || len(checker.seen) != 1 {
				t.Fatalf("decision=%v calls=%d checks=%d", result.Decision.Decision(), u.calls, len(checker.seen))
			}
			if result.DecisionDuration <= 0 {
				t.Fatal("successful Engine check did not report its duration")
			}
			if result.Decision.RevisionID() != revision || result.Decision.DataGeneration() != 1 || result.Decision.SlotGeneration() != 1 {
				t.Fatal("result lost the real Engine snapshot")
			}
			if (result.Output != nil) != (tc.calls == 1) {
				t.Fatal("output does not match dispatch")
			}
			if tc.calls == 1 && (u.name != "refund_remote" || string(u.args) != fmt.Sprintf(`{"amount":%d,"customer":%q}`, tc.amount, tc.customer)) {
				t.Fatal("dispatch did not use canonical mapped arguments")
			}
		})
	}
}

func TestRejectsUntrustedInputsBeforeCheckOrDispatch(t *testing.T) {
	for _, tc := range []struct{ name, tool, args string }{
		{"unknown-tool", "unknown", `{"customer":"customer1","amount":100}`},
		{"spoof-user", "refund", `{"customer":"customer1","amount":100,"user_id":"alice"}`},
		{"spoof-approval", "refund", `{"customer":"customer1","amount":100,"approval":"granted"}`},
		{"negative", "refund", `{"customer":"customer1","amount":-1}`},
		{"fraction", "refund", `{"customer":"customer1","amount":1.5}`},
		{"missing", "refund", `{"customer":"customer1"}`},
		{"duplicate", "refund", `{"customer":"customer1","amount":100,"amount":200}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, u, checker, _ := fixture(t)
			gateway, err := gw.New(config)
			must(t, err)
			_, err = gateway.Invoke(context.Background(), identity(t, "alice", "agent", "task"), gw.Call{InvocationID: nextID(), Tool: tc.tool, Arguments: json.RawMessage(tc.args)})
			if err == nil || u.calls != 0 || len(checker.seen) != 0 {
				t.Fatal("untrusted input reached authorization or dispatch")
			}
		})
	}
}

func TestChangedRemoteSchemaFailsClosed(t *testing.T) {
	config, u, checker, _ := fixture(t)
	gateway, err := gw.New(config)
	must(t, err)
	u.tools[0].InputSchema = json.RawMessage(`{"type":"object","properties":{"customer":{"type":"string"}},"additionalProperties":false}`)
	_, err = gateway.Invoke(context.Background(), identity(t, "alice", "agent", "task"), gw.Call{InvocationID: nextID(), Tool: "refund", Arguments: json.RawMessage(`{"customer":"customer1","amount":100}`)})
	if !errors.Is(err, gw.ErrCatalog) || u.calls != 0 || len(checker.seen) != 0 {
		t.Fatal("changed schema reached authorization or dispatch")
	}
}

func TestMissingAndErroredEngineFailsClosed(t *testing.T) {
	config, u, checker, _ := fixture(t)
	for _, engine := range []gw.Checker{nil, (*recordingChecker)(nil)} {
		config.Engine = engine
		if _, err := gw.New(config); !errors.Is(err, gw.ErrConfiguration) {
			t.Fatal("missing Engine accepted")
		}
	}
	config.Engine = checker
	checker.err = errors.New("fixture Engine unavailable")
	gateway, err := gw.New(config)
	must(t, err)
	id := identity(t, "alice", "agent", "task")
	call := gw.Call{InvocationID: nextID(), Tool: "refund", Arguments: json.RawMessage(`{"customer":"customer1","amount":100}`)}
	if _, err := gateway.Invoke(context.Background(), id, call); !errors.Is(err, gw.ErrEngine) {
		t.Fatal("Engine error did not fail closed")
	}
	if _, err := gateway.BatchCheck(context.Background(), id, []gw.Call{call}); !errors.Is(err, gw.ErrEngine) || u.calls != 0 {
		t.Fatal("batch Engine error authorized dispatch")
	}
}

func TestInvocationBindingCoversFullArgumentsIdentityAndConfig(t *testing.T) {
	config, _, checker, _ := fixture(t)
	readBinding := func(config gw.Config, actor, agent, task, args string) string {
		t.Helper()
		gateway, err := gw.New(config)
		must(t, err)
		_, err = gateway.Invoke(context.Background(), identity(t, actor, agent, task), gw.Call{InvocationID: nextID(), Tool: config.Tools[0].Name, Arguments: json.RawMessage(args)})
		must(t, err)
		got := checker.seen[len(checker.seen)-1].Attributes()["invocation_context"]
		if len(got) != 64 {
			t.Fatal("missing fixed-size invocation binding")
		}
		return got
	}
	args := `{"customer":"customer1","amount":20000,"memo":"first"}`
	base := readBinding(config, "alice", "agent", "task", args)
	if readBinding(config, "alice", "agent", "task", ` { "memo":"first", "amount":20000, "customer":"customer1" } `) != base {
		t.Fatal("JSON formatting changed canonical binding")
	}
	for _, tc := range []struct{ name, actor, agent, task, args string }{
		{"actor", "bob", "agent", "task", args},
		{"agent", "alice", "agent2", "task", args},
		{"task", "alice", "agent", "task2", args},
		{"amount", "alice", "agent", "task", `{"customer":"customer1","amount":20001,"memo":"first"}`},
		{"non-policy-argument", "alice", "agent", "task", `{"customer":"customer1","amount":20000,"memo":"second"}`},
		{"customer", "alice", "agent", "task", `{"customer":"customer2","amount":20000,"memo":"first"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if readBinding(config, tc.actor, tc.agent, tc.task, tc.args) == base {
				t.Fatal("changed invocation retained its binding")
			}
		})
	}
	for _, field := range []string{"connection", "config", "mapping", "tool"} {
		t.Run(field, func(t *testing.T) {
			changed := config
			changed.Tools = append([]gw.Tool(nil), config.Tools...)
			switch field {
			case "connection":
				changed.Tools[0].ConnectionID = "stripe2"
			case "config":
				changed.Tools[0].ConfigVersion = "v2"
			case "mapping":
				changed.Tools[0].MappingVersion = "v2"
			case "tool":
				changed.Tools[0].Name = "refund2"
			}
			if readBinding(changed, "alice", "agent", "task", args) == base {
				t.Fatal("changed configuration retained its binding")
			}
		})
	}
}

func TestBatchCheckUsesPinnedEngineResultsWithoutDispatch(t *testing.T) {
	config, u, checker, revision := fixture(t)
	gateway, err := gw.New(config)
	must(t, err)
	calls := []gw.Call{}
	for _, amount := range []int{10000, 10001, 50001} {
		calls = append(calls, gw.Call{InvocationID: nextID(), Tool: "refund", Arguments: json.RawMessage(fmt.Sprintf(`{"customer":"customer1","amount":%d}`, amount))})
	}
	results, err := gateway.BatchCheck(context.Background(), identity(t, "alice", "agent", "task"), calls)
	must(t, err)
	if len(results) != 3 || len(checker.seen) != 1 || u.calls != 0 {
		t.Fatal("batch did not evaluate once without dispatch")
	}
	for i, want := range []pe.Decision{pe.DecisionAllow, pe.DecisionRequireApproval, pe.DecisionDeny} {
		if results[i].Decision() != want || results[i].RevisionID() != revision || results[i].DataGeneration() != 1 || results[i].SlotGeneration() != 1 || !results[i].EvaluatedAt().Equal(results[0].EvaluatedAt()) {
			t.Fatal("batch lost its pinned evaluation or ordering")
		}
	}
}

var invocationCounter atomic.Uint64

func nextID() string { return fmt.Sprintf("fixture-call-%016d", invocationCounter.Add(1)) }
func testJournal(t *testing.T) *journalsqlite.Store {
	t.Helper()
	dir := t.TempDir()
	must(t, os.Chmod(dir, 0700))
	store, err := journalsqlite.Open(filepath.Join(dir, "journal.db"))
	must(t, err)
	t.Cleanup(func() { must(t, store.Close()) })
	return store
}

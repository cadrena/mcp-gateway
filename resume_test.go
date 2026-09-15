package mcpgateway_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cadrena/dsl"
	gw "github.com/cadrena/mcp-gateway"
	"github.com/cadrena/mcp-gateway/journal"
	pe "github.com/cadrena/policy-engine"
	"github.com/cadrena/policy-engine/embedded"
	"github.com/cadrena/policy-engine/store/memory"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type resumeTxKey struct{}
type resumeVerifier struct{ want [32]byte }

func (v *resumeVerifier) VerifyApproval(ctx context.Context, r pe.ApprovalVerificationRequest) (pe.ApprovalVerificationResult, error) {
	digest, valid := r.Binding().AuthorizationDigest()
	if ctx.Value(resumeTxKey{}) != true || !valid || digest != v.want || string(r.Evidence()) != "trusted-evidence" {
		return pe.ApprovalVerificationResult{}, errors.New("invalid fixture approval")
	}
	return pe.NewApprovalVerificationResult(r.RequirementIDs())
}

type resumeUpstream struct {
	calls       atomic.Int32
	reads       atomic.Int32
	networkInTx atomic.Bool
	unknown     bool
}

func (u *resumeUpstream) ListTools(ctx context.Context) ([]*mcp.Tool, error) {
	if ctx.Value(resumeTxKey{}) != nil {
		u.networkInTx.Store(true)
	}
	return []*mcp.Tool{{Name: "refund_remote", InputSchema: json.RawMessage(refundSchema)}}, nil
}
func (u *resumeUpstream) Validate(ctx context.Context, _ json.RawMessage) error {
	u.reads.Add(1)
	if ctx.Value(resumeTxKey{}) != nil {
		u.networkInTx.Store(true)
	}
	return nil
}
func (u *resumeUpstream) CallTool(ctx context.Context, _ string, _ json.RawMessage) (*mcp.CallToolResult, error) {
	u.calls.Add(1)
	if ctx.Value(resumeTxKey{}) != nil {
		u.networkInTx.Store(true)
	}
	if u.unknown {
		return nil, errors.New("fixture timeout")
	}
	return &mcp.CallToolResult{StructuredContent: map[string]any{"status": "succeeded"}}, nil
}

type testBoundary struct {
	store  journal.Store
	mode   string
	late   func(context.Context) (gw.Authorization, error)
	cancel context.CancelFunc
}

func (b *testBoundary) WithinAuthorization(ctx context.Context, check func(context.Context) (gw.Authorization, error)) (journal.Lease, error) {
	b.late = check
	if b.mode == "skip" {
		return journal.Lease{}, nil
	}
	if b.cancel != nil {
		b.cancel()
	}
	auth, err := check(context.WithValue(context.Background(), resumeTxKey{}, true))
	if err != nil {
		return journal.Lease{}, err
	}
	if b.mode == "double" {
		_, _ = check(ctx)
	}
	if b.mode == "rollback" {
		return journal.Lease{}, errors.New("fixture rollback")
	}
	if b.mode == "wrong" {
		auth.Record.Digest[0] ^= 1
	}
	if b.mode == "forged" {
		issuer, err := journal.NewIssuer()
		if err != nil {
			return journal.Lease{}, err
		}
		return issuer.Issue(auth.Record.Key, auth.Record.Digest), nil
	}
	lease, err := b.store.Authorize(ctx, auth.Record)
	if b.mode == "commit-error" {
		return lease, errors.New("uncertain commit")
	}
	return lease, err
}
func resumeFixture(t *testing.T, verifier *resumeVerifier) (gw.Config, *resumeUpstream) {
	t.Helper()
	ctx := context.Background()
	storage, err := memory.New()
	must(t, err)
	engine, err := embedded.New(embedded.WithStore(storage), embedded.WithCallerAuthorizer(fixtureAuthorizer{}), embedded.WithApprovalVerifier(verifier))
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
	u := &resumeUpstream{}
	config := gw.Config{Namespace: "tenant", CallerID: "gateway", Slot: "active", Engine: engine, Journal: testJournal(t), Tools: []gw.Tool{{Name: "refund", RemoteName: "refund_remote", ConnectionID: "stripe", ConfigVersion: "v1", MappingVersion: "v1", Action: "refund", ResourceType: "customer", ResourceArgument: "customer", Schema: json.RawMessage(refundSchema), Upstream: u}}}
	return config, u
}

func pendingResume(t *testing.T, g *gw.Gateway, v *resumeVerifier) (gw.Identity, gw.Call, gw.Approval) {
	t.Helper()
	who := identity(t, "alice", "agent", "task")
	call := gw.Call{InvocationID: nextID(), Tool: "refund", Arguments: json.RawMessage(`{"customer":"customer1","amount":25000}`)}
	result, err := g.Invoke(context.Background(), who, call)
	must(t, err)
	digest, ok := result.Decision.ApprovalBindingDigest()
	if !ok || result.InvocationKey == ([32]byte{}) || result.RequestDigest == ([32]byte{}) {
		t.Fatal("missing pending binding")
	}
	v.want = digest
	return who, call, gw.Approval{Evidence: []byte("trusted-evidence"), BindingDigest: digest}
}
func TestResumeRealEngineCommitThenDispatch(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		v := &resumeVerifier{}
		config, u := resumeFixture(t, v)
		u.unknown = unknown
		g, err := gw.New(config)
		must(t, err)
		who, call, approval := pendingResume(t, g, v)
		b := &testBoundary{store: config.Journal}
		result, err := g.Resume(context.Background(), who, call, approval, b)
		if unknown {
			if !errors.Is(err, gw.ErrUpstream) || result.State != journal.OutcomeUnknown {
				t.Fatal("uncertain outcome lost")
			}
		} else {
			must(t, err)
			if result.State != journal.Completed {
				t.Fatal("dispatch not complete")
			}
		}
		if u.calls.Load() != 1 || u.reads.Load() != 1 || u.networkInTx.Load() {
			t.Fatal("network ordering violated")
		}
		_, err = g.Resume(context.Background(), who, call, approval, b)
		if !errors.Is(err, gw.ErrReplay) || u.calls.Load() != 1 {
			t.Fatal("resume replay dispatched")
		}
		if _, err = b.late(context.Background()); !errors.Is(err, gw.ErrAuthorizationBoundary) {
			t.Fatal("late callback accepted")
		}
	}
}
func TestResumeRejectsBrokenBoundary(t *testing.T) {
	for _, mode := range []string{"skip", "double", "rollback", "commit-error", "wrong", "forged", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			v := &resumeVerifier{}
			config, u := resumeFixture(t, v)
			g, err := gw.New(config)
			must(t, err)
			who, call, approval := pendingResume(t, g, v)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			b := &testBoundary{store: config.Journal, mode: mode}
			if mode == "cancel" {
				b.cancel = cancel
			}
			if _, err = g.Resume(ctx, who, call, approval, b); err == nil {
				t.Fatal("broken boundary accepted")
			}
			if u.calls.Load() != 0 {
				t.Fatal("broken boundary dispatched")
			}
		})
	}
}
func TestResumeRejectsChangedApproval(t *testing.T) {
	for _, change := range []string{"binding", "evidence", "actor", "arguments", "task", "config", "allow", "deny"} {
		t.Run(change, func(t *testing.T) {
			v := &resumeVerifier{}
			config, u := resumeFixture(t, v)
			g, err := gw.New(config)
			must(t, err)
			who, call, approval := pendingResume(t, g, v)
			switch change {
			case "binding":
				approval.BindingDigest[0] ^= 1
			case "evidence":
				approval.Evidence = []byte("changed")
			case "actor":
				who = identity(t, "bob", "agent", "task")
			case "task":
				who = identity(t, "alice", "agent", "other")
			case "arguments":
				call.Arguments = json.RawMessage(`{"customer":"customer1","amount":25001}`)
			case "config":
				config.Tools[0].ConfigVersion = "v2"
				g, err = gw.New(config)
				must(t, err)
			case "allow":
				call.Arguments = json.RawMessage(`{"customer":"customer1","amount":100}`)
			case "deny":
				call.Arguments = json.RawMessage(`{"customer":"customer1","amount":50001}`)
			}
			if _, err = g.Resume(context.Background(), who, call, approval, &testBoundary{store: config.Journal}); err == nil {
				t.Fatal("changed approval accepted")
			}
			if u.calls.Load() != 0 {
				t.Fatal("changed approval dispatched")
			}
			if change != "evidence" && u.reads.Load() != 0 {
				t.Fatal("invalid base approval probed payment")
			}
		})
	}
}
func TestResumeConcurrentDuplicate(t *testing.T) {
	v := &resumeVerifier{}
	config, u := resumeFixture(t, v)
	g, err := gw.New(config)
	must(t, err)
	who, call, approval := pendingResume(t, g, v)
	var wg sync.WaitGroup
	var wins atomic.Int32
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := g.Resume(context.Background(), who, call, approval, &testBoundary{store: config.Journal})
			if err == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 || u.calls.Load() != 1 {
		t.Fatal("duplicate continuation dispatched")
	}
}

type boundaryFunc func(context.Context, func(context.Context) (gw.Authorization, error)) (journal.Lease, error)

func (f boundaryFunc) WithinAuthorization(ctx context.Context, check func(context.Context) (gw.Authorization, error)) (journal.Lease, error) {
	return f(ctx, check)
}

type blockedResumeChecker struct {
	gw.Checker
	started, release chan struct{}
}

func (b *blockedResumeChecker) Check(ctx context.Context, caller pe.Caller, request pe.CheckRequest) (pe.CheckResponse, error) {
	if len(request.ApprovalEvidence()) > 0 {
		close(b.started)
		<-b.release
	}
	return b.Checker.Check(ctx, caller, request)
}
func TestResumeRejectsInFlightCallback(t *testing.T) {
	v := &resumeVerifier{}
	config, u := resumeFixture(t, v)
	blocked := &blockedResumeChecker{Checker: config.Engine, started: make(chan struct{}), release: make(chan struct{})}
	config.Engine = blocked
	g, err := gw.New(config)
	must(t, err)
	who, call, approval := pendingResume(t, g, v)
	callbackDone := make(chan error, 1)
	boundary := boundaryFunc(func(ctx context.Context, check func(context.Context) (gw.Authorization, error)) (journal.Lease, error) {
		go func() { _, err := check(context.WithValue(ctx, resumeTxKey{}, true)); callbackDone <- err }()
		<-blocked.started
		return journal.Lease{}, nil
	})
	if _, err = g.Resume(context.Background(), who, call, approval, boundary); !errors.Is(err, gw.ErrAuthorizationBoundary) {
		t.Fatal("unfinished callback accepted")
	}
	close(blocked.release)
	if err := <-callbackDone; err == nil {
		t.Fatal("callback completed after boundary returned")
	}
	if u.calls.Load() != 0 {
		t.Fatal("unfinished callback dispatched")
	}
}
func TestResumeRejectsPolicyDrift(t *testing.T) {
	v := &resumeVerifier{}
	config, u := resumeFixture(t, v)
	g, err := gw.New(config)
	must(t, err)
	who, call, approval := pendingResume(t, g, v)
	engine := config.Engine.(pe.Engine)
	caller, err := pe.NewCaller("seed", nil)
	must(t, err)
	// A data generation change invalidates approval while the original relation remains.
	tuple, err := pe.NewRelationshipTuple(dsl.Tuple{Resource: dsl.EntityRef{Type: "customer", ID: "customer2"}, Relation: "operator", Subject: dsl.SubjectRef{Type: "user", ID: "alice"}}, nil)
	must(t, err)
	original, err := g.Invoke(context.Background(), who, call)
	must(t, err)
	write, err := pe.NewWriteDataRequest(pe.WriteDataRequestInput{Namespace: "tenant", ValidationRevisionID: original.Decision.RevisionID(), ExpectedGeneration: original.Decision.DataGeneration(), IdempotencyKey: "drift", TupleWrites: []pe.RelationshipTuple{tuple}})
	must(t, err)
	_, err = engine.WriteData(context.Background(), caller, write)
	must(t, err)
	if _, err = g.Resume(context.Background(), who, call, approval, &testBoundary{store: config.Journal}); !errors.Is(err, gw.ErrApproval) {
		t.Fatal("data generation drift accepted")
	}
	if u.calls.Load() != 0 || u.reads.Load() != 0 {
		t.Fatal("stale approval reached network validation")
	}
}

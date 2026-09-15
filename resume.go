package mcpgateway

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/cadrena/mcp-gateway/journal"
	pe "github.com/cadrena/policy-engine"
)

var ErrApproval = errors.New("approval continuation invalid")
var ErrAuthorizationBoundary = errors.New("authorization boundary invalid")

// Approval contains trusted host evidence for one saved require-approval result.
// MCP arguments and request metadata cannot populate this value.
type Approval struct {
	Evidence      []byte
	BindingDigest [32]byte
}

func (Approval) String() string               { return "[approval]" }
func (Approval) GoString() string             { return "[approval]" }
func (Approval) MarshalJSON() ([]byte, error) { return []byte(`"[approval]"`), nil }

// Authorization is the bounded result the host commits with its private state.
type Authorization struct {
	Decision pe.DecisionResult
	Record   journal.Record
}

// AuthorizationBoundary runs check exactly once, synchronously, with a private
// transaction context. Its Engine verifier must use that context to consume the
// exact grant. The boundary commits grant consumption, Record, invocation,
// durable audit and outbox together, then issues a lease from the configured
// journal adapter. Any commit error, including an uncertain commit, returns an
// error and prevents dispatch. No network calls belong inside this transaction.
// The host must check current identity, approver authority, expiry and config
// during this transaction, and again inside journal.Start before dispatch.
type AuthorizationBoundary interface {
	WithinAuthorization(context.Context, func(context.Context) (Authorization, error)) (journal.Lease, error)
}

// Resume continues only a matching approval through a trusted host transaction.
// It never accepts an earlier ALLOW or a changed current policy as an approval.
// Invoke and its MCP endpoint remain evidence-free and retain their behavior.
func (g *Gateway) Resume(ctx context.Context, identity Identity, call Call, approval Approval, boundary AuthorizationBoundary) (Result, error) {
	if ctx == nil || g == nil || nilPort(boundary) || len(approval.Evidence) == 0 || len(approval.Evidence) > pe.MaxEvidenceBytes || approval.BindingDigest == ([32]byte{}) {
		return Result{}, ErrApproval
	}
	if len(call.InvocationID) < 16 || len(call.InvocationID) > 128 || !toolName.MatchString(call.InvocationID) {
		return Result{}, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	call.Arguments = append(json.RawMessage(nil), call.Arguments...)
	evidence := append([]byte(nil), approval.Evidence...)
	p, err := g.prepare(ctx, identity, call)
	if err != nil {
		return Result{}, err
	}
	keyData, _ := json.Marshal([]string{"cadrena-dispatch-v1", g.namespace, g.callerID, call.InvocationID})
	key := sha256.Sum256(keyData)
	digest := sha256.Sum256(p.envelope)
	record, err := g.journal.Lookup(ctx, key)
	if err == nil {
		if record.Digest != digest {
			return Result{}, ErrConflict
		}
		return Result{State: record.State, Replayed: true, InvocationKey: key, RequestDigest: digest}, ErrReplay
	}
	if !errors.Is(err, journal.ErrNotFound) {
		return Result{}, ErrJournal
	}
	caller, err := g.caller(p.envelope)
	if err != nil {
		return Result{}, ErrEngine
	}
	preRequest, err := pe.NewCheckRequest(p.input)
	if err != nil {
		return Result{}, ErrInput
	}
	preResponse, err := g.engine.Check(ctx, caller, preRequest)
	if err != nil {
		return Result{}, ErrEngine
	}
	result := Result{Decision: preResponse.Result(), InvocationKey: key, RequestDigest: digest}
	actual, valid := result.Decision.ApprovalBindingDigest()
	if result.Decision.Decision() != pe.DecisionRequireApproval || !valid || actual != approval.BindingDigest {
		return result, ErrApproval
	}
	// A matching base decision proves current resource access before read preflight.
	// It still grants no mutation. The final Check repeats inside the transaction.
	if validator, ok := p.tool.config.Upstream.(Validator); ok {
		if err := validator.Validate(ctx, append(json.RawMessage(nil), p.args...)); err != nil {
			return result, ErrInput
		}
	}
	input := p.input
	input.ApprovalEvidence = evidence
	request, err := pe.NewCheckRequest(input)
	if err != nil {
		return result, ErrApproval
	}
	var mu sync.Mutex
	live, called, done, violation := true, false, false, false
	var evaluated Authorization
	var checkErr error
	callback := func(txCtx context.Context) (Authorization, error) {
		mu.Lock()
		if !live || called || txCtx == nil {
			violation = true
			mu.Unlock()
			return Authorization{}, ErrAuthorizationBoundary
		}
		called = true
		mu.Unlock()
		// Preserve private context values while linking the original deadline and cancel.
		checkCtx, stop := context.WithCancel(txCtx)
		stopOriginal := context.AfterFunc(ctx, stop)
		defer stop()
		defer stopOriginal()
		var auth Authorization
		err := ctx.Err()
		if err == nil {
			var response pe.CheckResponse
			response, err = g.engine.Check(checkCtx, caller, request)
			if err == nil {
				decision := response.Result()
				if decision.Decision() != pe.DecisionAllow || !decision.UsedApproval() {
					err = ErrApproval
				} else {
					auth = Authorization{Decision: decision, Record: journal.Record{Key: key, Digest: digest, State: journal.Authorized, Outcome: journal.Unknown, DecisionID: decision.DecisionID(), RevisionID: decision.RevisionID()}}
				}
			}
		}
		if err == nil {
			err = ctx.Err()
		}
		mu.Lock()
		defer mu.Unlock()
		if !live {
			return Authorization{}, ErrAuthorizationBoundary
		}
		evaluated, checkErr, done = auth, err, true
		return auth, err
	}
	lease, boundaryErr := boundary.WithinAuthorization(ctx, callback)
	mu.Lock()
	live = false
	complete := called && done && !violation && checkErr == nil
	auth := evaluated
	mu.Unlock()
	if boundaryErr != nil {
		return result, boundaryErr
	}
	if !complete {
		return result, ErrAuthorizationBoundary
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if !lease.Matches(key, digest) {
		return result, ErrAuthorizationBoundary
	}
	result.Decision = auth.Decision
	return g.dispatch(ctx, p, key, lease, result)
}

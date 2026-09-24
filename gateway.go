package mcpgateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"time"

	"github.com/cadrena/dsl"
	"github.com/cadrena/mcp-gateway/internal/catalog"
	"github.com/cadrena/mcp-gateway/invocation"
	"github.com/cadrena/mcp-gateway/journal"
	pe "github.com/cadrena/policy-engine"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var (
	ErrConfiguration = errors.New("gateway configuration invalid")
	ErrIdentity      = errors.New("trusted identity required")
	ErrInput         = errors.New("tool input invalid")
	ErrCatalog       = errors.New("tool catalog mismatch")
	ErrEngine        = errors.New("authorization unavailable")
	ErrUpstream      = errors.New("upstream outcome unavailable")
	ErrJournal       = errors.New("durable journal unavailable")
	ErrReplay        = journal.ErrReplay
	ErrConflict      = journal.ErrConflict
)

var identifier = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)
var toolName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

// Identity is created by trusted host authentication, never from tool arguments.
// Its constructor validates shape; the host remains responsible for authentication.
type Identity struct{ actor, agent, task string }

func NewIdentity(actor, agent, task string) (Identity, error) {
	for _, value := range []string{actor, agent, task} {
		if !identifier.MatchString(value) {
			return Identity{}, ErrIdentity
		}
	}
	return Identity{actor, agent, task}, nil
}

func (i Identity) String() string { return "[gateway identity]" }

// Checker is the public Engine port. Errors never authorize dispatch.
type Checker interface {
	Check(context.Context, pe.Caller, pe.CheckRequest) (pe.CheckResponse, error)
	BatchCheck(context.Context, pe.Caller, pe.BatchCheckRequest) (pe.BatchCheckResponse, error)
}

// Upstream is a trusted host port. Use transport.Client for remote MCP servers.
type Upstream interface {
	ListTools(context.Context) ([]*mcp.Tool, error)
	CallTool(context.Context, string, json.RawMessage) (*mcp.CallToolResult, error)
}

// Tool fixes a remote tool to one authorization mapping and schema.
type Tool struct {
	Name, RemoteName, ConnectionID, ConfigVersion, MappingVersion string
	Action, ResourceType, ResourceArgument                        string
	Schema                                                        json.RawMessage
	Upstream                                                      Upstream
}

type Config struct {
	Namespace, CallerID, Slot string
	Engine                    Checker
	Tools                     []Tool
	Journal                   journal.Store
}

type pinnedTool struct {
	config Tool
	schema *catalog.Schema
}

// Gateway is immutable after construction. Hosts must replace it on config changes.
type Gateway struct {
	namespace, callerID string
	selector            pe.Selector
	engine              Checker
	tools               map[string]pinnedTool
	journal             journal.Store
}

func nilPort(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Map, reflect.Func, reflect.Slice:
		return r.IsNil()
	}
	return false
}

func New(config Config) (*Gateway, error) {
	if nilPort(config.Journal) || nilPort(config.Engine) || len(config.Tools) == 0 || len(config.Tools) > 64 {
		return nil, ErrConfiguration
	}
	for _, s := range []string{config.Namespace, config.CallerID, config.Slot} {
		if !identifier.MatchString(s) {
			return nil, ErrConfiguration
		}
	}
	selector, err := pe.NewSelector(config.Slot, "")
	if err != nil {
		return nil, ErrConfiguration
	}
	g := &Gateway{namespace: config.Namespace, callerID: config.CallerID, selector: selector, engine: config.Engine, tools: make(map[string]pinnedTool), journal: config.Journal}
	for _, tool := range config.Tools {
		if !toolName.MatchString(tool.Name) || !toolName.MatchString(tool.RemoteName) || nilPort(tool.Upstream) {
			return nil, ErrConfiguration
		}
		if _, exists := g.tools[tool.Name]; exists {
			return nil, ErrConfiguration
		}
		for _, s := range []string{tool.ConnectionID, tool.ConfigVersion, tool.MappingVersion, tool.Action, tool.ResourceType, tool.ResourceArgument} {
			if !identifier.MatchString(s) {
				return nil, ErrConfiguration
			}
		}
		schema, err := catalog.New(tool.Schema)
		if err != nil {
			return nil, ErrConfiguration
		}
		tool.Schema = append(json.RawMessage(nil), tool.Schema...)
		g.tools[tool.Name] = pinnedTool{tool, schema}
	}
	return g, nil
}

// Call combines a host request identifier with model tool data.
// The host must reuse InvocationID for retries. Models must not select it.
type Call struct {
	InvocationID string
	Tool         string
	Arguments    json.RawMessage
}

func (c Call) String() string { return "[gateway call]" }

type Result struct {
	// InvocationKey and RequestDigest are trusted host metadata, not execution authority.
	// The HTTP handler does not expose these fields to MCP clients.
	InvocationKey, RequestDigest [32]byte
	Decision                     pe.DecisionResult
	// DecisionDuration measures only the Engine Check call. It excludes upstream
	// validation, journal work, and tool execution.
	DecisionDuration time.Duration
	State            journal.State
	Replayed         bool
	// Output is untrusted upstream content. It is absent for DENY and REQUIRE_APPROVAL.
	Output *mcp.CallToolResult
}

type prepared struct {
	tool     pinnedTool
	args     json.RawMessage
	input    pe.CheckRequestInput
	envelope []byte
}

func (g *Gateway) prepare(ctx context.Context, identity Identity, call Call) (prepared, error) {
	if g == nil {
		return prepared{}, ErrConfiguration
	}
	if _, err := NewIdentity(identity.actor, identity.agent, identity.task); err != nil {
		return prepared{}, err
	}
	if err := ctx.Err(); err != nil {
		return prepared{}, err
	}
	tool, found := g.tools[call.Tool]
	if !found {
		return prepared{}, ErrCatalog
	}
	args, values, err := tool.schema.Validate(call.Arguments)
	if err != nil {
		return prepared{}, ErrInput
	}
	resource, ok := values[tool.config.ResourceArgument].StringValue()
	if !ok || resource == "" {
		return prepared{}, ErrInput
	}
	listed, err := tool.config.Upstream.ListTools(ctx)
	if err != nil || len(listed) > 256 {
		return prepared{}, ErrCatalog
	}
	count := 0
	for _, remote := range listed {
		if remote == nil {
			return prepared{}, ErrCatalog
		}
		if remote.Name != tool.config.RemoteName {
			continue
		}
		count++
		raw, err := json.Marshal(remote.InputSchema)
		if err != nil {
			return prepared{}, ErrCatalog
		}
		actual, err := catalog.New(raw)
		if err != nil || actual.Hash() != tool.schema.Hash() {
			return prepared{}, ErrCatalog
		}
	}
	if count != 1 {
		return prepared{}, ErrCatalog
	}
	hash := tool.schema.Hash()
	// A fixed JSON tuple prevents ambiguous concatenation and binds every argument.
	envelope, err := json.Marshal([]any{"cadrena-invocation-v1", g.namespace, identity.actor, identity.agent, identity.task, tool.config.ConnectionID, tool.config.ConfigVersion, tool.config.Name, tool.config.RemoteName, hex.EncodeToString(hash[:]), tool.config.MappingVersion, tool.config.Action, tool.config.ResourceType, tool.config.ResourceArgument, json.RawMessage(args)})
	if err != nil {
		return prepared{}, ErrInput
	}
	data, err := pe.NewContextualData(nil, nil)
	if err != nil {
		return prepared{}, ErrEngine
	}
	return prepared{tool, args, pe.CheckRequestInput{Namespace: g.namespace, Selector: g.selector, Subject: dsl.EntityRef{Type: "user", ID: identity.actor}, Resource: dsl.EntityRef{Type: tool.config.ResourceType, ID: resource}, Action: tool.config.Action, Arguments: values, ContextualData: data}, envelope}, nil
}

func (g *Gateway) caller(envelope []byte) (pe.Caller, error) {
	digest := sha256.Sum256(envelope)
	return pe.NewCaller(g.callerID, map[string]string{"invocation_context": hex.EncodeToString(digest[:])})
}

// Validator is an optional trusted read port for payment ownership and bounds.
// It must not perform mutations. Arguments are already canonical and typed.
type Validator interface {
	Validate(context.Context, json.RawMessage) error
}

// Invoke performs one journal-backed execution attempt.
// The same retained invocation ID never creates another dispatch.
// Approval continuation requires the private transaction workflow and is not accepted here.
func (g *Gateway) Invoke(ctx context.Context, identity Identity, call Call) (Result, error) {
	if len(call.InvocationID) < 16 || len(call.InvocationID) > 128 || !toolName.MatchString(call.InvocationID) {
		return Result{}, ErrInput
	}
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
	request, err := pe.NewCheckRequest(p.input)
	if err != nil {
		return Result{}, ErrInput
	}
	decisionStarted := time.Now()
	response, err := g.engine.Check(ctx, caller, request)
	decisionDuration := time.Since(decisionStarted)
	if err != nil {
		return Result{}, ErrEngine
	}
	result := Result{Decision: response.Result(), DecisionDuration: decisionDuration, InvocationKey: key, RequestDigest: digest}
	switch result.Decision.Decision() {
	case pe.DecisionDeny, pe.DecisionRequireApproval:
		return result, nil
	case pe.DecisionAllow:
	default:
		return Result{}, ErrEngine
	}
	// Read validation follows authorization, so denied users cannot probe payment data.
	if validator, ok := p.tool.config.Upstream.(Validator); ok {
		if err := validator.Validate(ctx, append(json.RawMessage(nil), p.args...)); err != nil {
			return result, ErrInput
		}
	}
	lease, err := g.journal.Authorize(ctx, journal.Record{Key: key, Digest: digest, State: journal.Authorized, Outcome: journal.Unknown, DecisionID: result.Decision.DecisionID(), RevisionID: result.Decision.RevisionID()})
	if err != nil {
		if errors.Is(err, journal.ErrReplay) || errors.Is(err, journal.ErrConflict) {
			return result, err
		}
		return result, ErrJournal
	}
	return g.dispatch(ctx, p, key, lease, result)
}

// dispatch remains private: callers must first commit authorization.
func (g *Gateway) dispatch(ctx context.Context, p prepared, key [32]byte, lease journal.Lease, result Result) (Result, error) {
	result.State = journal.Authorized
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if err := g.journal.Start(ctx, lease); err != nil {
		return result, ErrJournal
	}
	result.State = journal.DispatchStarted
	dispatchCtx, err := invocation.WithKey(ctx, hex.EncodeToString(key[:]))
	if err != nil {
		return result, ErrJournal
	}
	output, dispatchErr := p.tool.config.Upstream.CallTool(dispatchCtx, p.tool.config.RemoteName, append(json.RawMessage(nil), p.args...))
	state, outcome := journal.Completed, journal.Success
	if dispatchErr != nil || output == nil {
		state, outcome = journal.OutcomeUnknown, journal.Unknown
	} else if output.IsError {
		outcome = journal.Failure
	} else if content, ok := output.StructuredContent.(map[string]any); ok {
		switch content["status"] {
		case "pending":
			outcome = journal.Pending
		case "failed", "canceled":
			outcome = journal.Failure
		}
	}
	// Persist failure even when the caller cancelled or the upstream timed out.
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := g.journal.Finish(finishCtx, lease, state, outcome); err != nil {
		result.State = journal.OutcomeUnknown
		return result, ErrJournal
	}
	result.State = state
	if dispatchErr != nil || output == nil {
		return result, ErrUpstream
	}
	result.Output = output
	return result, nil
}

// BatchCheck evaluates a bounded batch under one Engine snapshot. It never dispatches.
// Each identity and full tool envelope contributes to the common caller binding.
func (g *Gateway) BatchCheck(ctx context.Context, identity Identity, calls []Call) ([]pe.DecisionResult, error) {
	if len(calls) == 0 || len(calls) > 16 {
		return nil, ErrInput
	}
	items := make([]pe.BatchCheckItem, 0, len(calls))
	envelopes := make([]json.RawMessage, 0, len(calls))
	for _, call := range calls {
		p, err := g.prepare(ctx, identity, call)
		if err != nil {
			return nil, err
		}
		item, err := pe.NewBatchCheckItem(p.input.Subject, p.input.Resource, p.input.Action, p.input.Arguments)
		if err != nil {
			return nil, ErrInput
		}
		items = append(items, item)
		envelopes = append(envelopes, p.envelope)
	}
	raw, err := json.Marshal(envelopes)
	if err != nil {
		return nil, ErrInput
	}
	caller, err := g.caller(raw)
	if err != nil {
		return nil, ErrEngine
	}
	data, _ := pe.NewContextualData(nil, nil)
	request, err := pe.NewBatchCheckRequest(pe.BatchCheckRequestInput{Namespace: g.namespace, Selector: g.selector, Items: items, ContextualData: data})
	if err != nil {
		return nil, ErrInput
	}
	response, err := g.engine.BatchCheck(ctx, caller, request)
	if err != nil {
		return nil, ErrEngine
	}
	results := response.Results()
	if len(results) != len(calls) {
		return nil, ErrEngine
	}
	for _, r := range results {
		switch r.Decision() {
		case pe.DecisionAllow, pe.DecisionDeny, pe.DecisionRequireApproval:
		default:
			return nil, ErrEngine
		}
	}
	return results, nil
}

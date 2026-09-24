package mcpgateway_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	gw "github.com/cadrena/mcp-gateway"
	"github.com/cadrena/mcp-gateway/invocation"
	"github.com/cadrena/mcp-gateway/journal"
	journalsqlite "github.com/cadrena/mcp-gateway/journal/sqlite"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var errDurableFault = errors.New("injected durable boundary failure")

// faultJournal wraps actual SQLite commits; error injection models a lost reply.
// It does not simulate a filesystem fault or a killed process.
type faultJournal struct {
	journal.Store
	phase   string
	applied bool
	mu      sync.Mutex
	record  journal.Record
}

func (s *faultJournal) Authorize(ctx context.Context, record journal.Record) (journal.Lease, error) {
	s.mu.Lock()
	s.record = record
	s.mu.Unlock()
	if s.phase == "authorize" && !s.applied {
		return journal.Lease{}, errDurableFault
	}
	lease, err := s.Store.Authorize(ctx, record)
	if err == nil && s.phase == "authorize" {
		return lease, errDurableFault
	}
	return lease, err
}

func (s *faultJournal) Start(ctx context.Context, lease journal.Lease) error {
	if s.phase == "start" && !s.applied {
		return errDurableFault
	}
	err := s.Store.Start(ctx, lease)
	if err == nil && s.phase == "start" {
		return errDurableFault
	}
	return err
}

func (s *faultJournal) Finish(ctx context.Context, lease journal.Lease, state journal.State, outcome journal.Outcome) error {
	if s.phase == "finish" && !s.applied {
		return errDurableFault
	}
	err := s.Store.Finish(ctx, lease, state, outcome)
	if err == nil && s.phase == "finish" {
		return errDurableFault
	}
	return err
}

func (s *faultJournal) recordedKey() [32]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.record.Key
}

type durableUpstream struct {
	calls atomic.Int32
	call  func(context.Context) (*mcp.CallToolResult, error)
}

func (*durableUpstream) ListTools(context.Context) ([]*mcp.Tool, error) {
	return []*mcp.Tool{{Name: "refund_remote", InputSchema: json.RawMessage(refundSchema)}}, nil
}

func (u *durableUpstream) CallTool(ctx context.Context, _ string, _ json.RawMessage) (*mcp.CallToolResult, error) {
	u.calls.Add(1)
	if u.call != nil {
		return u.call(ctx)
	}
	return &mcp.CallToolResult{StructuredContent: map[string]any{"status": "succeeded"}}, nil
}

func durableFixture(t *testing.T) (gw.Config, *faultJournal, *durableUpstream) {
	t.Helper()
	config, _, checker, _ := fixture(t)
	// Bypass the nonconcurrent recording fixture for contention tests.
	config.Engine = checker.inner
	s := &faultJournal{Store: config.Journal}
	u := &durableUpstream{}
	config.Journal = s
	config.Tools[0].Upstream = u
	return config, s, u
}

func durableCall() gw.Call {
	return gw.Call{InvocationID: "invocation-fixture-0001", Tool: "refund", Arguments: json.RawMessage(`{"customer":"customer1","amount":100}`)}
}

func TestDurableInvokeCommitsBeforeDispatchAndRejectsReplay(t *testing.T) {
	config, s, u := durableFixture(t)
	u.call = func(ctx context.Context) (*mcp.CallToolResult, error) {
		key := s.recordedKey()
		record, err := s.Lookup(context.Background(), key)
		if err != nil || record.State != journal.DispatchStarted || record.Outcome != journal.Unknown {
			t.Error("upstream ran before dispatch commit")
		}
		if got, ok := invocation.Key(ctx); !ok || got != hex.EncodeToString(key[:]) {
			t.Error("upstream did not receive the durable dispatch key")
		}
		return &mcp.CallToolResult{}, nil
	}
	g, err := gw.New(config)
	must(t, err)
	id := identity(t, "alice", "agent", "task")
	result, err := g.Invoke(context.Background(), id, durableCall())
	must(t, err)
	record, err := s.Lookup(context.Background(), s.recordedKey())
	must(t, err)
	if result.State != journal.Completed || record.State != journal.Completed || record.Outcome != journal.Success || u.calls.Load() != 1 {
		t.Fatal("successful result was not persisted")
	}
	result, err = g.Invoke(context.Background(), id, durableCall())
	if !errors.Is(err, gw.ErrReplay) || !result.Replayed || result.State != journal.Completed || result.DecisionDuration != 0 || u.calls.Load() != 1 {
		t.Fatal("repeated invocation created another dispatch")
	}
	changed := durableCall()
	changed.Arguments = json.RawMessage(`{"customer":"customer1","amount":101}`)
	if _, err = g.Invoke(context.Background(), id, changed); !errors.Is(err, gw.ErrConflict) || u.calls.Load() != 1 {
		t.Fatal("changed arguments reused an invocation key")
	}
}

func TestDurableConcurrentWorkersDispatchOnce(t *testing.T) {
	config, _, u := durableFixture(t)
	g, err := gw.New(config)
	must(t, err)
	id := identity(t, "alice", "agent", "task")
	var wg sync.WaitGroup
	var winners atomic.Int32
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := g.Invoke(context.Background(), id, durableCall())
			if err == nil {
				winners.Add(1)
			} else if !errors.Is(err, gw.ErrReplay) {
				t.Errorf("unexpected duplicate worker result: %v", err)
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 || u.calls.Load() != 1 {
		t.Fatalf("winners=%d dispatches=%d", winners.Load(), u.calls.Load())
	}
}

func TestDurableCommitErrorsDoNotPermitUnsafeDispatch(t *testing.T) {
	for _, phase := range []string{"authorize", "start", "finish"} {
		for _, applied := range []bool{false, true} {
			name := phase + "-rejected"
			if applied {
				name = phase + "-committed-error"
			}
			t.Run(name, func(t *testing.T) {
				config, s, u := durableFixture(t)
				s.phase, s.applied = phase, applied
				g, err := gw.New(config)
				must(t, err)
				id := identity(t, "alice", "agent", "task")
				result, err := g.Invoke(context.Background(), id, durableCall())
				if !errors.Is(err, gw.ErrJournal) {
					t.Fatalf("journal error not reported: %v", err)
				}
				wantCalls := int32(0)
				if phase == "finish" {
					wantCalls = 1
					if result.State != journal.OutcomeUnknown {
						t.Fatal("unconfirmed finish reported a known result")
					}
				}
				if u.calls.Load() != wantCalls {
					t.Fatal("failed commit permitted an unsafe dispatch")
				}
				record, lookupErr := s.Lookup(context.Background(), s.recordedKey())
				if phase == "authorize" && !applied {
					if !errors.Is(lookupErr, journal.ErrNotFound) {
						t.Fatal("rejected authorization persisted a row")
					}
					return
				}
				must(t, lookupErr)
				want := journal.Authorized
				if phase == "start" && applied || phase == "finish" {
					want = journal.DispatchStarted
				}
				if phase == "finish" && applied {
					want = journal.Completed
				}
				if record.State != want {
					t.Fatalf("persisted state=%v want=%v", record.State, want)
				}
				if _, err := g.Invoke(context.Background(), id, durableCall()); !errors.Is(err, gw.ErrReplay) || u.calls.Load() != wantCalls {
					t.Fatal("commit uncertainty permitted a replay")
				}
			})
		}
	}
}

func TestDurableOutcomesAndCancellation(t *testing.T) {
	for _, mode := range []string{"pending", "failed", "canceled", "tool-error", "network-error", "nil-output", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			config, s, u := durableFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			u.call = func(context.Context) (*mcp.CallToolResult, error) {
				switch mode {
				case "network-error":
					return nil, errors.New("fixture connection lost")
				case "nil-output":
					return nil, nil
				case "cancel":
					cancel()
					return nil, context.Canceled
				case "tool-error":
					return &mcp.CallToolResult{IsError: true}, nil
				default:
					return &mcp.CallToolResult{StructuredContent: map[string]any{"status": mode}}, nil
				}
			}
			g, err := gw.New(config)
			must(t, err)
			_, invokeErr := g.Invoke(ctx, identity(t, "alice", "agent", "task"), durableCall())
			record, err := s.Lookup(context.Background(), s.recordedKey())
			must(t, err)
			state, outcome := journal.Completed, journal.Failure
			if mode == "pending" {
				outcome = journal.Pending
			}
			if mode == "network-error" || mode == "nil-output" || mode == "cancel" {
				state, outcome = journal.OutcomeUnknown, journal.Unknown
				if !errors.Is(invokeErr, gw.ErrUpstream) {
					t.Fatalf("uncertain outcome error=%v", invokeErr)
				}
			} else {
				must(t, invokeErr)
			}
			if record.State != state || record.Outcome != outcome || u.calls.Load() != 1 {
				t.Fatal("outcome was not persisted after the upstream response")
			}
			if _, err := g.Invoke(context.Background(), identity(t, "alice", "agent", "task"), durableCall()); !errors.Is(err, gw.ErrReplay) || u.calls.Load() != 1 {
				t.Fatal("terminal or uncertain outcome retried upstream")
			}
		})
	}
}

func TestDurableReopenPreventsResumingOldAuthorization(t *testing.T) {
	for _, phase := range []string{"authorize", "start"} {
		t.Run(phase, func(t *testing.T) {
			config, s, u := durableFixture(t)
			dir, err := filepath.EvalSymlinks(t.TempDir())
			must(t, err)
			must(t, os.Chmod(dir, 0700))
			path := filepath.Join(dir, "core-journal.db")
			storage, err := journalsqlite.Open(path)
			must(t, err)
			t.Cleanup(func() { _ = storage.Close() })
			s.Store, s.phase, s.applied = storage, phase, true
			g, err := gw.New(config)
			must(t, err)
			id := identity(t, "alice", "agent", "task")
			if _, err := g.Invoke(context.Background(), id, durableCall()); !errors.Is(err, gw.ErrJournal) || u.calls.Load() != 0 {
				t.Fatal("lost commit response caused dispatch")
			}
			key := s.recordedKey()
			must(t, storage.Close())
			reopened, err := journalsqlite.Open(path)
			must(t, err)
			t.Cleanup(func() { _ = reopened.Close() })
			record, err := reopened.Lookup(context.Background(), key)
			must(t, err)
			if phase == "authorize" && (record.State != journal.Authorized || !record.Quarantined) {
				t.Fatal("old authorization did not enter quarantine")
			}
			if phase == "start" && (record.State != journal.OutcomeUnknown || record.Outcome != journal.Unknown) {
				t.Fatal("old dispatch did not become unknown")
			}
			config.Journal = reopened
			g, err = gw.New(config)
			must(t, err)
			if _, err := g.Invoke(context.Background(), id, durableCall()); !errors.Is(err, gw.ErrReplay) || u.calls.Load() != 0 {
				t.Fatal("reopened Gateway dispatched an old invocation")
			}
		})
	}
}

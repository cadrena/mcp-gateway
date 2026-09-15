package main

import (
	"bytes"
	"context"
	"encoding/json"
	simulator "github.com/cadrena/mcp-gateway/examples/refund-simulator"
	"os"
	"path/filepath"
	"testing"
)

func privateState(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(p, 0700); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestLocalAcceptanceAndPersistentRerun(t *testing.T) {
	dir := privateState(t)
	for attempt := 0; attempt < 2; attempt++ {
		var output bytes.Buffer
		if err := run(context.Background(), []string{"--state-dir", dir}, &output); err != nil {
			t.Fatal(err)
		}
		var got report
		if err := json.Unmarshal(output.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if !got.Simulator || got.Status != "passed" || len(got.Cases) != 8 || got.ApprovalContinuation == "" {
			t.Fatal("incorrect simulated report")
		}
		decisions := map[string]string{}
		for _, c := range got.Cases {
			decisions[c.Name] = c.Decision
			if c.Name == "allow_boundary" && (c.RefundCount != 1 || c.RemainingMinor != 90000) {
				t.Fatal("allow ledger mismatch")
			}
			if c.Decision == "REQUIRE_APPROVAL" && (c.RefundCount != 0 || c.RemainingMinor != 100000) {
				t.Fatal("pending approval mutated ledger")
			}
		}
		wantAllow := "ALLOW"
		if attempt == 1 {
			wantAllow = "REPLAY_REFUSED"
		}
		for name, want := range map[string]string{"allow_boundary": wantAllow, "approval_lower": "REQUIRE_APPROVAL", "approval_upper": "REQUIRE_APPROVAL", "deny_upper": "DENY", "deny_foreign_actor": "DENY", "same_invocation": "REPLAY_REFUSED", "changed_arguments": "CONFLICT", "reopened_journal": "REPLAY_REFUSED"} {
			if decisions[name] != want {
				t.Fatalf("%s=%s want %s", name, decisions[name], want)
			}
		}
	}
}
func TestLocalArgumentsAndPrivateDirectory(t *testing.T) {
	for _, args := range [][]string{nil, {"--state-dir", "relative"}, {"--unknown"}, {"--state-dir", "/tmp", "extra"}} {
		if run(context.Background(), args, &bytes.Buffer{}) == nil {
			t.Fatal("invalid arguments accepted")
		}
	}
	dir := privateState(t)
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if run(context.Background(), []string{"--state-dir", dir}, &bytes.Buffer{}) == nil {
		t.Fatal("public directory accepted")
	}
	target := privateState(t)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if run(context.Background(), []string{"--state-dir", link}, &bytes.Buffer{}) == nil {
		t.Fatal("symlink directory accepted")
	}
}
func TestLocalCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if run(ctx, []string{"--state-dir", privateState(t)}, &bytes.Buffer{}) == nil {
		t.Fatal("cancelled execution accepted")
	}
}

func TestEndpointStartupFailure(t *testing.T) {
	sim, err := simulator.New(filepath.Join(privateState(t), "ledger.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer sim.Close()
	// The upstream endpoint starts first; nil ports fail Gateway construction.
	// Cleanup must close that endpoint without dereferencing the nil result.
	got, err := startEndpoints(sim, nil, nil)
	if err == nil || got != nil {
		if got != nil {
			got.close()
		}
		t.Fatal("invalid runtime started")
	}
}

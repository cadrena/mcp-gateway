package refundsimulator

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cadrena/mcp-gateway/invocation"
)

const args = `{"customer":"cus_demo","payment":"ch_demo","amount_minor":250}`

func testKey(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func fixture(t *testing.T) (*Simulator, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "sim.db")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err = s.Seed(context.Background(), Payment{Customer: "cus_demo", ID: "ch_demo", AmountMinor: 1000}); err != nil {
		t.Fatal(err)
	}
	return s, path
}
func TestConcurrentReplayReopenAndSeed(t *testing.T) {
	s, path := fixture(t)
	ctx := context.Background()
	key := testKey("same")
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := s.Refund(ctx, json.RawMessage(args), key)
			if err != nil || !r.Simulator || r.Status != "simulated" {
				t.Error("refund failed")
			}
		}()
	}
	wg.Wait()
	r, err := s.Summary(ctx, "ch_demo")
	if err != nil || r.RemainingMinor != 750 || r.RefundCount != 1 {
		t.Fatal("duplicate deduction")
	}
	if _, err = s.Refund(ctx, json.RawMessage(strings.Replace(args, "250", "251", 1)), key); !errors.Is(err, ErrConflict) {
		t.Fatal("changed replay accepted")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Seed(ctx, Payment{Customer: "cus_demo", ID: "ch_demo", AmountMinor: 1000}); err != nil {
		t.Fatal(err)
	}
	if err = s.Seed(ctx, Payment{Customer: "cus_demo", ID: "ch_demo", AmountMinor: 2000}); !errors.Is(err, ErrConflict) {
		t.Fatal("seed reset balance")
	}
	if _, err = s.Refund(ctx, json.RawMessage(args), key); err != nil {
		t.Fatal(err)
	}
	r, err = s.Summary(ctx, "ch_demo")
	if err != nil || r.RemainingMinor != 750 || r.RefundCount != 1 {
		t.Fatal("reopen lost ledger")
	}
}
func TestConcurrentBalanceAndReplayWhenEmpty(t *testing.T) {
	s, _ := fixture(t)
	ctx := context.Background()
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.Refund(ctx, json.RawMessage(args), testKey(string(rune('a'+i))))
			if err == nil {
				wins.Add(1)
			} else if !errors.Is(err, ErrBalance) {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	r, err := s.Summary(ctx, "ch_demo")
	if err != nil || wins.Load() != 4 || r.RemainingMinor != 0 || r.RefundCount != 4 {
		t.Fatal("balance was not atomic")
	}
	var key string
	if err = s.db.QueryRow(`SELECT key FROM refunds LIMIT 1`).Scan(&key); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Refund(ctx, json.RawMessage(args), key); err != nil {
		t.Fatal("empty balance blocked saved result")
	}
}
func TestStrictArgumentsAndTrustedKey(t *testing.T) {
	s, _ := fixture(t)
	ctx := context.Background()
	for _, raw := range []string{`{}`, strings.Replace(args, "250", "1.0", 1), strings.Replace(args, "250", "0", 1), strings.Replace(args, "250", "-1", 1), strings.Replace(args, "250", "9223372036854775808", 1), args + `{}`, strings.Replace(args, `"customer":`, `"customer":"cus_demo","customer":`, 1), strings.Replace(args, `250}`, `250,"approved":true}`, 1)} {
		if _, err := s.Refund(ctx, json.RawMessage(raw), testKey(raw)); !errors.Is(err, ErrArguments) {
			t.Fatal("invalid argument accepted")
		}
	}
	if _, err := s.Refund(ctx, json.RawMessage(strings.Replace(args, "cus_demo", "cus_other", 1)), testKey("other")); !errors.Is(err, ErrBalance) {
		t.Fatal("foreign customer accepted")
	}
	r, err := s.CallTool(ctx, ToolName, json.RawMessage(args))
	if err != nil || !r.IsError {
		t.Fatal("missing trusted key accepted")
	}
	ctx, err = invocation.WithKey(ctx, testKey("trusted"))
	if err != nil {
		t.Fatal(err)
	}
	r, err = s.CallTool(ctx, ToolName, json.RawMessage(args))
	if err != nil || r.IsError {
		t.Fatal("trusted invocation failed")
	}
}
func TestOwnershipAndPermissions(t *testing.T) {
	s, path := fixture(t)
	if other, err := New(path); err == nil {
		other.Close()
		t.Fatal("second owner allowed")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if other, err := New(path); err == nil {
		other.Close()
		t.Fatal("shared database accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(path), "link.db")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if other, err := New(link); err == nil {
		other.Close()
		t.Fatal("symlink accepted")
	}
	hard := filepath.Join(filepath.Dir(path), "hard.db")
	if err := os.Link(path, hard); err != nil {
		t.Fatal(err)
	}
	if other, err := New(path); err == nil {
		other.Close()
		t.Fatal("hard link accepted")
	}
}
func TestTransactionRollback(t *testing.T) {
	s, _ := fixture(t)
	_, err := s.db.Exec(`CREATE TRIGGER fail_refund BEFORE INSERT ON refunds BEGIN SELECT RAISE(ABORT,'fixture'); END`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Refund(context.Background(), json.RawMessage(args), testKey("rollback")); !errors.Is(err, ErrStore) {
		t.Fatal("failed ledger insert accepted")
	}
	r, err := s.Summary(context.Background(), "ch_demo")
	if err != nil || r.RemainingMinor != 1000 || r.RefundCount != 0 {
		t.Fatal("balance escaped rollback")
	}
}
func TestHandlerSecurity(t *testing.T) {
	s, _ := fixture(t)
	h, err := NewHandler(s, HTTPConfig{GatewayBearer: "local-test-bearer-only", AllowedHosts: []string{"localhost"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, host, origin, bearer, method string
		status                             int
	}{{"anonymous", "localhost", "", "", http.MethodPost, 401}, {"foreign host", "foreign", "", "local-test-bearer-only", http.MethodPost, 403}, {"origin", "localhost", "https://foreign", "local-test-bearer-only", http.MethodPost, 403}, {"method", "localhost", "", "local-test-bearer-only", http.MethodGet, 405}} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "http://localhost/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
			req.Host = tc.host
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.bearer != "" {
				req.Header.Set("Authorization", "Bearer "+tc.bearer)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != tc.status {
				t.Fatalf("got %d", w.Code)
			}
		})
	}
}

func TestFailureClassification(t *testing.T) {
	for _, err := range []error{ErrArguments, ErrBalance, ErrConflict, ErrConfig} {
		r, failure := refundResult(Result{}, err)
		if failure != nil || r == nil || !r.IsError {
			t.Fatal("known rejection classification failed")
		}
	}
	for _, err := range []error{ErrStore, errors.New("unexpected private storage details")} {
		r, failure := refundResult(Result{}, err)
		if r != nil || failure != ErrStore {
			t.Fatal("uncertain storage outcome reported as known failure")
		}
	}
}

func TestCommitUnknownCannotDoubleDebit(t *testing.T) {
	s, _ := fixture(t)
	s.commitRefund = func(tx *sql.Tx) error {
		if err := tx.Commit(); err != nil {
			return err
		}
		return errors.New("simulated lost commit acknowledgement")
	}
	ctx, err := invocation.WithKey(context.Background(), testKey("uncertain"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.CallTool(ctx, ToolName, json.RawMessage(args))
	if result != nil || err != ErrStore {
		t.Fatal("uncertain commit reported as a known result")
	}
	result, err = s.CallTool(ctx, ToolName, json.RawMessage(args))
	if err != nil || result.IsError {
		t.Fatal("saved result replay failed")
	}
	summary, err := s.Summary(ctx, "ch_demo")
	if err != nil || summary.RemainingMinor != 750 || summary.RefundCount != 1 {
		t.Fatal("uncertain replay double debited")
	}
}

func TestHandlerRejectsDuplicateEnvelopeKeys(t *testing.T) {
	s, _ := fixture(t)
	h, err := NewHandler(s, HTTPConfig{GatewayBearer: "local-test-bearer-only", AllowedHosts: []string{"localhost"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"tools/call"}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"demo.refund_payment","arguments":` + args + `,"_meta":{"cadrena/idempotency-key":"` + testKey("a") + `","cadrena/idempotency-key":"` + testKey("b") + `"}}}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "http://localhost/", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer local-test-bearer-only")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("duplicate accepted: %d", w.Code)
		}
	}
	summary, err := s.Summary(context.Background(), "ch_demo")
	if err != nil || summary.RemainingMinor != 1000 || summary.RefundCount != 0 {
		t.Fatal("duplicate request mutated ledger")
	}
}

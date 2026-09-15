// Package refundsimulator provides a local, persistent demo ledger. It never
// contacts a payment provider and does not authorize Gateway callers.
package refundsimulator

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"sync"

	"github.com/cadrena/mcp-gateway/invocation"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	_ "modernc.org/sqlite"
)

var (
	ErrConfig    = errors.New("invalid simulator configuration")
	ErrArguments = errors.New("invalid simulator arguments")
	ErrConflict  = errors.New("simulator idempotency conflict")
	ErrBalance   = errors.New("simulator payment or balance unavailable")
	ErrStore     = errors.New("simulator storage unavailable")
)

type Simulator struct {
	mu     sync.Mutex
	db     *sql.DB
	lock   *os.File
	closed bool
	// commitRefund is an internal fault seam. Production always uses Tx.Commit.
	commitRefund func(*sql.Tx) error
}

func (*Simulator) String() string   { return "local refund simulator" }
func (*Simulator) GoString() string { return "local refund simulator" }

type Payment struct {
	Customer, ID string
	AmountMinor  int64
}
type Summary struct {
	Customer       string `json:"customer"`
	Payment        string `json:"payment"`
	Currency       string `json:"currency"`
	OriginalMinor  int64  `json:"original_minor"`
	RemainingMinor int64  `json:"remaining_minor"`
	RefundCount    int64  `json:"refund_count"`
	Simulator      bool   `json:"simulator"`
}
type Result struct {
	RefundID    string `json:"refund_id"`
	Status      string `json:"status"`
	AmountMinor int64  `json:"amount_minor"`
	Currency    string `json:"currency"`
	Simulator   bool   `json:"simulator"`
}

const paymentsSQL = `CREATE TABLE payments (id TEXT PRIMARY KEY NOT NULL, customer TEXT NOT NULL, original INTEGER NOT NULL CHECK(original>0), remaining INTEGER NOT NULL CHECK(remaining>=0 AND remaining<=original))`
const refundsSQL = `CREATE TABLE refunds (key TEXT PRIMARY KEY NOT NULL, payment TEXT NOT NULL REFERENCES payments(id), customer TEXT NOT NULL, amount INTEGER NOT NULL CHECK(amount>0), result BLOB NOT NULL)`

// New accepts an absolute path in an existing private directory. A process lock
// excludes a second owner. It never creates or replaces seeded payment data.
func New(path string) (*Simulator, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrConfig
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrConfig
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || privateDirectory(resolved) != nil {
		return nil, ErrConfig
	}
	path = filepath.Join(resolved, filepath.Base(path))
	lock, err := lockFile(path + ".lock")
	if err != nil {
		return nil, ErrStore
	}
	s := &Simulator{lock: lock, commitRefund: func(tx *sql.Tx) error { return tx.Commit() }}
	fail := func() (*Simulator, error) { _ = s.Close(); return nil, ErrStore }
	if privateFile(path, true) != nil {
		return fail()
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if privateFile(path+suffix, false) != nil {
			return fail()
		}
	}
	u := url.URL{Scheme: "file", Path: path}
	q := u.Query()
	for _, p := range []string{"busy_timeout(5000)", "journal_mode(WAL)", "synchronous(FULL)", "foreign_keys(ON)"} {
		q.Add("_pragma", p)
	}
	u.RawQuery = q.Encode()
	s.db, err = sql.Open("sqlite", u.String())
	if err != nil {
		return fail()
	}
	s.db.SetMaxOpenConns(1)
	var integrity string
	if s.db.QueryRow("PRAGMA integrity_check").Scan(&integrity) != nil || integrity != "ok" {
		return fail()
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fail()
	}
	var version, count int
	if tx.QueryRow("PRAGMA user_version").Scan(&version) != nil || tx.QueryRow(`SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'`).Scan(&count) != nil {
		_ = tx.Rollback()
		return fail()
	}
	if version == 0 && count == 0 {
		_, err = tx.Exec(paymentsSQL + ";" + refundsSQL + ";PRAGMA user_version=1")
	} else if version == 1 && count == 2 {
		for name, want := range map[string]string{"payments": paymentsSQL, "refunds": refundsSQL} {
			var got string
			if tx.QueryRow(`SELECT sql FROM sqlite_schema WHERE name=?`, name).Scan(&got) != nil || got != want {
				err = ErrStore
				break
			}
		}
	} else {
		err = ErrStore
	}
	if err != nil {
		_ = tx.Rollback()
		return fail()
	}
	if tx.Commit() != nil {
		return fail()
	}
	return s, nil
}
func (s *Simulator) configured() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db != nil && !s.closed
}
func (s *Simulator) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var err error
	if s.db != nil {
		err = s.db.Close()
	}
	if s.lock != nil {
		if e := unlockFile(s.lock); e != nil {
			err = e
		}
	}
	if err != nil {
		return ErrStore
	}
	return nil
}

// Seed inserts an explicit fixture once. A repeated identical fixture preserves
// all refunds; a different original amount or customer returns ErrConflict.
func (s *Simulator) Seed(ctx context.Context, p Payment) error {
	if s == nil || ctx == nil {
		return ErrConfig
	}
	if !identifier(p.Customer, "cus_") || !identifier(p.ID, "ch_") || p.AmountMinor <= 0 {
		return ErrArguments
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.db == nil {
		return ErrStore
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrStore
	}
	defer tx.Rollback()
	var customer string
	var amount int64
	err = tx.QueryRowContext(ctx, `SELECT customer,original FROM payments WHERE id=?`, p.ID).Scan(&customer, &amount)
	if err == nil {
		if customer != p.Customer || amount != p.AmountMinor {
			return ErrConflict
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return ErrStore
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO payments(id,customer,original,remaining) VALUES(?,?,?,?)`, p.ID, p.Customer, p.AmountMinor, p.AmountMinor); err != nil {
		return ErrStore
	}
	if tx.Commit() != nil {
		return ErrStore
	}
	return nil
}
func (s *Simulator) Summary(ctx context.Context, payment string) (Summary, error) {
	var r Summary
	if s == nil || ctx == nil {
		return r, ErrConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.db == nil {
		return r, ErrStore
	}
	err := s.db.QueryRowContext(ctx, `SELECT customer,id,original,remaining,(SELECT count(*) FROM refunds WHERE payment=p.id) FROM payments p WHERE id=?`, payment).Scan(&r.Customer, &r.Payment, &r.OriginalMinor, &r.RemainingMinor, &r.RefundCount)
	if err != nil {
		return Summary{}, ErrStore
	}
	r.Currency = "usd"
	r.Simulator = true
	return r, nil
}

// Refund applies a stable trusted key atomically. Identical replay returns the
// saved result even when the current balance cannot fund another refund.
func (s *Simulator) Refund(ctx context.Context, raw json.RawMessage, key string) (Result, error) {
	var r Result
	if s == nil || ctx == nil {
		return r, ErrConfig
	}
	a, err := parseArguments(raw)
	if err != nil {
		return r, err
	}
	if !validKey(key) {
		return r, ErrArguments
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.db == nil {
		return r, ErrStore
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return r, ErrStore
	}
	defer tx.Rollback()
	var customer, payment string
	var amount int64
	var saved []byte
	err = tx.QueryRowContext(ctx, `SELECT customer,payment,amount,result FROM refunds WHERE key=?`, key).Scan(&customer, &payment, &amount, &saved)
	if err == nil {
		if customer != a.Customer || payment != a.Payment || amount != a.Amount {
			return r, ErrConflict
		}
		if json.Unmarshal(saved, &r) != nil || !r.Simulator || r.Status != "simulated" || r.AmountMinor != amount || r.Currency != "usd" {
			return Result{}, ErrStore
		}
		return r, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return r, ErrStore
	}
	result, err := tx.ExecContext(ctx, `UPDATE payments SET remaining=remaining-? WHERE id=? AND customer=? AND remaining>=?`, a.Amount, a.Payment, a.Customer, a.Amount)
	if err != nil {
		return r, ErrStore
	}
	n, err := result.RowsAffected()
	if err != nil {
		return r, ErrStore
	}
	if n != 1 {
		return r, ErrBalance
	}
	id := sha256.Sum256([]byte("cadrena/local-refund/v1:" + key))
	r = Result{RefundID: "sim_" + hex.EncodeToString(id[:]), Status: "simulated", AmountMinor: a.Amount, Currency: "usd", Simulator: true}
	saved, _ = json.Marshal(r)
	if _, err = tx.ExecContext(ctx, `INSERT INTO refunds(key,payment,customer,amount,result) VALUES(?,?,?,?,?)`, key, a.Payment, a.Customer, a.Amount, saved); err != nil {
		return Result{}, ErrStore
	}
	if s.commitRefund(tx) != nil {
		return Result{}, ErrStore
	}
	return r, nil
}
func (s *Simulator) ListTools(ctx context.Context) ([]*mcp.Tool, error) {
	if ctx == nil || !s.configured() {
		return nil, ErrConfig
	}
	var schema map[string]any
	_ = json.Unmarshal([]byte(Schema), &schema)
	return []*mcp.Tool{{Name: ToolName, Description: "Local refund simulator. No external payment occurs.", InputSchema: schema}}, nil
}
func (s *Simulator) CallTool(ctx context.Context, name string, raw json.RawMessage) (*mcp.CallToolResult, error) {
	if ctx == nil || name != ToolName {
		return toolFailure("simulator_invalid_tool"), nil
	}
	key, ok := invocation.Key(ctx)
	if !ok {
		return toolFailure("trusted_idempotency_key_required"), nil
	}
	r, err := s.Refund(ctx, raw, key)
	return refundResult(r, err)
}

// A storage failure can follow an uncertain commit. Propagate an opaque error
// so the Gateway retains OutcomeUnknown rather than claiming no refund occurred.
func refundResult(r Result, err error) (*mcp.CallToolResult, error) {
	if err != nil {
		if errors.Is(err, ErrArguments) || errors.Is(err, ErrConflict) || errors.Is(err, ErrBalance) || errors.Is(err, ErrConfig) {
			return toolFailure("simulator_refund_not_executed"), nil
		}
		return nil, ErrStore
	}
	return &mcp.CallToolResult{StructuredContent: r, Content: []mcp.Content{&mcp.TextContent{Text: "LOCAL SIMULATOR refund status: simulated"}}}, nil
}

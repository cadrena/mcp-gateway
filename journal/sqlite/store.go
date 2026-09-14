// Package sqlite implements the standalone journal with SQLite.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cadrena/mcp-gateway/journal"
	_ "modernc.org/sqlite"
)

const tableSQL = `CREATE TABLE entries (
 key BLOB PRIMARY KEY NOT NULL CHECK(typeof(key)='blob' AND length(key)=32),
 digest BLOB NOT NULL CHECK(typeof(digest)='blob' AND length(digest)=32),
 state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 4),
 outcome INTEGER NOT NULL CHECK(outcome BETWEEN 1 AND 4),
 decision_id TEXT NOT NULL,
 revision_id TEXT NOT NULL,
 quarantined INTEGER NOT NULL CHECK(quarantined IN (0,1))
)`

type Store struct {
	mu     sync.RWMutex
	db     *sql.DB
	lock   *os.File
	issuer *journal.Issuer
	closed bool
}

var _ journal.Store = (*Store)(nil)

// Open requires an absolute path in an existing private directory. It rejects
// symlinks and shared permissions. The process lock lasts until Close.
func Open(path string) (*Store, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, journal.ErrStore
	}
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	if err != nil || parentInfo.Mode()&os.ModeSymlink != 0 {
		return nil, journal.ErrStore
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return nil, journal.ErrStore
	}
	// Resolve system ancestors such as macOS /var before opening any files.
	path = filepath.Join(resolved, filepath.Base(path))
	if err = privateDirectory(resolved); err != nil {
		return nil, journal.ErrStore
	}
	lock, err := lockFile(path + ".lock")
	if err != nil {
		return nil, journal.ErrStore
	}
	s := &Store{lock: lock}
	fail := func() (*Store, error) { _ = s.Close(); return nil, journal.ErrStore }
	if err = privateFile(path, true); err != nil {
		return fail()
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if err = privateFile(path+suffix, false); err != nil {
			return fail()
		}
	}
	s.issuer, err = journal.NewIssuer()
	if err != nil {
		return fail()
	}
	u := url.URL{Scheme: "file", Path: path}
	query := u.Query()
	for _, p := range []string{"busy_timeout(5000)", "journal_mode(WAL)", "synchronous(FULL)", "foreign_keys(ON)"} {
		query.Add("_pragma", p)
	}
	u.RawQuery = query.Encode()
	s.db, err = sql.Open("sqlite", u.String())
	if err != nil {
		return fail()
	}
	s.db.SetMaxOpenConns(1)
	s.db.SetMaxIdleConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = s.initialize(ctx); err != nil {
		return fail()
	}
	return s, nil
}

func (s *Store) Close() error {
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
		return journal.ErrStore
	}
	return nil
}

func (s *Store) initialize(ctx context.Context) error {
	var integrity string
	if s.db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity) != nil || integrity != "ok" {
		return journal.ErrStore
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version, count int
	if err = tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'`).Scan(&count); err != nil {
		return err
	}
	switch version {
	case 0:
		if count != 0 {
			return journal.ErrStore
		}
		if _, err = tx.ExecContext(ctx, tableSQL); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "PRAGMA user_version=1"); err != nil {
			return err
		}
	case 1:
		var definition string
		if count != 1 || tx.QueryRowContext(ctx, `SELECT sql FROM sqlite_schema WHERE type='table' AND name='entries'`).Scan(&definition) != nil || definition != tableSQL {
			return journal.ErrStore
		}
	default:
		return journal.ErrStore
	}
	rows, err := tx.QueryContext(ctx, `SELECT key,digest,state,outcome,decision_id,revision_id,quarantined FROM entries`)
	if err != nil {
		return err
	}
	for rows.Next() {
		if _, err = scan(rows); err != nil {
			_ = rows.Close()
			return err
		}
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE entries SET quarantined=1 WHERE state=1; UPDATE entries SET state=4,outcome=1 WHERE state=2`); err != nil {
		return err
	}
	return tx.Commit()
}

type scanner interface{ Scan(...any) error }

func scan(row scanner) (journal.Record, error) {
	var r journal.Record
	var rawKey, rawDigest any
	var state, outcome, quarantine int64
	if err := row.Scan(&rawKey, &rawDigest, &state, &outcome, &r.DecisionID, &r.RevisionID, &quarantine); err != nil {
		return r, err
	}
	key, keyOK := rawKey.([]byte)
	digest, digestOK := rawDigest.([]byte)
	if !keyOK || !digestOK || len(key) != 32 || len(digest) != 32 || state < 1 || state > 4 || outcome < 1 || outcome > 4 || (quarantine != 0 && quarantine != 1) {
		return journal.Record{}, journal.ErrStore
	}
	copy(r.Key[:], key)
	copy(r.Digest[:], digest)
	r.State = journal.State(state)
	r.Outcome = journal.Outcome(outcome)
	r.Quarantined = quarantine == 1
	if !r.Valid() {
		return journal.Record{}, journal.ErrStore
	}
	return r, nil
}

func (s *Store) Authorize(ctx context.Context, r journal.Record) (journal.Lease, error) {
	if s == nil {
		return journal.Lease{}, journal.ErrStore
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed || s.db == nil || s.issuer == nil || !r.Valid() || r.State != journal.Authorized || r.Outcome != journal.Unknown || r.Quarantined {
		return journal.Lease{}, journal.ErrStore
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return journal.Lease{}, journal.ErrStore
	}
	defer tx.Rollback()
	old, err := scan(tx.QueryRowContext(ctx, `SELECT key,digest,state,outcome,decision_id,revision_id,quarantined FROM entries WHERE key=?`, r.Key[:]))
	if err == nil {
		if old.Digest != r.Digest {
			return journal.Lease{}, journal.ErrConflict
		}
		return journal.Lease{}, journal.ErrReplay
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return journal.Lease{}, journal.ErrStore
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO entries(key,digest,state,outcome,decision_id,revision_id,quarantined) VALUES(?,?,?,?,?,?,0)`, r.Key[:], r.Digest[:], r.State, r.Outcome, r.DecisionID, r.RevisionID); err != nil {
		return journal.Lease{}, journal.ErrStore
	}
	if err = tx.Commit(); err != nil {
		return journal.Lease{}, journal.ErrStore
	}
	return s.issuer.Issue(r.Key, r.Digest), nil
}

func (s *Store) Start(ctx context.Context, lease journal.Lease) error {
	return s.transition(ctx, lease, journal.Authorized, journal.DispatchStarted, journal.Unknown)
}

func (s *Store) Finish(ctx context.Context, lease journal.Lease, state journal.State, outcome journal.Outcome) error {
	if state != journal.Completed && state != journal.OutcomeUnknown {
		return journal.ErrStore
	}
	if state == journal.Completed && (outcome != journal.Success && outcome != journal.Failure && outcome != journal.Pending) || state == journal.OutcomeUnknown && outcome != journal.Unknown {
		return journal.ErrStore
	}
	return s.transition(ctx, lease, journal.DispatchStarted, state, outcome)
}

func (s *Store) transition(ctx context.Context, lease journal.Lease, from, to journal.State, outcome journal.Outcome) error {
	if s == nil {
		return journal.ErrStore
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed || s.db == nil || s.issuer == nil {
		return journal.ErrStore
	}
	key, digest, ok := s.issuer.Resolve(lease)
	if !ok {
		return journal.ErrStore
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return journal.ErrStore
	}
	defer tx.Rollback()
	r, err := scan(tx.QueryRowContext(ctx, `SELECT key,digest,state,outcome,decision_id,revision_id,quarantined FROM entries WHERE key=?`, key[:]))
	if err != nil {
		return journal.ErrStore
	}
	if r.Digest != digest {
		return journal.ErrConflict
	}
	if r.State != from || r.Quarantined {
		return journal.ErrReplay
	}
	result, err := tx.ExecContext(ctx, `UPDATE entries SET state=?,outcome=? WHERE key=? AND digest=? AND state=? AND quarantined=0`, to, outcome, key[:], digest[:], from)
	if err != nil {
		return journal.ErrStore
	}
	n, err := result.RowsAffected()
	if err != nil {
		return journal.ErrStore
	}
	if n != 1 {
		return journal.ErrReplay
	}
	if err = tx.Commit(); err != nil {
		return journal.ErrStore
	}
	return nil
}

func (s *Store) Lookup(ctx context.Context, key [32]byte) (journal.Record, error) {
	if s == nil {
		return journal.Record{}, journal.ErrStore
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed || s.db == nil || s.issuer == nil || key == ([32]byte{}) {
		return journal.Record{}, journal.ErrStore
	}
	r, err := scan(s.db.QueryRowContext(ctx, `SELECT key,digest,state,outcome,decision_id,revision_id,quarantined FROM entries WHERE key=?`, key[:]))
	if errors.Is(err, sql.ErrNoRows) {
		return journal.Record{}, journal.ErrNotFound
	}
	if err != nil {
		return journal.Record{}, journal.ErrStore
	}
	return r, nil
}

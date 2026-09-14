package sqlite

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cadrena/mcp-gateway/journal"
)

func fixtureRecord() journal.Record {
	return journal.Record{Key: [32]byte{1}, Digest: [32]byte{2}, State: journal.Authorized, Outcome: journal.Unknown, DecisionID: "decision-1", RevisionID: "revision-1"}
}
func privateTemp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}
func openFixture(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(privateTemp(t), "journal.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func TestConcurrentAuthorizeAndDispatch(t *testing.T) {
	s, _ := openFixture(t)
	ctx := context.Background()
	r := fixtureRecord()
	var winners atomic.Int32
	var lease journal.Lease
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, err := s.Authorize(ctx, r)
			if err == nil {
				lease = l
				winners.Add(1)
			} else if !errors.Is(err, journal.ErrReplay) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatal("authorization did not have one winner")
	}
	winners.Store(0)
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.Start(ctx, lease)
			if err == nil {
				winners.Add(1)
			} else if !errors.Is(err, journal.ErrReplay) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatal("dispatch did not have one winner")
	}
	got, err := s.Lookup(ctx, r.Key)
	if err != nil || got.State != journal.DispatchStarted {
		t.Fatal("dispatch transition not committed")
	}
	if err = s.Finish(ctx, lease, journal.Completed, journal.Success); err != nil {
		t.Fatal(err)
	}
	if err = s.Finish(ctx, lease, journal.Completed, journal.Success); !errors.Is(err, journal.ErrReplay) {
		t.Fatal("finish replay accepted")
	}
	if err = s.Start(ctx, lease); !errors.Is(err, journal.ErrReplay) {
		t.Fatal("completed row redispatched")
	}
	r.Digest[0]++
	if _, err = s.Authorize(ctx, r); !errors.Is(err, journal.ErrConflict) {
		t.Fatal("different binding accepted")
	}
}

func TestLeaseAndStateFailures(t *testing.T) {
	s, _ := openFixture(t)
	ctx := context.Background()
	r := fixtureRecord()
	lease, err := s.Authorize(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := journal.NewIssuer()
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Start(ctx, issuer.Issue(r.Key, r.Digest)); !errors.Is(err, journal.ErrStore) {
		t.Fatal("foreign lease accepted")
	}
	if err = s.Finish(ctx, lease, journal.Completed, journal.Success); !errors.Is(err, journal.ErrReplay) {
		t.Fatal("finish before dispatch accepted")
	}
	if err = s.Finish(ctx, lease, journal.Completed, journal.Unknown); !errors.Is(err, journal.ErrStore) {
		t.Fatal("invalid completed outcome accepted")
	}
	if _, err = s.Lookup(ctx, [32]byte{9}); !errors.Is(err, journal.ErrNotFound) {
		t.Fatal("missing record not reported")
	}
	if err = s.Start(ctx, lease); err != nil {
		t.Fatal(err)
	}
	if err = s.Finish(ctx, lease, journal.OutcomeUnknown, journal.Unknown); err != nil {
		t.Fatal(err)
	}
	got, err := s.Lookup(ctx, r.Key)
	if err != nil || got.State != journal.OutcomeUnknown || got.Outcome != journal.Unknown {
		t.Fatal("unknown outcome not stored")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if err = s.Start(ctx, lease); !errors.Is(err, journal.ErrStore) {
		t.Fatal("closed store accepted lease")
	}
}

func TestCanceledAuthorizationLeavesNoRecord(t *testing.T) {
	s, _ := openFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := fixtureRecord()
	if _, err := s.Authorize(ctx, r); !errors.Is(err, journal.ErrStore) {
		t.Fatal("canceled authorization accepted")
	}
	if _, err := s.Lookup(context.Background(), r.Key); !errors.Is(err, journal.ErrNotFound) {
		t.Fatal("canceled transaction persisted")
	}
}

func TestZeroStoreFailsClosed(t *testing.T) {
	for _, s := range []*Store{nil, {}} {
		ctx := context.Background()
		r := fixtureRecord()
		if _, err := s.Authorize(ctx, r); !errors.Is(err, journal.ErrStore) {
			t.Fatal("zero store authorized")
		}
		if _, err := s.Lookup(ctx, r.Key); !errors.Is(err, journal.ErrStore) {
			t.Fatal("zero store returned record")
		}
		if err := s.Start(ctx, journal.Lease{}); !errors.Is(err, journal.ErrStore) {
			t.Fatal("zero store started")
		}
		if err := s.Finish(ctx, journal.Lease{}, journal.Completed, journal.Success); !errors.Is(err, journal.ErrStore) {
			t.Fatal("zero store finished")
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReopenPreservesTerminalRecordsAndRejectsOldLease(t *testing.T) {
	for _, outcome := range []journal.Outcome{journal.Success, journal.Failure, journal.Pending} {
		t.Run(string(rune('0'+outcome)), func(t *testing.T) {
			s, path := openFixture(t)
			ctx := context.Background()
			r := fixtureRecord()
			lease, err := s.Authorize(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			if err = s.Start(ctx, lease); err != nil {
				t.Fatal(err)
			}
			if err = s.Finish(ctx, lease, journal.Completed, outcome); err != nil {
				t.Fatal(err)
			}
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			got, err := reopened.Lookup(ctx, r.Key)
			if err != nil || got.State != journal.Completed || got.Outcome != outcome {
				t.Fatal("terminal outcome changed on reopen")
			}
			if err = reopened.Start(ctx, lease); !errors.Is(err, journal.ErrStore) {
				t.Fatal("old lease accepted")
			}
		})
	}
}

func TestExclusiveLockBlocksRecovery(t *testing.T) {
	s, path := openFixture(t)
	r := fixtureRecord()
	lease, err := s.Authorize(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := Open(path); err == nil {
		_ = other.Close()
		t.Fatal("second owner acquired journal")
	}
	got, err := s.Lookup(context.Background(), r.Key)
	if err != nil || got.Quarantined {
		t.Fatal("failed second owner changed live record")
	}
	if err = s.Start(context.Background(), lease); err != nil {
		t.Fatal(err)
	}
}

func TestCrashHelper(t *testing.T) {
	path := os.Getenv("CADRENA_JOURNAL_CRASH_PATH")
	if path == "" {
		return
	}
	s, err := Open(path)
	if err != nil {
		os.Exit(90)
	}
	lease, err := s.Authorize(context.Background(), fixtureRecord())
	if err != nil {
		os.Exit(91)
	}
	if os.Getenv("CADRENA_JOURNAL_CRASH_PHASE") == "started" {
		if s.Start(context.Background(), lease) != nil {
			os.Exit(92)
		}
	}
	if _, err = os.Stdout.WriteString("READY\n"); err != nil {
		os.Exit(93)
	}
	// The parent kills this process only after it reads the committed boundary.
	for {
		time.Sleep(time.Second)
	}
}

func TestSubprocessCrashRecovery(t *testing.T) {
	for _, phase := range []string{"authorized", "started"} {
		t.Run(phase, func(t *testing.T) {
			path := filepath.Join(privateTemp(t), "crash.db")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCrashHelper$")
			cmd.Env = append(os.Environ(), "CADRENA_JOURNAL_CRASH_PATH="+path, "CADRENA_JOURNAL_CRASH_PHASE="+phase)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			defer func() {
				if !waited {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				}
			}()
			ready := make(chan bool, 1)
			go func() {
				scanner := bufio.NewScanner(stdout)
				scanner.Buffer(make([]byte, 64), 128)
				ready <- scanner.Scan() && scanner.Text() == "READY"
			}()
			select {
			case ok := <-ready:
				if !ok {
					t.Fatal("helper stopped before committed readiness")
				}
			case <-ctx.Done():
				t.Fatal("helper readiness timed out")
			}
			if err = cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			err = cmd.Wait()
			waited = true
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != -1 {
				t.Fatalf("helper did not terminate by signal: %v", err)
			}
			s, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			r := fixtureRecord()
			got, err := s.Lookup(context.Background(), r.Key)
			if err != nil {
				t.Fatal(err)
			}
			if phase == "authorized" {
				if got.State != journal.Authorized || !got.Quarantined {
					t.Fatal("authorized crash was not quarantined")
				}
			} else if got.State != journal.OutcomeUnknown || got.Outcome != journal.Unknown {
				t.Fatal("started crash did not become unknown")
			}
			if _, err = s.Authorize(context.Background(), r); !errors.Is(err, journal.ErrReplay) {
				t.Fatal("crash recovery issued a new lease")
			}
		})
	}
}

func TestCorruptionAndSchemaVersionFailClosed(t *testing.T) {
	for _, damage := range []string{`PRAGMA user_version=2`, `PRAGMA ignore_check_constraints=ON; UPDATE entries SET state=99`, `PRAGMA ignore_check_constraints=ON; UPDATE entries SET digest='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'`, `UPDATE entries SET decision_id=''`, `CREATE TABLE unexpected(x INTEGER)`} {
		t.Run(damage, func(t *testing.T) {
			s, path := openFixture(t)
			if _, err := s.Authorize(context.Background(), fixtureRecord()); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(damage); err != nil {
				t.Fatal(err)
			}
			if err = db.Close(); err != nil {
				t.Fatal(err)
			}
			if corrupt, err := Open(path); err == nil {
				_ = corrupt.Close()
				t.Fatal("corrupt database accepted")
			}
		})
	}
}

func TestUnsafePathsAndPermissionsFailClosed(t *testing.T) {
	parent := privateTemp(t)
	target := filepath.Join(parent, "target.db")
	if err := os.WriteFile(target, nil, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link.db")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if s, err := Open(link); err == nil {
		_ = s.Close()
		t.Fatal("database symlink accepted")
	}
	if err := os.Chmod(target, 0644); err != nil {
		t.Fatal(err)
	}
	if s, err := Open(target); err == nil {
		_ = s.Close()
		t.Fatal("shared database accepted")
	}
	if err := os.Chmod(parent, 0755); err != nil {
		t.Fatal(err)
	}
	if s, err := Open(filepath.Join(parent, "other.db")); err == nil {
		_ = s.Close()
		t.Fatal("shared directory accepted")
	}
}

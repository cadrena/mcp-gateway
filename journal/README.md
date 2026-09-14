# Durable execution journal

The journal records authorization before the Gateway starts an upstream call.
It stores hashes and bounded decision metadata. It does not store arguments,
identity data, approval evidence, or credentials.

## Public contract

- `Authorize(ctx, record)` inserts one record and commits it before returning a lease.
- `Start(ctx, lease)` commits the transition from `Authorized` to `DispatchStarted`.
- `Finish(ctx, lease, state, outcome)` records a terminal result after dispatch starts.
- `Lookup(ctx, key)` reads a validated record.

An existing key never creates another lease. Matching digests return `ErrReplay`.
Different digests return `ErrConflict`. Unknown keys return `ErrNotFound` during
lookup. Storage failures return `ErrStore` without database error text.

The caller supplies `Authorized` and `Unknown` when it creates a record.
Completed results use `Success`, `Failure`, or `Pending`. Uncertain results use
`OutcomeUnknown` and `Unknown`.

Each adapter owns a private `Issuer`. The issuer authenticates an opaque lease
with a random secret. Each new store instance creates a new issuer. A lease
from an earlier instance cannot start a call after recovery.

An adapter must issue leases only after successful commits. A commit error
never grants execution rights, including an error with an uncertain commit.
The interface permits a future PostgreSQL adapter without private imports.

## SQLite adapter

`sqlite.Open(path)` returns `*sqlite.Store`. Call `Close()` when the store stops.

The adapter supports Linux and macOS. Other platforms reject `Open`.
The path must be absolute. Its parent directory must already exist, belong to
the current user, and exclude group and other permissions. Use mode `0700`.
The adapter does not change existing permissions.

The adapter rejects a symbolic link for the parent directory or database file.
It resolves ancestor links before opening files, including the macOS `/var`
system link. Database, lock, and existing WAL files must be regular files with
one link. They must belong to the current user and exclude shared permissions.
New files use mode `0600`.

The directory owner remains trusted. Do not replace the lock file or modify the
database through another connection while the store runs. Directory permissions
exclude other users; they do not stop another process with the same credentials.

An exclusive file lock remains active from `Open` through `Close`. Another
owner cannot run recovery against a live store. SQLite uses WAL, `synchronous=FULL`,
a five-second busy timeout, and one database connection. Each mutation uses a
short SQL transaction.

Open checks database integrity, schema version, schema definition, and all record
invariants before recovery. It rejects unknown versions and unexpected schema
objects. It never drops data or automatically repairs corruption.

Recovery uses these rules:

- `Authorized` stays authorized and receives a quarantine flag.
- `DispatchStarted` changes to `OutcomeUnknown` with an unknown outcome.
- Terminal records retain their state and outcome.

Quarantine preserves journal history. It prevents execution under authority from
a previous store lifetime. W2 does not delete records or implement retention.

## Verification

Run these commands from the Gateway directory:

```sh
rtk proxy env GOENV=off GOWORK=off GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GOTOOLCHAIN=go1.25.13 go test -race -timeout 60s ./journal/...
rtk proxy env GOENV=off GOWORK=off GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GOTOOLCHAIN=go1.25.13 python3 -c 'import subprocess; subprocess.run(["go", "vet", "./journal/..."], timeout=45, check=True)'
```

Tests use real SQLite databases. Sixteen concurrent workers compete separately
for authorization and dispatch. Only one worker wins each transition.

Crash tests start a subprocess and kill it after authorization or dispatch
commits. The parent reopens the database and verifies recovery without replay.
These tests cover process termination. They do not simulate power loss,
filesystem corruption during a write, or hardware faults.

Other tests cover issuer isolation, canceled authorization, invalid transitions,
terminal outcomes, exclusive ownership, corrupt records, unsupported schemas,
and unsafe file permissions.

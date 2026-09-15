// Package journal defines the durable boundary before an upstream side effect.
package journal

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"regexp"
)

type State uint8

const (
	Authorized State = iota + 1
	DispatchStarted
	Completed
	OutcomeUnknown
)

type Outcome uint8

const (
	Unknown Outcome = iota + 1
	Success
	Failure
	Pending
)

var (
	ErrConflict = errors.New("journal binding conflict")
	ErrReplay   = errors.New("journal execution already exists")
	ErrNotFound = errors.New("journal record not found")
	ErrStore    = errors.New("journal unavailable")
)

// Record contains bounded metadata only. It never contains payloads or credentials.
type Record struct {
	Key, Digest            [32]byte
	State                  State
	Outcome                Outcome
	DecisionID, RevisionID string
	Quarantined            bool
}

var metadataID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_.-]{0,255}$`)

// Valid checks storage invariants. Quarantine preserves the Authorized state.
func (r Record) Valid() bool {
	if r.Key == ([32]byte{}) || r.Digest == ([32]byte{}) || !metadataID.MatchString(r.DecisionID) || !metadataID.MatchString(r.RevisionID) {
		return false
	}
	if r.Quarantined && r.State != Authorized {
		return false
	}
	switch r.State {
	case Authorized, DispatchStarted, OutcomeUnknown:
		return r.Outcome == Unknown
	case Completed:
		return r.Outcome == Success || r.Outcome == Failure || r.Outcome == Pending
	default:
		return false
	}
}

func (Record) String() string   { return "[journal record]" }
func (Record) GoString() string { return "[journal record]" }

// Lease is an opaque capability for one authorized row and one store lifetime.
// Issuers must remain private to their adapter instance.
type Lease struct{ key, digest, signature [32]byte }

// Matches checks binding only. It does not authenticate a lease or grant execution.
// Store.Start must still authenticate the issuing adapter and commit its CAS.
func (l Lease) Matches(key, digest [32]byte) bool {
	return key != ([32]byte{}) && digest != ([32]byte{}) && l.key == key && l.digest == digest
}

func (Lease) String() string   { return "[journal lease]" }
func (Lease) GoString() string { return "[journal lease]" }

// Issuer lets independent adapters create opaque leases without exposing fields.
// A new issuer on each Open prevents reconstruction after recovery.
type Issuer struct{ secret [32]byte }

func (Issuer) String() string   { return "[journal issuer]" }
func (Issuer) GoString() string { return "[journal issuer]" }

func NewIssuer() (*Issuer, error) {
	i := &Issuer{}
	if _, err := rand.Read(i.secret[:]); err != nil {
		return nil, ErrStore
	}
	return i, nil
}

// Issue must run only after a successful authorization commit for a new record.
func (i *Issuer) Issue(key, digest [32]byte) Lease {
	if i == nil || i.secret == ([32]byte{}) || key == ([32]byte{}) || digest == ([32]byte{}) {
		return Lease{}
	}
	return Lease{key, digest, i.sign(key, digest)}
}

func (i *Issuer) Resolve(lease Lease) (key, digest [32]byte, ok bool) {
	if i == nil || i.secret == ([32]byte{}) || lease.key == ([32]byte{}) || lease.digest == ([32]byte{}) {
		return key, digest, false
	}
	want := i.sign(lease.key, lease.digest)
	if !hmac.Equal(want[:], lease.signature[:]) {
		return key, digest, false
	}
	return lease.key, lease.digest, true
}

func (i *Issuer) sign(key, digest [32]byte) [32]byte {
	m := hmac.New(sha256.New, i.secret[:])
	_, _ = m.Write([]byte("cadrena-journal-lease-v1"))
	_, _ = m.Write(key[:])
	_, _ = m.Write(digest[:])
	var out [32]byte
	copy(out[:], m.Sum(nil))
	return out
}

type Store interface {
	Authorize(context.Context, Record) (Lease, error)
	Start(context.Context, Lease) error
	Finish(context.Context, Lease, State, Outcome) error
	Lookup(context.Context, [32]byte) (Record, error)
}

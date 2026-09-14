package journal

import (
	"fmt"
	"strings"
	"testing"
)

func TestLeaseIssuerIsolation(t *testing.T) {
	a, err := NewIssuer()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewIssuer()
	if err != nil {
		t.Fatal(err)
	}
	key, digest := [32]byte{1}, [32]byte{2}
	lease := a.Issue(key, digest)
	gotKey, gotDigest, ok := a.Resolve(lease)
	if !ok || gotKey != key || gotDigest != digest {
		t.Fatal("issuer rejected own lease")
	}
	if _, _, ok = b.Resolve(lease); ok {
		t.Fatal("another issuer accepted lease")
	}
	lease.digest[0]++
	if _, _, ok = a.Resolve(lease); ok {
		t.Fatal("modified lease accepted")
	}
	for _, issuer := range []*Issuer{nil, {}} {
		if _, _, ok = issuer.Resolve(Lease{}); ok {
			t.Fatal("invalid issuer accepted lease")
		}
	}
	if got := fmt.Sprintf("%v %+v %#v", lease, lease, lease); strings.Contains(got, "signature") || strings.Contains(got, "digest") {
		t.Fatal("lease formatting exposed fields")
	}
}

func TestRecordInvariants(t *testing.T) {
	good := Record{Key: [32]byte{1}, Digest: [32]byte{2}, State: Authorized, Outcome: Unknown, DecisionID: "decision-1", RevisionID: "sha256:123"}
	if !good.Valid() {
		t.Fatal("valid record rejected")
	}
	for _, change := range []func(*Record){func(r *Record) { r.Key = [32]byte{} }, func(r *Record) { r.Digest = [32]byte{} }, func(r *Record) { r.State = 0 }, func(r *Record) { r.Outcome = 0 }, func(r *Record) { r.Outcome = Success }, func(r *Record) { r.DecisionID = "secret\nvalue" }, func(r *Record) { r.RevisionID = "" }, func(r *Record) { r.State = DispatchStarted; r.Quarantined = true }} {
		r := good
		change(&r)
		if r.Valid() {
			t.Fatal("invalid record accepted")
		}
	}
}

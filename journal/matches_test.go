package journal_test

import (
	"github.com/cadrena/mcp-gateway/journal"
	"testing"
)

func TestLeaseMatchesBindingOnly(t *testing.T) {
	key, digest := [32]byte{1}, [32]byte{2}
	issuer, err := journal.NewIssuer()
	if err != nil {
		t.Fatal(err)
	}
	lease := issuer.Issue(key, digest)
	if !lease.Matches(key, digest) || lease.Matches([32]byte{3}, digest) || lease.Matches(key, [32]byte{3}) || lease.Matches([32]byte{}, digest) || (journal.Lease{}).Matches(key, digest) {
		t.Fatal("lease binding mismatch")
	}
	other, err := journal.NewIssuer()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := other.Resolve(lease); ok {
		t.Fatal("binding match authenticated another issuer")
	}
}

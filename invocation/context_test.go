package invocation_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cadrena/mcp-gateway/invocation"
)

func TestTrustedKeyPreservesParentContext(t *testing.T) {
	type parentKey struct{}
	parent, cancel := context.WithCancel(context.WithValue(context.Background(), parentKey{}, "parent"))
	defer cancel()
	key := strings.Repeat("0123456789abcdef", 4)
	ctx, err := invocation.WithKey(parent, key)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := invocation.Key(ctx)
	if !ok || got != key || ctx.Value(parentKey{}) != "parent" {
		t.Fatal("key or parent value changed")
	}
	if _, ok := invocation.Key(parent); ok {
		t.Fatal("child key changed its parent")
	}
	cancel()
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("child lost parent cancellation")
	}
}

func TestInvalidKeysCannotCreateContext(t *testing.T) {
	for _, key := range []string{"", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("A", 64), strings.Repeat("g", 64), strings.Repeat("é", 32), strings.Repeat("a", 63) + "\n"} {
		ctx, err := invocation.WithKey(context.Background(), key)
		if !errors.Is(err, invocation.ErrKey) || ctx != nil {
			t.Fatal("invalid key created a context")
		}
	}
	ctx, err := invocation.WithKey(nil, strings.Repeat("a", 64))
	if !errors.Is(err, invocation.ErrKey) || ctx != nil {
		t.Fatal("nil parent accepted")
	}
}

func TestMissingOrUntrustedContextValueHasNoKey(t *testing.T) {
	for _, ctx := range []context.Context{nil, context.Background(), context.WithValue(context.Background(), invocation.MetadataKey, strings.Repeat("a", 64))} {
		if key, ok := invocation.Key(ctx); ok || key != "" {
			t.Fatal("untrusted context value became a dispatch key")
		}
	}
}

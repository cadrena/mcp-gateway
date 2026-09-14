// Package invocation carries trusted dispatch metadata between host adapters.
// It does not authenticate requests or grant permission to dispatch a tool.
package invocation

import (
	"context"
	"errors"
)

// MetadataKey identifies the host's dispatch key in MCP request metadata.
const MetadataKey = "cadrena/idempotency-key"

// ErrKey reports an invalid dispatch key without disclosing its value.
var ErrKey = errors.New("invalid invocation key")

type keyContext struct{}

// WithKey attaches a host-generated SHA-256 key after the durable dispatch gate.
// The key must contain exactly 64 lowercase ASCII hexadecimal characters.
// Callers must not obtain this key from incoming tool arguments or metadata.
func WithKey(ctx context.Context, key string) (context.Context, error) {
	if ctx == nil || !validKey(key) {
		return nil, ErrKey
	}
	return context.WithValue(ctx, keyContext{}, key), nil
}

// Key returns the trusted dispatch key, if the host attached one with WithKey.
func Key(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	key, ok := ctx.Value(keyContext{}).(string)
	if !ok || !validKey(key) {
		return "", false
	}
	return key, true
}

func validKey(key string) bool {
	if len(key) != 64 {
		return false
	}
	for _, b := range []byte(key) {
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return false
		}
	}
	return true
}

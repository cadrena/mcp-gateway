package refundupstream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testArguments = `{"customer":"cus_fixture","payment":"ch_fixture","amount_minor":10000}`

var testKey = strings.Repeat("a", 64)

func testCharge() map[string]any {
	return map[string]any{"id": "ch_fixture", "object": "charge", "customer": "cus_fixture", "currency": "usd", "livemode": false, "paid": true, "captured": true, "refunded": false, "amount": 100000, "amount_captured": 100000, "amount_refunded": 0}
}
func testRefund(status string) map[string]any {
	return map[string]any{"id": "re_fixture", "object": "refund", "charge": "ch_fixture", "amount": 10000, "currency": "usd", "status": status}
}

// Only tests can replace the fixed production endpoint.
func testAdapter(t *testing.T, h http.HandlerFunc) (*Adapter, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(h)
	t.Cleanup(server.Close)
	a, err := New(Config{APIKey: "sk_test_fixture"})
	if err != nil {
		t.Fatal(err)
	}
	a.endpoint = server.URL
	return a, server
}

func TestConfigurationIsTestOnly(t *testing.T) {
	for _, key := range []string{"", "sk_live_secret", "rk_live_secret", "pk_test_secret", "sk_test_", "sk_test_secret\n", "sk_test_a:b"} {
		if _, err := New(Config{APIKey: key}); !errors.Is(err, ErrConfig) {
			t.Fatalf("unsafe key accepted: %v", err)
		}
	}
	for _, key := range []string{"sk_test_fixture", "rk_test_fixture"} {
		a, err := New(Config{APIKey: key})
		if err != nil {
			t.Fatal(err)
		}
		if a.endpoint != "https://api.stripe.com" {
			t.Fatal("production endpoint changed")
		}
		if strings.Contains(fmt.Sprint(a), key) || strings.Contains(fmt.Sprint(Config{APIKey: key}), key) {
			t.Fatal("key leaked in string")
		}
	}
}

func TestStrictArgumentsRejectBeforeNetwork(t *testing.T) {
	var calls atomic.Int32
	a, _ := testAdapter(t, func(http.ResponseWriter, *http.Request) { calls.Add(1) })
	for _, args := range []string{`null`, `[]`, `{}`, `{"customer":"cus_fixture","payment":"pi_fixture","amount_minor":1}`, `{"customer":"cus_fixture","payment":"ch_fixture","amount_minor":0}`, `{"customer":"cus_fixture","payment":"ch_fixture","amount_minor":1.0}`, `{"customer":"cus_fixture","payment":"ch_fixture","amount_minor":1e2}`, `{"customer":"cus_fixture","payment":"ch_fixture","amount_minor":9223372036854775808}`, `{"customer":"cus_fixture","payment":"ch_fixture","amount_minor":1,"amount_minor":2}`, `{"customer":"cus_fixture","payment":"ch_fixture","amount_minor":1,"key":"secret"}`, `{"customer":"cus_fixture","payment":"ch_fixture","amount_minor":1} {}`, `{"customer":"cus_fixture","payment":"ch_/escape","amount_minor":1}`} {
		if err := a.Validate(context.Background(), json.RawMessage(args)); !errors.Is(err, ErrArguments) {
			t.Fatalf("argument validation result: %v", err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid arguments reached Stripe")
	}
}

func TestChargeOwnershipAndRemainingAmount(t *testing.T) {
	for _, name := range []string{"customer", "live", "missing-live", "paid", "captured", "currency", "amount", "refunded", "charge-id", "object", "negative-refunded", "missing-captured-amount", "partial-capture"} {
		t.Run(name, func(t *testing.T) {
			charge := testCharge()
			switch name {
			case "customer":
				charge["customer"] = "cus_other"
			case "live":
				charge["livemode"] = true
			case "missing-live":
				delete(charge, "livemode")
			case "paid":
				charge["paid"] = false
			case "captured":
				charge["captured"] = false
			case "currency":
				charge["currency"] = "eur"
			case "amount":
				charge["amount_refunded"] = 95000
			case "refunded":
				charge["refunded"] = true
			case "charge-id":
				charge["id"] = "ch_other"
			case "object":
				charge["object"] = "payment_intent"
			case "negative-refunded":
				charge["amount_refunded"] = -1
			case "missing-captured-amount":
				delete(charge, "amount_captured")
			case "partial-capture":
				charge["amount_captured"] = 5000
			}
			var posts atomic.Int32
			a, _ := testAdapter(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					posts.Add(1)
				}
				_ = json.NewEncoder(w).Encode(charge)
			})
			if _, err := a.Refund(context.Background(), json.RawMessage(testArguments), testKey); !errors.Is(err, ErrValidation) {
				t.Fatalf("expected validation error: %v", err)
			}
			if posts.Load() != 0 {
				t.Fatal("invalid Charge refunded")
			}
		})
	}
}

func TestRefundStatusesAndStableKey(t *testing.T) {
	for _, status := range []string{"succeeded", "failed", "pending"} {
		t.Run(status, func(t *testing.T) {
			var reads, posts atomic.Int32
			a, _ := testAdapter(t, func(w http.ResponseWriter, r *http.Request) {
				user, password, ok := r.BasicAuth()
				if !ok || user != "sk_test_fixture" || password != "" {
					t.Error("invalid Stripe authentication")
				}
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/v1/charges/ch_fixture":
					reads.Add(1)
					if r.Header.Get("Idempotency-Key") != "" {
						t.Error("read carries refund key")
					}
					_ = json.NewEncoder(w).Encode(testCharge())
				case r.Method == http.MethodPost && r.URL.Path == "/v1/refunds":
					posts.Add(1)
					if err := r.ParseForm(); err != nil {
						t.Error(err)
					}
					if len(r.PostForm) != 2 || r.PostForm.Get("charge") != "ch_fixture" || r.PostForm.Get("amount") != "10000" || r.Header.Get("Idempotency-Key") != testKey {
						t.Error("wrong refund binding")
					}
					_ = json.NewEncoder(w).Encode(testRefund(status))
				default:
					t.Error("unexpected Stripe request")
					http.Error(w, "unexpected", 400)
				}
			})
			result, err := a.Refund(context.Background(), json.RawMessage(testArguments), testKey)
			if err != nil || result.Status != status || result.RefundID != "re_fixture" || result.AmountMinor != 10000 {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if reads.Load() != 1 || posts.Load() != 1 {
				t.Fatal("unexpected retry")
			}
		})
	}
}

func TestInvalidIdempotencyKeyNeverReads(t *testing.T) {
	var calls atomic.Int32
	a, _ := testAdapter(t, func(http.ResponseWriter, *http.Request) { calls.Add(1) })
	for _, key := range []string{"", strings.Repeat("a", 63), strings.Repeat("A", 64), strings.Repeat("a", 63) + "\n"} {
		if _, err := a.Refund(context.Background(), json.RawMessage(testArguments), key); !errors.Is(err, ErrArguments) {
			t.Fatalf("invalid key accepted: %v", err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid key reached Stripe")
	}
}

func TestAmbiguousRefundNeverRetries(t *testing.T) {
	for _, mode := range []string{"500", "timeout", "malformed", "wrong-amount", "unsupported-status", "oversized", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			var posts, redirects atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirects.Add(1) }))
			defer target.Close()
			a, _ := testAdapter(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					_ = json.NewEncoder(w).Encode(testCharge())
					return
				}
				posts.Add(1)
				switch mode {
				case "500":
					http.Error(w, "provider-secret", 500)
				case "timeout":
					time.Sleep(100 * time.Millisecond)
				case "malformed":
					fmt.Fprint(w, "provider-secret")
				case "wrong-amount":
					result := testRefund("succeeded")
					result["amount"] = 1
					_ = json.NewEncoder(w).Encode(result)
				case "unsupported-status":
					_ = json.NewEncoder(w).Encode(testRefund("requires_action"))
				case "oversized":
					fmt.Fprint(w, strings.Repeat("x", (1<<20)+1))
				case "redirect":
					http.Redirect(w, r, target.URL, 307)
				}
			})
			if mode == "timeout" {
				a.http.Timeout = 30 * time.Millisecond
			}
			_, err := a.Refund(context.Background(), json.RawMessage(testArguments), testKey)
			if !errors.Is(err, ErrOutcomeUnknown) || strings.Contains(err.Error(), "provider-secret") {
				t.Fatalf("unexpected result: %v", err)
			}
			if posts.Load() != 1 || redirects.Load() != 0 {
				t.Fatal("refund retried or redirected")
			}
		})
	}
}

func TestReadFailureAndKnownRejection(t *testing.T) {
	for _, phase := range []string{"read", "refund"} {
		t.Run(phase, func(t *testing.T) {
			var posts atomic.Int32
			a, _ := testAdapter(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet && phase == "refund" {
					_ = json.NewEncoder(w).Encode(testCharge())
					return
				}
				if r.Method == http.MethodPost {
					posts.Add(1)
				}
				http.Error(w, "secret body", 400)
			})
			_, err := a.Refund(context.Background(), json.RawMessage(testArguments), testKey)
			if phase == "read" {
				if !errors.Is(err, ErrRead) || posts.Load() != 0 {
					t.Fatal("read failure dispatched")
				}
			} else if !errors.Is(err, ErrRejected) || posts.Load() != 1 {
				t.Fatal("rejection lost")
			}
		})
	}
}

func TestNilAndZeroAdapterFailClosed(t *testing.T) {
	for _, adapter := range []*Adapter{nil, {}} {
		if err := adapter.Validate(context.Background(), json.RawMessage(testArguments)); !errors.Is(err, ErrConfig) {
			t.Fatal("invalid adapter validated")
		}
		if _, err := adapter.Refund(context.Background(), json.RawMessage(testArguments), testKey); !errors.Is(err, ErrConfig) {
			t.Fatal("invalid adapter refunded")
		}
		if _, err := NewHandler(adapter, HTTPConfig{GatewayBearer: gatewayToken, AllowedHosts: []string{"127.0.0.1:8099"}}); !errors.Is(err, ErrConfig) {
			t.Fatal("invalid adapter handler accepted")
		}
	}
}

func TestCredentialFormattingAndStructuredLogs(t *testing.T) {
	secret := "sk_test_probe" // Deliberately short, synthetic test credential.
	adapter, err := New(Config{APIKey: secret})
	if err != nil {
		t.Fatal(err)
	}
	values := []any{Config{APIKey: secret}, adapter, *adapter, HTTPConfig{GatewayBearer: gatewayToken, AllowedHosts: []string{"127.0.0.1:8099"}}}
	for _, value := range values {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			text := fmt.Sprintf(format, value)
			if strings.Contains(text, secret) || strings.Contains(text, gatewayToken) {
				t.Fatal("formatted credential leak")
			}
		}
		var output bytes.Buffer
		slog.New(slog.NewJSONHandler(&output, nil)).Info("fixture", "configuration", value)
		if strings.Contains(output.String(), secret) || strings.Contains(output.String(), gatewayToken) {
			t.Fatal("structured credential leak")
		}
	}
}

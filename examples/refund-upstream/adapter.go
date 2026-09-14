// Package refundupstream provides a Stripe test-mode refund example.
// It is not an authorization service or a durable dispatch journal.
package refundupstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const ToolName = "stripe.refund_payment"
const IdempotencyMetadataKey = "cadrena/idempotency-key"
const Schema = `{"type":"object","properties":{"customer":{"type":"string","minLength":5,"maxLength":255},"payment":{"type":"string","minLength":4,"maxLength":255},"amount_minor":{"type":"integer","minimum":1}},"required":["customer","payment","amount_minor"],"additionalProperties":false}`

var (
	ErrConfig         = errors.New("invalid Stripe test configuration")
	ErrArguments      = errors.New("invalid refund arguments")
	ErrValidation     = errors.New("test payment validation failed")
	ErrRead           = errors.New("test payment read failed")
	ErrRejected       = errors.New("refund request rejected")
	ErrOutcomeUnknown = errors.New("refund outcome unknown; do not retry")
)

// Config accepts test-mode secret or restricted keys. New uses only api.stripe.com.
type Config struct{ APIKey string }

// Adapter holds a fixed endpoint and a host-owned credential.
type Adapter struct {
	key      string
	endpoint string
	http     *http.Client
}

// String prevents accidental credential exposure through formatted values.
func (Config) String() string        { return "Stripe test configuration [redacted]" }
func (Adapter) String() string       { return "Stripe test adapter [redacted]" }
func (Config) GoString() string      { return "Stripe test configuration [redacted]" }
func (Adapter) GoString() string     { return "Stripe test adapter [redacted]" }
func (Config) LogValue() slog.Value  { return slog.StringValue("Stripe test configuration [redacted]") }
func (Adapter) LogValue() slog.Value { return slog.StringValue("Stripe test adapter [redacted]") }

func (a *Adapter) configured() bool {
	return a != nil && a.http != nil && a.endpoint != "" && (identifier(a.key, "sk_test_") || identifier(a.key, "rk_test_"))
}

func New(cfg Config) (*Adapter, error) {
	if !(identifier(cfg.APIKey, "sk_test_") || identifier(cfg.APIKey, "rk_test_")) {
		return nil, ErrConfig
	}
	return &Adapter{key: cfg.APIKey, endpoint: "https://api.stripe.com", http: newHTTPClient()}, nil
}

func newHTTPClient() *http.Client {
	t := &http.Transport{Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false,
		DialContext:     (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 32 << 10}
	return &http.Client{Transport: t, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrRejected }}
}

type arguments struct {
	Customer string
	Payment  string
	Amount   int64
}

func identifier(s, prefix string) bool {
	if !strings.HasPrefix(s, prefix) || len(s) <= len(prefix) || len(s) > 255 {
		return false
	}
	for _, ch := range s[len(prefix):] {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9') {
			return false
		}
	}
	return true
}

func parseArguments(raw json.RawMessage) (arguments, error) {
	var a arguments
	if len(raw) > 8192 {
		return a, ErrArguments
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return a, ErrArguments
	}
	seen := map[string]bool{}
	for d.More() {
		token, err = d.Token()
		if err != nil {
			return a, ErrArguments
		}
		key, ok := token.(string)
		if !ok || seen[key] {
			return a, ErrArguments
		}
		seen[key] = true
		switch key {
		case "customer":
			err = d.Decode(&a.Customer)
		case "payment":
			err = d.Decode(&a.Payment)
		case "amount_minor":
			err = d.Decode(&a.Amount)
		default:
			return a, ErrArguments
		}
		if err != nil {
			return a, ErrArguments
		}
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return a, ErrArguments
	}
	if _, err = d.Token(); err != io.EOF {
		return a, ErrArguments
	}
	if len(seen) != 3 || !identifier(a.Customer, "cus_") || !identifier(a.Payment, "ch_") || a.Amount <= 0 {
		return a, ErrArguments
	}
	return a, nil
}

// Validate reads the test Charge. It does not create a refund.
// The Gateway must also authorize the authenticated subject for this customer.
func (a *Adapter) Validate(ctx context.Context, raw json.RawMessage) error {
	if !a.configured() || ctx == nil {
		return ErrConfig
	}
	args, err := parseArguments(raw)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return a.validate(ctx, args)
}

func (a *Adapter) validate(ctx context.Context, args arguments) error {
	data, status, err := a.request(ctx, http.MethodGet, "/v1/charges/"+args.Payment, nil, "")
	if err != nil || status != http.StatusOK {
		return ErrRead
	}
	var charge struct {
		ID             string `json:"id"`
		Object         string `json:"object"`
		Customer       string `json:"customer"`
		Currency       string `json:"currency"`
		Live           *bool  `json:"livemode"`
		Paid           bool   `json:"paid"`
		Captured       bool   `json:"captured"`
		Refunded       bool   `json:"refunded"`
		Amount         *int64 `json:"amount"`
		AmountCaptured *int64 `json:"amount_captured"`
		AmountRefunded *int64 `json:"amount_refunded"`
	}
	if json.Unmarshal(data, &charge) != nil || charge.ID != args.Payment || charge.Object != "charge" || charge.Customer != args.Customer || charge.Currency != "usd" || charge.Live == nil || *charge.Live || !charge.Paid || !charge.Captured || charge.Refunded || charge.Amount == nil || charge.AmountCaptured == nil || charge.AmountRefunded == nil {
		return ErrValidation
	}
	if *charge.Amount <= 0 || *charge.AmountCaptured <= 0 || *charge.AmountCaptured > *charge.Amount || *charge.AmountRefunded < 0 || *charge.AmountRefunded > *charge.AmountCaptured || args.Amount > *charge.AmountCaptured-*charge.AmountRefunded {
		return ErrValidation
	}
	return nil
}

// Result preserves the provider status. Pending is not a successful refund.
type Result struct {
	RefundID    string `json:"refund_id"`
	Status      string `json:"status"`
	AmountMinor int64  `json:"amount_minor"`
	Currency    string `json:"currency"`
}

// Refund validates the Charge again, then attempts one refund request.
// The caller supplies the Gateway's stable journal key. It is not a tool argument.
func (a *Adapter) Refund(ctx context.Context, raw json.RawMessage, key string) (Result, error) {
	var result Result
	if !a.configured() || ctx == nil {
		return result, ErrConfig
	}
	args, err := parseArguments(raw)
	if err != nil {
		return result, err
	}
	if !validKey(key) {
		return result, ErrArguments
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err = a.validate(ctx, args); err != nil {
		return result, err
	}
	form := url.Values{"charge": {args.Payment}, "amount": {strconv.FormatInt(args.Amount, 10)}}
	data, status, err := a.request(ctx, http.MethodPost, "/v1/refunds", strings.NewReader(form.Encode()), key)
	if err != nil {
		return result, ErrOutcomeUnknown
	}
	if status >= 400 && status < 500 && status != 408 && status != 409 && status != 429 {
		return result, ErrRejected
	}
	if status != http.StatusOK {
		return result, ErrOutcomeUnknown
	}
	var refund struct {
		ID       string `json:"id"`
		Object   string `json:"object"`
		Charge   string `json:"charge"`
		Amount   int64  `json:"amount"`
		Currency string `json:"currency"`
		Status   string `json:"status"`
	}
	if json.Unmarshal(data, &refund) != nil || !identifier(refund.ID, "re_") || refund.Object != "refund" || refund.Charge != args.Payment || refund.Amount != args.Amount || refund.Currency != "usd" {
		return result, ErrOutcomeUnknown
	}
	switch refund.Status {
	case "succeeded", "failed", "pending":
	default:
		return result, ErrOutcomeUnknown
	}
	return Result{RefundID: refund.ID, Status: refund.Status, AmountMinor: refund.Amount, Currency: refund.Currency}, nil
}

func validKey(key string) bool {
	if len(key) != 64 {
		return false
	}
	for _, c := range key {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (a *Adapter) request(ctx context.Context, method, path string, body io.Reader, key string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, a.endpoint+path, body)
	if err != nil {
		return nil, 0, ErrRejected
	}
	req.SetBasicAuth(a.key, "")
	req.Header.Set("Accept", "application/json")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Idempotency-Key", key)
	}
	// No replayable body, persistent connection, proxy, redirect, or SDK retry.
	req.GetBody = nil
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, 0, ErrRejected
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return nil, resp.StatusCode, ErrRejected
	}
	return data, resp.StatusCode, nil
}

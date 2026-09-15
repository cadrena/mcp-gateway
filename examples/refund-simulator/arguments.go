package refundsimulator

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

const ToolName = "demo.refund_payment"
const Schema = `{"type":"object","properties":{"customer":{"type":"string","minLength":5,"maxLength":255},"payment":{"type":"string","minLength":4,"maxLength":255},"amount_minor":{"type":"integer","minimum":1}},"required":["customer","payment","amount_minor"],"additionalProperties":false}`

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

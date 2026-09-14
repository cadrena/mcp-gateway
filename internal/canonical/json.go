// Package canonical provides bounded JSON with unique object keys.
package canonical

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"unicode/utf8"
)

const MaxBytes = 64 << 10
const maxDepth = 32

var ErrInvalid = errors.New("invalid or unsupported JSON")

// JSON sorts object keys and removes insignificant whitespace. Numbers retain
// their JSON spelling; this is not RFC 8785 canonicalization.
func JSON(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > MaxBytes || !utf8.Valid(raw) || !validSurrogates(raw) {
		return nil, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := read(d, 0)
	if err != nil {
		return nil, ErrInvalid
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, ErrInvalid
	}
	result, err := json.Marshal(v)
	if err != nil || len(result) > MaxBytes {
		return nil, ErrInvalid
	}
	return result, nil
}

func read(d *json.Decoder, depth int) (any, error) {
	if depth > maxDepth {
		return nil, ErrInvalid
	}
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch t {
	case json.Delim('{'):
		m := map[string]any{}
		for d.More() {
			k, err := d.Token()
			if err != nil {
				return nil, err
			}
			name, ok := k.(string)
			if !ok {
				return nil, ErrInvalid
			}
			if _, ok = m[name]; ok {
				return nil, ErrInvalid
			}
			v, err := read(d, depth+1)
			if err != nil {
				return nil, err
			}
			m[name] = v
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return nil, ErrInvalid
		}
		return m, nil
	case json.Delim('['):
		a := []any{}
		for d.More() {
			v, err := read(d, depth+1)
			if err != nil {
				return nil, err
			}
			a = append(a, v)
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return nil, ErrInvalid
		}
		return a, nil
	default:
		if _, ok := t.(json.Delim); ok {
			return nil, ErrInvalid
		}
		return t, nil
	}
}

// encoding/json replaces unpaired UTF-16 escapes. Reject them before decoding
// so distinct malformed input cannot collapse into the replacement character.
func validSurrogates(raw []byte) bool {
	quoted := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			quoted = !quoted
			continue
		}
		if !quoted || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		n, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}

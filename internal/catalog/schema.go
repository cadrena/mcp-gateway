// Package catalog validates the Gateway's deliberately narrow schema profile.
package catalog

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/cadrena/mcp-gateway/internal/canonical"
	policyengine "github.com/cadrena/policy-engine"
)

var ErrSchema = errors.New("unsupported tool schema")
var ErrArguments = errors.New("invalid tool arguments")

type property struct {
	kind                                   string
	minimum, maximum, minLength, maxLength *int64
	enum                                   map[string]bool
}
type Schema struct {
	hash       [32]byte
	properties map[string]property
	required   map[string]bool
}

// New copies a strict flat object schema. Unknown keywords fail closed.
func New(raw json.RawMessage) (*Schema, error) {
	encoded, err := canonical.JSON(raw)
	if err != nil {
		return nil, ErrSchema
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(encoded, &root) != nil || root == nil {
		return nil, ErrSchema
	}
	if !keys(root, "type", "properties", "required", "additionalProperties") {
		return nil, ErrSchema
	}
	var kind string
	if json.Unmarshal(root["type"], &kind) != nil || kind != "object" || string(root["additionalProperties"]) != "false" {
		return nil, ErrSchema
	}
	var props map[string]json.RawMessage
	if json.Unmarshal(root["properties"], &props) != nil || props == nil || len(props) > 128 {
		return nil, ErrSchema
	}
	s := &Schema{hash: sha256.Sum256(encoded), properties: map[string]property{}, required: map[string]bool{}}
	for name, raw := range props {
		if name == "" || len(name) > 256 {
			return nil, ErrSchema
		}
		p, err := parseProperty(raw)
		if err != nil {
			return nil, ErrSchema
		}
		s.properties[name] = p
	}
	if required, ok := root["required"]; ok {
		var names []string
		if bytes.Equal(required, []byte("null")) || json.Unmarshal(required, &names) != nil {
			return nil, ErrSchema
		}
		for _, name := range names {
			if _, ok := s.properties[name]; !ok || s.required[name] {
				return nil, ErrSchema
			}
			s.required[name] = true
		}
	}
	return s, nil
}

func keys(m map[string]json.RawMessage, allowed ...string) bool {
	for key := range m {
		found := false
		for _, a := range allowed {
			if key == a {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func integer(raw json.RawMessage) (int64, error) {
	if len(raw) == 0 || strings.ContainsAny(string(raw), ".eE\"+ \t\r\n") {
		return 0, ErrArguments
	}
	return strconv.ParseInt(string(raw), 10, 64)
}

func parseProperty(raw json.RawMessage) (property, error) {
	p := property{}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || m == nil || !keys(m, "type", "minimum", "maximum", "minLength", "maxLength", "enum") {
		return p, ErrSchema
	}
	if json.Unmarshal(m["type"], &p.kind) != nil {
		return p, ErrSchema
	}
	switch p.kind {
	case "string", "integer", "boolean", "null":
	default:
		return p, ErrSchema
	}
	for key, target := range map[string]**int64{"minimum": &p.minimum, "maximum": &p.maximum, "minLength": &p.minLength, "maxLength": &p.maxLength} {
		if value, ok := m[key]; ok {
			if (key == "minimum" || key == "maximum") && p.kind != "integer" {
				return p, ErrSchema
			}
			if (key == "minLength" || key == "maxLength") && p.kind != "string" {
				return p, ErrSchema
			}
			n, err := integer(value)
			if err != nil || (strings.Contains(key, "Length") && n < 0) {
				return p, ErrSchema
			}
			*target = &n
		}
	}
	if p.minimum != nil && p.maximum != nil && *p.minimum > *p.maximum {
		return p, ErrSchema
	}
	if p.minLength != nil && p.maxLength != nil && *p.minLength > *p.maxLength {
		return p, ErrSchema
	}
	if enum, ok := m["enum"]; ok {
		var items []json.RawMessage
		if json.Unmarshal(enum, &items) != nil || len(items) == 0 || len(items) > 128 {
			return p, ErrSchema
		}
		p.enum = map[string]bool{}
		for _, item := range items {
			_, norm, err := p.value(item, false)
			if err != nil || p.enum[string(norm)] {
				return p, ErrSchema
			}
			p.enum[string(norm)] = true
		}
	}
	return p, nil
}

// Hash returns a copy of the pinned schema digest. Array ordering is retained.
func (s *Schema) Hash() [32]byte {
	if s == nil {
		return [32]byte{}
	}
	return s.hash
}

// Validate returns independent canonical arguments and exact Engine scalars.
// Integer inputs reject fractions and exponents, including mathematically whole values.
func (s *Schema) Validate(args json.RawMessage) (json.RawMessage, map[string]policyengine.Value, error) {
	if s == nil || s.properties == nil {
		return nil, nil, ErrSchema
	}
	encoded, err := canonical.JSON(args)
	if err != nil {
		return nil, nil, ErrArguments
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(encoded, &fields) != nil || fields == nil {
		return nil, nil, ErrArguments
	}
	for name := range s.required {
		if _, ok := fields[name]; !ok {
			return nil, nil, ErrArguments
		}
	}
	values := make(map[string]policyengine.Value, len(fields))
	normalized := make(map[string]json.RawMessage, len(fields))
	for name, raw := range fields {
		p, ok := s.properties[name]
		if !ok {
			return nil, nil, ErrArguments
		}
		v, norm, err := p.value(raw, true)
		if err != nil {
			return nil, nil, ErrArguments
		}
		values[name] = v
		normalized[name] = norm
	}
	result, err := json.Marshal(normalized)
	if err != nil {
		return nil, nil, ErrArguments
	}
	return result, values, nil
}

func (p property) value(raw json.RawMessage, checkEnum bool) (policyengine.Value, json.RawMessage, error) {
	var value policyengine.Value
	var norm []byte
	switch p.kind {
	case "string":
		var text string
		if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &text) != nil {
			return value, nil, ErrArguments
		}
		length := int64(utf8.RuneCountInString(text))
		if p.minLength != nil && length < *p.minLength || p.maxLength != nil && length > *p.maxLength {
			return value, nil, ErrArguments
		}
		var err error
		value, err = policyengine.NewStringValue(text)
		if err != nil {
			return value, nil, ErrArguments
		}
		norm, _ = json.Marshal(text)
	case "integer":
		n, err := integer(raw)
		if err != nil {
			return value, nil, ErrArguments
		}
		if p.minimum != nil && n < *p.minimum || p.maximum != nil && n > *p.maximum {
			return value, nil, ErrArguments
		}
		value = policyengine.NewIntegerValue(n)
		norm = []byte(strconv.FormatInt(n, 10))
	case "boolean":
		if string(raw) != "true" && string(raw) != "false" {
			return value, nil, ErrArguments
		}
		value = policyengine.NewBooleanValue(string(raw) == "true")
		norm = append([]byte(nil), raw...)
	case "null":
		if string(raw) != "null" {
			return value, nil, ErrArguments
		}
		value = policyengine.NewNullValue()
		norm = []byte("null")
	default:
		return value, nil, ErrArguments
	}
	if checkEnum && p.enum != nil && !p.enum[string(norm)] {
		return value, nil, ErrArguments
	}
	return value, norm, nil
}

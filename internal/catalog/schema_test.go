package catalog

import (
	"encoding/json"
	"math"
	"strings"
	"sync"
	"testing"

	policyengine "github.com/cadrena/policy-engine"
)

const validSchema = `{"type":"object","properties":{"amount":{"type":"integer","minimum":1,"maximum":9223372036854775807},"label":{"type":"string","minLength":1,"maxLength":2},"flag":{"type":"boolean"},"empty":{"type":"null"}},"required":["amount"],"additionalProperties":false}`

func TestValidateExactScalarsAndCanonicalOrdering(t *testing.T) {
	s, err := New(json.RawMessage(validSchema))
	if err != nil {
		t.Fatal(err)
	}
	got, values, err := s.Validate(json.RawMessage(`{"label":"😀é","flag":true,"amount":9223372036854775807,"empty":null}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"amount":9223372036854775807,"empty":null,"flag":true,"label":"😀é"}` {
		t.Fatal("incorrect canonical ordering")
	}
	if n, ok := values["amount"].Integer(); !ok || n != math.MaxInt64 {
		t.Fatal("integer precision lost")
	}
	if v, ok := values["flag"].Boolean(); !ok || !v {
		t.Fatal("boolean lost")
	}
	if !values["empty"].IsNull() {
		t.Fatal("null lost")
	}
	if v, ok := values["label"].StringValue(); !ok || v != "😀é" {
		t.Fatal("string lost")
	}
}

func TestSchemaRejectsUnsupportedConstraints(t *testing.T) {
	bad := []string{
		`null`, `[]`, `{}`, `{"type":"object","properties":{}}`,
		`{"type":"object","properties":{},"additionalProperties":true}`,
		`{"type":"object","properties":{},"additionalProperties":false,"allOf":[]}`,
		`{"type":"object","properties":{},"additionalProperties":false,"required":["unknown"]}`,
		`{"type":"object","properties":{},"additionalProperties":false,"required":null}`,
		`{"type":"object","properties":{"n":{"type":"integer"}},"additionalProperties":false,"required":["n","n"]}`,
	}
	for _, property := range []string{`{"type":"number"}`, `{"type":"array","items":{"type":"string"}}`, `{"type":"object","properties":{}}`, `{"type":["string","null"]}`, `{"type":"string","pattern":"x"}`, `{"type":"integer","minimum":1.0}`, `{"type":"integer","minimum":1e2}`, `{"type":"integer","minimum":9223372036854775808}`, `{"type":"integer","minimum":5,"maximum":4}`, `{"type":"boolean","maximum":2}`, `{"type":"integer","maxLength":2}`, `{"type":"string","minLength":-1}`, `{"type":"string","minLength":5,"maxLength":2}`, `{"type":"integer","enum":[1,1]}`, `{"type":"integer","enum":["1"]}`, `{"type":"integer","enum":[]}`, `{"type":"integer","enum":null}`, `{"type":"string","enum":[null]}`, `{"type":"string","format":"email"}`} {
		bad = append(bad, `{"type":"object","properties":{"n":`+property+`},"additionalProperties":false}`)
	}
	for _, raw := range bad {
		if _, err := New(json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted unsupported schema: %s", raw)
		}
	}
}

func TestArgumentsRejectCoercionAndUnknownFields(t *testing.T) {
	s, err := New(json.RawMessage(validSchema))
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`null`, `[]`, `{}`, `{"amount":1,"extra":1}`, `{"amount":1,"amount":2}`, `{"amount":1,"\u0061mount":2}`, `{"amount":1} {}`, `{"amount":"1"}`, `{"amount":1.0}`, `{"amount":1e0}`, `{"amount":9223372036854775808}`, `{"amount":-9223372036854775809}`, `{"amount":0}`, `{"amount":true}`, `{"amount":null}`, `{"amount":{}}`, `{"amount":[]}`, `{"amount":1,"flag":1}`, `{"amount":1,"empty":false}`, `{"amount":1,"label":null}`, `{"amount":1,"label":""}`, `{"amount":1,"label":"abc"}`} {
		if canonical, values, err := s.Validate(json.RawMessage(raw)); err == nil || canonical != nil || values != nil {
			t.Fatalf("invalid arguments passed: %s", raw)
		}
	}
}

func TestEnumAndIntegerNormalization(t *testing.T) {
	s, err := New(json.RawMessage(`{"type":"object","properties":{"n":{"type":"integer","enum":[0,-9223372036854775808]},"s":{"type":"string","enum":["é"]},"b":{"type":"boolean","enum":[false]},"z":{"type":"null","enum":[null]}},"additionalProperties":false}`))
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := s.Validate(json.RawMessage(`{"n":-0,"s":"é","b":false,"z":null}`))
	if err != nil || string(got) != `{"b":false,"n":0,"s":"é","z":null}` {
		t.Fatal("enum normalization failed")
	}
	if _, v, err := s.Validate(json.RawMessage(`{"n":-9223372036854775808}`)); err != nil {
		t.Fatal(err)
	} else if n, _ := v["n"].Integer(); n != math.MinInt64 {
		t.Fatal("minimum integer lost")
	}
	for _, raw := range []string{`{"n":1}`, `{"s":"e"}`, `{"b":true}`} {
		if _, _, err := s.Validate(json.RawMessage(raw)); err == nil {
			t.Fatal("enum constraint ignored")
		}
	}
}

func TestSchemaHashAndImmutability(t *testing.T) {
	raw := json.RawMessage(validSchema)
	s, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	hash := s.Hash()
	raw[0] = '!'
	reordered := `{"additionalProperties":false,"required":["amount"],"properties":{"empty":{"type":"null"},"flag":{"type":"boolean"},"label":{"maxLength":2,"minLength":1,"type":"string"},"amount":{"maximum":9223372036854775807,"minimum":1,"type":"integer"}},"type":"object"}`
	other, err := New(json.RawMessage(reordered))
	if err != nil || other.Hash() != hash {
		t.Fatal("object ordering changed schema hash")
	}
	changed, err := New(json.RawMessage(strings.Replace(validSchema, `"minimum":1`, `"minimum":2`, 1)))
	if err != nil || changed.Hash() == hash {
		t.Fatal("constraint change did not change hash")
	}
	args := json.RawMessage(`{"amount":3}`)
	out, values, err := s.Validate(args)
	if err != nil {
		t.Fatal(err)
	}
	args[0] = '!'
	out[0] = '!'
	values["amount"] = policyengine.NewIntegerValue(4)
	again, v, err := s.Validate(json.RawMessage(`{"amount":3}`))
	n, _ := v["amount"].Integer()
	if err != nil || string(again) != `{"amount":3}` || n != 3 || s.Hash() != hash {
		t.Fatal("caller mutation changed schema")
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := s.Validate(json.RawMessage(`{"amount":3}`)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}

func TestZeroSchemaFailsClosed(t *testing.T) {
	for _, s := range []*Schema{nil, {}} {
		if _, _, err := s.Validate(json.RawMessage(`{}`)); err == nil {
			t.Fatal("zero schema accepted")
		}
	}
}

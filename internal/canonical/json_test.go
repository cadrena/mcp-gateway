package canonical

import (
	"bytes"
	"strings"
	"testing"
)

func TestJSONCanonicalAndExactNumbers(t *testing.T) {
	got, err := JSON([]byte(` { "z":9223372036854775807,"a":{"y":1e99,"x":-0},"b":[true,null,"\ud83d\ude00"] } `))
	if err != nil || string(got) != `{"a":{"x":-0,"y":1e99},"b":[true,null,"😀"],"z":9223372036854775807}` {
		t.Fatalf("unexpected canonical form: %s %v", got, err)
	}
	again, err := JSON(got)
	if err != nil || !bytes.Equal(got, again) {
		t.Fatal("canonical output is not stable")
	}
}

func TestJSONRejectsAmbiguousOrUnboundedInputs(t *testing.T) {
	inputs := []string{``, `{"x":1,"x":2}`, `{"x":1,"\u0078":2}`, `{"a":{"x":1,"x":2}}`, `{} true`, `{"x":NaN}`, `{"x":01}`, `{"x":1.}`, `{"x":+1}`, `{"x":Infinity}`, `{"x":"\ud800"}`, `{"x":"\udc00"}`, `{"x":"\ud800\u0041"}`, `{"x":"\ud800\udc00\udc00"}`, `{"x":"` + string([]byte{0xff}) + `"}`, strings.Repeat("[", 34) + `0` + strings.Repeat("]", 34), `"` + strings.Repeat("a", MaxBytes) + `"`}
	for _, raw := range inputs {
		if _, err := JSON([]byte(raw)); err == nil {
			t.Fatalf("accepted invalid JSON of length %d", len(raw))
		}
	}
}

func TestJSONEscapedBackslashAndNoAliasing(t *testing.T) {
	raw := []byte(`{"x":"\\ud800","y":"\ufffd"}`)
	got, err := JSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] = '!'
	if got[0] != '{' {
		t.Fatal("output aliases input")
	}
}

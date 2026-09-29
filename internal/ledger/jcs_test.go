package ledger

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

// RFC 8785 Appendix B: IEEE-754 bit patterns and their canonical text.
func TestCanonicalizeNumbersRFC8785AppendixB(t *testing.T) {
	cases := []struct {
		bits uint64
		want string
	}{
		{0x0000000000000000, "0"},
		{0x8000000000000000, "0"},
		{0x0000000000000001, "5e-324"},
		{0x8000000000000001, "-5e-324"},
		{0x7fefffffffffffff, "1.7976931348623157e+308"},
		{0xffefffffffffffff, "-1.7976931348623157e+308"},
		{0x4340000000000000, "9007199254740992"},
		{0xc340000000000000, "-9007199254740992"},
		{0x4430000000000000, "295147905179352830000"},
		{0x44b52d02c7e14af5, "9.999999999999997e+22"},
		{0x44b52d02c7e14af6, "1e+23"},
		{0x44b52d02c7e14af7, "1.0000000000000001e+23"},
		{0x444b1ae4d6e2ef4e, "999999999999999700000"},
		{0x444b1ae4d6e2ef4f, "999999999999999900000"},
		{0x444b1ae4d6e2ef50, "1e+21"},
		{0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"},
		{0x3eb0c6f7a0b5ed8d, "0.000001"},
		{0x41b3de4355555553, "333333333.3333332"},
		{0x41b3de4355555554, "333333333.33333325"},
		{0x41b3de4355555555, "333333333.3333333"},
		{0x41b3de4355555556, "333333333.3333334"},
		{0x41b3de4355555557, "333333333.33333343"},
		{0xbecbf647612f3696, "-0.0000033333333333333333"},
		{0x43143ff3c1cb0959, "1424953923781206.2"},
	}
	impls := map[string]func(any) ([]byte, error){"stdlib": Canonicalize, "ref": canonicalizeRef}
	for name, canon := range impls {
		for _, c := range cases {
			got, err := canon(math.Float64frombits(c.bits))
			if err != nil {
				t.Errorf("%s %016x: %v", name, c.bits, err)
				continue
			}
			if string(got) != c.want {
				t.Errorf("%s %016x: got %s, want %s", name, c.bits, got, c.want)
			}
		}
		for _, f := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
			if _, err := canon(f); err == nil {
				t.Errorf("%s %v: expected an error", name, f)
			}
		}
	}
}

// RFC 8785 §3.2.2 example (numbers, string escaping, literals, key order).
func TestCanonicalizeRFC8785Example(t *testing.T) {
	in := `{
		"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
		"string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
		"literals": [null, true, false]
	}`
	want := `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`
	got := mustCanon(t, decode(t, in))
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

// RFC 8785 §3.2.3: keys sort by UTF-16 code units, so U+1F600 (D83D DE00) sorts before U+FB33.
func TestCanonicalizeKeyOrderUTF16(t *testing.T) {
	in := `{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}`
	want := "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"\u00f6\":\"Latin Small Letter O With Diaeresis\",\"\u20ac\":\"Euro Sign\",\"\U0001F600\":\"Emoji: Grinning Face\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}"
	if got := mustCanon(t, decode(t, in)); got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestCanonicalizeStrings(t *testing.T) {
	cases := map[string]string{
		"\b\t\n\f\r":       `"\b\t\n\f\r"`,
		"\x00\x1f":         `"\u0000\u001f"`,
		"\x7f":             "\"\x7f\"",         // DEL is not escaped
		"\u2028\u2029":     "\"\u2028\u2029\"", // encoding/json would escape these; JCS must not
		"<&>":              `"<&>"`,            // no HTML escaping
		`quote " back \ /`: `"quote \" back \\ /"`,
	}
	for in, want := range cases {
		if got := mustCanon(t, in); got != want {
			t.Errorf("%q: got %s, want %s", in, got, want)
		}
	}
	if _, err := Canonicalize("bad \xff utf8"); err == nil {
		t.Error("invalid UTF-8 string: expected an error")
	}
	if _, err := Canonicalize(map[string]any{"bad \xff": 1}); err == nil {
		t.Error("invalid UTF-8 key: expected an error")
	}
}

func TestCanonicalizeIntegerLimits(t *testing.T) {
	if got := mustCanon(t, int64(1<<53)); got != "9007199254740992" {
		t.Errorf("2^53: got %s", got)
	}
	for _, v := range []any{int64(1<<53 + 1), int64(-(1<<53 + 1)), uint64(1 << 60)} {
		if _, err := Canonicalize(v); err == nil {
			t.Errorf("%v: expected an error (not exactly representable)", v)
		}
	}
}

func TestCanonicalizeGoTypes(t *testing.T) {
	v := map[string]any{
		"strs": []string{"b", "a"},
		"m":    map[string]int{"z": 1, "a": 2},
		"nil":  []any(nil),
		"num":  json.Number("1.50"),
		"i":    int32(-7),
	}
	want := `{"i":-7,"m":{"a":2,"z":1},"nil":null,"num":1.5,"strs":["b","a"]}`
	if got := mustCanon(t, v); got != want {
		t.Errorf("got %s, want %s", got, want)
	}
	if _, err := Canonicalize(struct{ A int }{1}); err == nil {
		t.Error("struct: expected an error")
	}
	if _, err := Canonicalize([]byte("abc")); err == nil {
		t.Error("[]byte: expected an error (encoding/json would silently base64 it)")
	}
}

func decode(t *testing.T, s string) any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func mustCanon(t *testing.T, v any) string {
	t.Helper()
	b, err := Canonicalize(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

package ledger

import (
	"encoding/json"
	"math"
	"math/rand/v2"
	"strings"
	"testing"
)

// Canonicalize (stdlib) and canonicalizeRef (independent implementation) must agree byte for
// byte, on random values and on values read back from JSON.
func TestCanonicalizeDifferential(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for i := range 20000 {
		v := randomValue(r, 0)
		std, err := Canonicalize(v)
		if err != nil {
			t.Fatalf("case %d: stdlib: %v", i, err)
		}
		ref, err := canonicalizeRef(v)
		if err != nil {
			t.Fatalf("case %d: ref: %v", i, err)
		}
		if string(std) != string(ref) {
			in, _ := json.Marshal(v)
			t.Fatalf("case %d mismatch\n input %s\n std   %s\n ref   %s", i, in, std, ref)
		}
		// Parsing the canonical form and canonicalizing again is a fixed point.
		again, err := Canonicalize(decode(t, string(std)))
		if err != nil || string(again) != string(std) {
			t.Fatalf("case %d: not a fixed point: %s vs %s (%v)", i, again, std, err)
		}
	}
}

func randomValue(r *rand.Rand, depth int) any {
	k := r.IntN(7)
	if depth > 3 {
		k = r.IntN(4)
	}
	switch k {
	case 0:
		return randomFloat(r)
	case 1:
		return randomString(r)
	case 2:
		return r.IntN(2) == 0
	case 3:
		return nil
	case 4:
		a := make([]any, r.IntN(4))
		for i := range a {
			a[i] = randomValue(r, depth+1)
		}
		return a
	default:
		m := map[string]any{}
		for range r.IntN(5) {
			m[randomString(r)] = randomValue(r, depth+1)
		}
		return m
	}
}

func randomFloat(r *rand.Rand) float64 {
	for {
		var f float64
		switch r.IntN(4) {
		case 0:
			f = math.Float64frombits(r.Uint64()) // any bit pattern: subnormals, huge, tiny
		case 1:
			f = float64(r.Int64N(1<<53)) - float64(1<<52)
		case 2:
			f = r.Float64() * math.Pow(10, float64(r.IntN(60)-30))
		default:
			f = math.Round(r.Float64()*1e6) / 1e6 // cost-like values
		}
		if !math.IsNaN(f) && !math.IsInf(f, 0) {
			return f
		}
	}
}

var alphabet = []rune("aZ09 \"\\/\b\f\n\r\t\x00\x1f\x7f<>&é€\u0080  דּ\U0001F600\U00010000￿")

func randomString(r *rand.Rand) string {
	var b strings.Builder
	for range r.IntN(8) {
		b.WriteRune(alphabet[r.IntN(len(alphabet))])
	}
	return b.String()
}

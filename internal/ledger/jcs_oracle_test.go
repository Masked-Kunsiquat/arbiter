package ledger

// An independent RFC 8785 implementation, used only as a test oracle for Canonicalize (which
// uses the standard library). If a future Go release changes canonical output, the differential
// test and the golden vectors fail before any ledger silently rehashes.

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

func canonicalizeRef(v any) ([]byte, error) {
	return refAppendValue(nil, reflect.ValueOf(v))
}

func refAppendValue(b []byte, v reflect.Value) ([]byte, error) {
	if !v.IsValid() {
		return append(b, "null"...), nil
	}
	if n, ok := v.Interface().(json.Number); ok {
		f, err := strconv.ParseFloat(string(n), 64)
		if err != nil {
			return nil, fmt.Errorf("jcs: bad number %q: %w", n, err)
		}
		return refAppendNumber(b, f)
	}
	switch v.Kind() {
	case reflect.Interface, reflect.Pointer:
		if v.IsNil() {
			return append(b, "null"...), nil
		}
		return refAppendValue(b, v.Elem())
	case reflect.Bool:
		return strconv.AppendBool(b, v.Bool()), nil
	case reflect.String:
		return refAppendString(b, v.String())
	case reflect.Float32, reflect.Float64:
		return refAppendNumber(b, v.Float())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n := v.Int()
		if n > maxExactInt || n < -maxExactInt {
			return nil, fmt.Errorf("jcs: integer %d is not exactly representable as a double", n)
		}
		return strconv.AppendInt(b, n, 10), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n := v.Uint()
		if n > maxExactInt {
			return nil, fmt.Errorf("jcs: integer %d is not exactly representable as a double", n)
		}
		return strconv.AppendUint(b, n, 10), nil
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.IsNil() {
			return append(b, "null"...), nil
		}
		b = append(b, '[')
		for i := range v.Len() {
			if i > 0 {
				b = append(b, ',')
			}
			var err error
			if b, err = refAppendValue(b, v.Index(i)); err != nil {
				return nil, err
			}
		}
		return append(b, ']'), nil
	case reflect.Map:
		if v.Type().Key().Kind() != reflect.String {
			return nil, fmt.Errorf("jcs: map key type %s is not string", v.Type().Key())
		}
		if v.IsNil() {
			return append(b, "null"...), nil
		}
		keys := make([]string, 0, v.Len())
		for _, k := range v.MapKeys() {
			if !utf8.ValidString(k.String()) {
				return nil, fmt.Errorf("jcs: invalid UTF-8 in key %q", k.String())
			}
			keys = append(keys, k.String())
		}
		slices.SortFunc(keys, refCompareUTF16)
		b = append(b, '{')
		for i, k := range keys {
			if i > 0 {
				b = append(b, ',')
			}
			b, _ = refAppendString(b, k)
			b = append(b, ':')
			var err error
			if b, err = refAppendValue(b, v.MapIndex(reflect.ValueOf(k).Convert(v.Type().Key()))); err != nil {
				return nil, err
			}
		}
		return append(b, '}'), nil
	}
	return nil, fmt.Errorf("jcs: unsupported type %s", v.Type())
}

// refAppendNumber formats f as ECMAScript's Number.prototype.toString does (RFC 8785 §3.2.2.3):
// shortest round-trip digits, positional notation for 1e-6 <= |f| < 1e21, exponent otherwise.
func refAppendNumber(b []byte, f float64) ([]byte, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return nil, errors.New("jcs: NaN and Infinity are not valid JSON")
	}
	if f == 0 { // also -0
		return append(b, '0'), nil
	}
	format := byte('f')
	if abs := math.Abs(f); abs < 1e-6 || abs >= 1e21 {
		format = 'e'
	}
	b = strconv.AppendFloat(b, f, format, -1, 64)
	if format == 'e' {
		// Go writes at least two exponent digits ("1e-07"); ECMAScript writes "1e-7".
		n := len(b)
		if n >= 4 && b[n-4] == 'e' && b[n-2] == '0' {
			b[n-2] = b[n-1]
			b = b[:n-1]
		}
	}
	return b, nil
}

// refAppendString writes s with the minimal escaping of RFC 8785 §3.2.2.2: only '"', '\\' and
// control characters below U+0020 are escaped; everything else (including U+2028/2029,
// DEL and non-ASCII) is written as UTF-8.
func refAppendString(b []byte, s string) ([]byte, error) {
	if !utf8.ValidString(s) {
		return nil, fmt.Errorf("jcs: invalid UTF-8 in string %q", s)
	}
	const hex = "0123456789abcdef"
	b = append(b, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			b = append(b, '\\', c)
		case c >= 0x20:
			b = append(b, c)
		case c == '\b':
			b = append(b, '\\', 'b')
		case c == '\t':
			b = append(b, '\\', 't')
		case c == '\n':
			b = append(b, '\\', 'n')
		case c == '\f':
			b = append(b, '\\', 'f')
		case c == '\r':
			b = append(b, '\\', 'r')
		default:
			b = append(b, '\\', 'u', '0', '0', hex[c>>4], hex[c&0xf])
		}
	}
	return append(b, '"'), nil
}

// refCompareUTF16 orders object keys by their UTF-16 code units (RFC 8785 §3.2.3), which differs
// from Go's byte order for characters above U+FFFF.
func refCompareUTF16(a, b string) int {
	return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(b)))
}

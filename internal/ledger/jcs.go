package ledger

import (
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"unicode/utf8"
)

// Canonicalize returns the RFC 8785 JSON Canonicalization Scheme (JCS) encoding of v.
//
// The canonical bytes come from the standard library (encoding/json/jsontext, part of the Go
// API since 1.27). This function first applies Arbiter's stricter input rules, because the
// ledger must fail loudly rather than record something other than what the core meant:
//
//   - v is built from nil, bool, string, float64, integer kinds, json.Number, slices, arrays
//     and maps with string keys; anything else ([]byte, structs, …) is an error;
//   - integers must be exactly representable as a double (|n| <= 2^53), since JCS numbers are
//     IEEE-754 doubles and would otherwise be rounded silently;
//   - NaN, ±Inf and invalid UTF-8 are errors.
func Canonicalize(v any) ([]byte, error) {
	norm, err := normalize(reflect.ValueOf(v))
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(norm)
	if err != nil {
		return nil, fmt.Errorf("jcs: %w", err)
	}
	out := jsontext.Value(b)
	if err := out.Canonicalize(); err != nil {
		return nil, fmt.Errorf("jcs: %w", err)
	}
	return out, nil
}

const maxExactInt = 1 << 53

// normalize validates v and converts it to plain JSON types (map[string]any, []any, string,
// float64, bool, nil).
func normalize(v reflect.Value) (any, error) {
	if !v.IsValid() {
		return nil, nil
	}
	if n, ok := v.Interface().(json.Number); ok {
		f, err := strconv.ParseFloat(string(n), 64)
		if err != nil {
			return nil, fmt.Errorf("jcs: bad number %q: %w", n, err)
		}
		return checkFloat(f)
	}
	switch v.Kind() {
	case reflect.Interface, reflect.Pointer:
		if v.IsNil() {
			return nil, nil
		}
		return normalize(v.Elem())
	case reflect.Bool:
		return v.Bool(), nil
	case reflect.String:
		if !utf8.ValidString(v.String()) {
			return nil, fmt.Errorf("jcs: invalid UTF-8 in string %q", v.String())
		}
		return v.String(), nil
	case reflect.Float32, reflect.Float64:
		return checkFloat(v.Float())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n := v.Int()
		if n > maxExactInt || n < -maxExactInt {
			return nil, fmt.Errorf("jcs: integer %d is not exactly representable as a double", n)
		}
		return float64(n), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if v.Uint() > maxExactInt {
			return nil, fmt.Errorf("jcs: integer %d is not exactly representable as a double", v.Uint())
		}
		return float64(v.Uint()), nil
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return nil, errors.New("jcs: byte slices are not supported (encode them as hex strings)")
		}
		if v.Kind() == reflect.Slice && v.IsNil() {
			return nil, nil
		}
		out := make([]any, v.Len())
		for i := range out {
			var err error
			if out[i], err = normalize(v.Index(i)); err != nil {
				return nil, err
			}
		}
		return out, nil
	case reflect.Map:
		if v.Type().Key().Kind() != reflect.String {
			return nil, fmt.Errorf("jcs: map key type %s is not string", v.Type().Key())
		}
		if v.IsNil() {
			return nil, nil
		}
		out := make(map[string]any, v.Len())
		for it := v.MapRange(); it.Next(); {
			k := it.Key().String()
			if !utf8.ValidString(k) {
				return nil, fmt.Errorf("jcs: invalid UTF-8 in key %q", k)
			}
			var err error
			if out[k], err = normalize(it.Value()); err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("jcs: unsupported type %s", v.Type())
}

func checkFloat(f float64) (any, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return nil, errors.New("jcs: NaN and Infinity are not valid JSON")
	}
	return f, nil
}

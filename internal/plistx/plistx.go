// Package plistx has small helpers over howett.net/plist for the loosely-typed
// dictionaries Apple's services return.
package plistx

import (
	"fmt"
	"strconv"

	"howett.net/plist"
)

// Decode parses an XML or binary plist whose root is a dictionary.
func Decode(data []byte) (map[string]any, error) {
	var v any
	if _, err := plist.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("plist root is %T, not a dictionary", v)
	}
	return m, nil
}

// DecodeAny parses a plist of any root type.
func DecodeAny(data []byte) (any, error) {
	var v any
	_, err := plist.Unmarshal(data, &v)
	return v, err
}

// EncodeXML serialises v as an XML plist.
func EncodeXML(v any) ([]byte, error) {
	return plist.MarshalIndent(v, plist.XMLFormat, "\t")
}

// Dict returns v as a dictionary (nil when it is not one).
func Dict(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// List returns v as a list.
func List(v any) []any {
	l, _ := v.([]any)
	return l
}

// Str returns v as a string ("" for nil; numbers are formatted).
func Str(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case []byte:
		return string(x)
	case uint64, int64, int, float64, bool:
		return fmt.Sprint(x)
	}
	return fmt.Sprint(v)
}

// Int returns v as an int64 (0 when absent/unparseable).
func Int(v any) int64 {
	switch x := v.(type) {
	case int:
		return int64(x)
	case int64:
		return x
	case uint64:
		return int64(x)
	case float64:
		return int64(x)
	case bool:
		if x {
			return 1
		}
		return 0
	case string:
		n, _ := strconv.ParseInt(x, 10, 64)
		return n
	}
	return 0
}

// Bytes returns v as a byte slice (nil when it is not data).
func Bytes(v any) []byte {
	b, _ := v.([]byte)
	return b
}

// Has reports whether v is non-nil (and non-empty for strings).
func Has(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case string:
		return x != ""
	}
	return true
}

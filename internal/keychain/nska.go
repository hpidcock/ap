package keychain

import (
	"errors"
	"strings"

	"howett.net/plist"
)

// ExpandKeyedArchive resolves an NSKeyedArchiver bplist's UID object graph into plain
// Go values (maps, slices, []byte, string, numbers). Archived NSData / NSString /
// NSArray objects are unwrapped to their payload.
func ExpandKeyedArchive(data []byte) (any, error) {
	var top map[string]any
	if _, err := plist.Unmarshal(data, &top); err != nil {
		return nil, err
	}
	objects, _ := top["$objects"].([]any)
	if objects == nil {
		return nil, errors.New("nska: no $objects")
	}
	var resolve func(node any, depth int) any
	resolve = func(node any, depth int) any {
		if depth > 64 {
			return nil
		}
		switch n := node.(type) {
		case plist.UID:
			if int(n) < len(objects) {
				return resolve(objects[n], depth+1)
			}
			return nil
		case string:
			if n == "$null" {
				return nil
			}
			return n
		case map[string]any:
			_, isObject := n["$class"]
			out := map[string]any{}
			for k, v := range n {
				if strings.HasPrefix(k, "$") {
					continue
				}
				out[k] = resolve(v, depth+1)
			}
			if isObject {
				if v, ok := out["NS.data"]; ok {
					return v
				}
				if v, ok := out["NS.string"]; ok {
					return v
				}
				if v, ok := out["NS.objects"]; ok {
					return v
				}
			}
			return out
		case []any:
			out := make([]any, len(n))
			for i, v := range n {
				out[i] = resolve(v, depth+1)
			}
			return out
		}
		return node
	}
	if t, ok := top["$top"].(map[string]any); ok {
		if root, ok := t["root"]; ok {
			return resolve(root, 0), nil
		}
	}
	return resolve(top["$top"], 0), nil
}

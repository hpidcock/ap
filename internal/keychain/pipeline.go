package keychain

import (
	"crypto/ecdh"
	"encoding/base64"
	"sort"
	"strings"
	"time"

	"howett.net/plist"

	"github.com/hpidcock/ap/internal/cloudkit"
	"github.com/hpidcock/ap/internal/proto"
	"github.com/hpidcock/ap/internal/vault"
)

// Decryption pipeline: tlkshare -> TLK -> class key -> item key -> item plist -> credential.

// item-record fields that are NOT part of the per-item authenticated data.
var aadExcluded = map[string]bool{
	"gen": true, "pcspublickey": true, "UUID": true, "data": true, "pcsservice": true,
	"pcspublicidentity": true, "parentkeyref": true, "uploadver": true, "wrappedkey": true,
	"encver": true,
}

// AuthenticatedDataV2 builds the AES-SIV associated-data values for an item record
// (encver 2): the authenticated metadata as a by-key-sorted map, values in key order.
func AuthenticatedDataV2(uuid string, fields map[string]any, encver, gen int64, parentKeyID string) [][]byte {
	aad := map[string][]byte{
		"UUID":       []byte(uuid),
		"encver":     cloudkit.LE8(encver),
		"gen":        cloudkit.LE8(gen),
		"wrappedkey": []byte(parentKeyID), // the parent class key's id, not the wrappedkey field
	}
	if v, ok := fields["pcsservice"]; ok && v != nil {
		if n, ok := asInt(v); ok {
			aad["pcsservice"] = cloudkit.LE8(n)
		}
	}
	for _, pcs := range []string{"pcspublicidentity", "pcspublickey"} {
		if b, ok := fields[pcs].([]byte); ok {
			aad[pcs] = b
		}
	}
	for name, val := range fields {
		if aadExcluded[name] || strings.HasPrefix(name, "server_") {
			continue
		}
		switch v := val.(type) {
		case string:
			aad[name] = []byte(v)
		case []byte:
			aad[name] = v
		case cloudkit.Date: // RFC3339 seconds, 'Z' suffix
			aad[name] = []byte(time.Unix(int64(v.Time), 0).UTC().Format("2006-01-02T15:04:05Z"))
		case bool:
			if v {
				aad[name] = cloudkit.LE8(1)
			} else {
				aad[name] = cloudkit.LE8(0)
			}
		case float64: // (value as u64).to_le_bytes()
			aad[name] = cloudkit.LE8(int64(v))
		case int64:
			aad[name] = cloudkit.LE8(v)
		case uint64:
			aad[name] = cloudkit.LE8(int64(v))
		case int:
			aad[name] = cloudkit.LE8(int64(v))
		}
	}
	keys := make([]string, 0, len(aad))
	for k := range aad {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([][]byte, 0, len(keys))
	for _, k := range keys {
		out = append(out, aad[k])
	}
	return out
}

func asInt(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case uint64:
		return int64(x), true
	case int:
		return int64(x), true
	case float64:
		return int64(x), true
	}
	return 0, false
}

// UnwrapTLKShares returns {tlkUuid: TLK} for every TLKShare addressed to us that we can
// decrypt. A share's wrappedkey ECIES-decrypts to a CuttlefishSerializedKey protobuf
// {uuid(1), zoneName(2), keyclass(3), key(4)} - NOT raw TLK bytes.
func UnwrapTLKShares(shares []cloudkit.Record, ourPeerID string, encKey *ecdh.PrivateKey) map[string][]byte {
	tlks := map[string][]byte{}
	for _, share := range shares {
		if share.Str("receiver") != ourPeerID {
			continue
		}
		wrapped := share.Str("wrappedkey")
		if wrapped == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(wrapped)
		if err != nil {
			continue
		}
		expanded, err := ExpandKeyedArchive(raw)
		if err != nil {
			continue
		}
		ies, _ := expanded.(map[string]any)
		if ies == nil {
			continue
		}
		serialized, err := ECIESDecryptSF(encKey, ies)
		if err != nil {
			continue // skip a poisoned/foreign share, keep the rest
		}
		f := proto.MustDecode(serialized)
		keyID, tlk := f.String(1), f.Bytes(4)
		if keyID != "" && len(tlk) > 0 {
			tlks[keyID] = tlk
		}
	}
	return tlks
}

// UnwrapClassKeys returns {keyId: class key (64B SIV)} by unwrapping each synckey with
// its parent TLK.
func UnwrapClassKeys(synckeys []cloudkit.Record, tlks map[string][]byte) map[string][]byte {
	keys := map[string][]byte{}
	for _, sk := range synckeys {
		tlk, ok := tlks[sk.Str("parentkeyref")]
		if !ok {
			continue
		}
		wrapped := sk.Str("wrappedkey")
		if wrapped == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(wrapped)
		if err != nil {
			continue
		}
		key, err := SIVUnwrap(tlk, raw)
		if err != nil {
			continue
		}
		keys[sk.Name] = key
	}
	return keys
}

// DecryptItems decrypts each item record whose parent class key we hold -> item plist dict.
func DecryptItems(items []cloudkit.Record, classKeys map[string][]byte) []map[string]any {
	var out []map[string]any
	for _, it := range items {
		parent := it.Str("parentkeyref")
		ck, ok := classKeys[parent]
		data := it.Bytes("data")
		wrapped := it.Str("wrappedkey")
		if !ok || data == nil || wrapped == "" {
			continue
		}
		rawWrapped, err := base64.StdEncoding.DecodeString(wrapped)
		if err != nil {
			continue
		}
		itemKey, err := SIVUnwrap(ck, rawWrapped)
		if err != nil {
			continue
		}
		encver := int64(2)
		if v, ok := asInt(it.Fields["encver"]); ok {
			encver = v
		}
		gen := int64(0)
		if v, ok := asInt(it.Fields["gen"]); ok {
			gen = v
		}
		aad := AuthenticatedDataV2(it.Name, it.Fields, encver, gen, parent)
		plaintext, err := DecryptItem(itemKey, data, aad)
		if err != nil {
			continue
		}
		var v any
		if _, err := plist.Unmarshal(plaintext, &v); err != nil {
			continue
		}
		if m, ok := v.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// BuildCredentialStore runs the full pipeline. TLKs come from two UNIONed sources: the
// pre-fetched `tlks` (fetchRecoverableTLKShares, the only source for user-controllable
// views like Passwords) and the plain tlkshare records in the fetched zones.
func BuildCredentialStore(byType map[string][]cloudkit.Record, ourPeerID string, encKey *ecdh.PrivateKey, tlks map[string][]byte) *vault.Store {
	merged := UnwrapTLKShares(byType["tlkshare"], ourPeerID, encKey)
	for k, v := range tlks {
		merged[k] = v
	}
	classKeys := UnwrapClassKeys(byType["synckey"], merged)
	items := DecryptItems(byType["item"], classKeys)
	return vault.FromItems(items)
}

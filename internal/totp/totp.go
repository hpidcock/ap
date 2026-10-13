// Package totp generates one-time codes (RFC 6238) for the `totp` block iCloud
// Keychain stores in a login's metadata sidecar. The secret stays in the vault; only
// generated codes are handed to the browser extension.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Code is a generated verification code and when it rolls over.
type Code struct {
	Code    string `json:"code"`
	Expires int64  `json:"expires"` // unix second the code rolls over
	Period  int    `json:"period"`
}

var algorithms = map[int64]string{0: "SHA1", 1: "SHA256", 2: "SHA512"}

func hashFor(name string) func() hash.Hash {
	switch strings.ToUpper(name) {
	case "SHA1":
		return sha1.New
	case "SHA256":
		return sha256.New
	case "SHA512":
		return sha512.New
	}
	return nil
}

func toInt(v any, def int64) int64 {
	switch x := v.(type) {
	case int:
		return int64(x)
	case int64:
		return x
	case uint64:
		return int64(x)
	case float64:
		return int64(x)
	case string:
		if n, err := strconv.ParseInt(x, 10, 64); err == nil {
			return n
		}
	}
	return def
}

// URIFromSidecar rebuilds an otpauth://totp URI from a sidecar's `totp` dict, or ""
// when it holds no usable secret. The stored secret is raw bytes, not base32.
func URIFromSidecar(block any) string {
	m, ok := block.(map[string]any)
	if !ok {
		return ""
	}
	secret, ok := m["secret"].([]byte)
	if !ok || len(secret) == 0 {
		return ""
	}
	issuer := strOf(m["issuer"])
	account := strOf(m["accountName"])
	var parts []string
	for _, p := range []string{issuer, account} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	label := strings.Join(parts, ":")
	if label == "" {
		label = "icloud"
	}
	algo := "SHA1"
	if name, ok := algorithms[toInt(m["algorithm"], -1)]; ok {
		algo = name
	}
	q := url.Values{}
	q.Set("secret", strings.TrimRight(base32.StdEncoding.EncodeToString(secret), "="))
	q.Set("algorithm", algo)
	q.Set("digits", strconv.FormatInt(toInt(m["digits"], 6), 10))
	q.Set("period", strconv.FormatInt(toInt(m["period"], 30), 10))
	if issuer != "" {
		q.Set("issuer", issuer)
	}
	return "otpauth://totp/" + url.PathEscape(label) + "?" + q.Encode()
}

func strOf(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case []byte:
		return string(x)
	}
	return fmt.Sprint(v)
}

// Generate returns the code for an otpauth://totp URI at the current time, or nil if
// the URI is unusable.
func Generate(uri string) *Code {
	return GenerateAt(uri, time.Now())
}

// GenerateAt is Generate at a given instant.
func GenerateAt(uri string, at time.Time) *Code {
	if uri == "" {
		return nil
	}
	u, err := url.Parse(uri)
	if err != nil {
		return nil
	}
	q := u.Query()
	raw := strings.ToUpper(strings.ReplaceAll(q.Get("secret"), " ", ""))
	if pad := (8 - len(raw)%8) % 8; pad > 0 {
		raw += strings.Repeat("=", pad)
	}
	key, err := base32.StdEncoding.DecodeString(raw)
	if err != nil || len(key) == 0 {
		return nil
	}
	algo := q.Get("algorithm")
	if algo == "" {
		algo = "SHA1"
	}
	hf := hashFor(algo)
	if hf == nil {
		return nil
	}
	digits := int(toInt(q.Get("digits"), 6))
	if digits < 6 {
		digits = 6
	}
	if digits > 10 {
		digits = 10
	}
	period := int(toInt(q.Get("period"), 30))
	if period < 1 {
		period = 1
	}
	counter := at.Unix() / int64(period)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	mac := hmac.New(hf, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := (binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff) % uint32(math.Pow10(digits))
	return &Code{
		Code:    fmt.Sprintf("%0*d", digits, code),
		Expires: (counter + 1) * int64(period),
		Period:  period,
	}
}

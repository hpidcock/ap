package totp

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 Appendix B: ASCII "12345678901234567890", 8 digits, 30s.
const rfcURI = "otpauth://totp/rfc?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8"

func TestRFC6238(t *testing.T) {
	for at, want := range map[int64]string{59: "94287082", 1111111109: "07081804", 1234567890: "89005924"} {
		got := GenerateAt(rfcURI, time.Unix(at, 0))
		if got == nil || got.Code != want {
			t.Errorf("at %d: got %+v want %s", at, got, want)
		}
	}
	if GenerateAt(rfcURI, time.Unix(59, 0)).Expires != 60 {
		t.Fatal("expiry must be the next period boundary")
	}
	if Generate("otpauth://totp/x?secret=not!base32") != nil || Generate("") != nil {
		t.Fatal("unusable URIs must yield nil")
	}
}

func TestURIFromSidecar(t *testing.T) {
	secret := make([]byte, 20)
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	block := map[string]any{"secret": secret, "algorithm": uint64(0), "digits": uint64(6), "period": uint64(30),
		"issuer": "Example", "accountName": "me@example.com"}
	uri := URIFromSidecar(block)
	if !strings.Contains(uri, "secret=AEBAGBAFAYDQQCIKBMGA2DQPCAIREEYU") || !strings.HasPrefix(uri, "otpauth://totp/Example:me@example.com?") {
		t.Fatalf("uri %s", uri)
	}
	if c := Generate(uri); c == nil || len(c.Code) != 6 {
		t.Fatalf("code %+v", c)
	}
	if URIFromSidecar(map[string]any{"digits": 6}) != "" || URIFromSidecar(nil) != "" {
		t.Fatal("blocks without a secret must yield no URI")
	}
}

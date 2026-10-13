package vault

import (
	"bytes"
	"testing"
	"time"

	"howett.net/plist"

	"github.com/hpidcock/ap/internal/hme"
	"github.com/hpidcock/ap/internal/totp"
)

func TestDomainsMatch(t *testing.T) {
	yes := [][2]string{{"example.com", "example.com"}, {"www.example.com", "example.com"},
		{"login.example.com", "example.com"}, {"example.com", "accounts.example.com"},
		{"https://login.example.com/path?x=1", "example.com"}}
	no := [][2]string{{"notexample.com", "example.com"}, {"example.com.evil.com", "example.com"}, {"", "example.com"}}
	for _, c := range yes {
		if !DomainsMatch(c[0], c[1]) {
			t.Errorf("%q should match %q", c[0], c[1])
		}
	}
	for _, c := range no {
		if DomainsMatch(c[0], c[1]) {
			t.Errorf("%q should not match %q", c[0], c[1])
		}
	}
}

func TestStoreMatch(t *testing.T) {
	store := NewStore([]Credential{
		{Domain: "example.com", Username: "alice", Password: "pw1", Title: "Example"},
		{Domain: "login.example.com", Username: "bob", Password: "pw2", Title: "Example Login"},
		{Domain: "other.org", Username: "carol", Password: "pw3", Title: "Other"},
	})
	hits := store.Match("www.example.com")
	if len(hits) != 2 || hits[0].Username != "alice" {
		t.Fatalf("%+v", hits)
	}
	if len(store.Match("nowhere.test")) != 0 {
		t.Fatal("unexpected match")
	}
	label := NewStore([]Credential{{Domain: "", Username: "me@example.com", Password: "pw", Title: "Cloudflare"}})
	if h := label.Match("dash.cloudflare.com"); len(h) != 1 {
		t.Fatalf("label-only match %+v", h)
	}
	generic := NewStore([]Credential{{Domain: "", Username: "me@example.com", Password: "pw", Title: "Login"}})
	if len(generic.Match("login.example.com")) != 0 {
		t.Fatal("generic label must not match")
	}
	recent := NewStore([]Credential{
		{Domain: "example.com", Username: "old", Title: "Example", MDat: 1000},
		{Domain: "example.com", Username: "new", Title: "Example", MDat: 2000},
	})
	if h := recent.Match("example.com"); h[0].Username != "new" {
		t.Fatalf("recency order %+v", h)
	}
}

func TestFromItems(t *testing.T) {
	when := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	sidecar, _ := plist.Marshal(map[string]any{
		"notes": []byte("my notes"), "title": []byte("Custom"),
		"ctxt": map[string]any{"": map[string]any{"lUsed": float64(700000000)}},
		"totp": map[string]any{"secret": []byte("12345678901234567890"), "issuer": "Example"},
	}, plist.BinaryFormat)
	store := FromItems([]map[string]any{
		{"srvr": "idmsa.apple.com", "acct": "me@gmail.com", "v_Data": []byte("pw"), "labl": "idmsa.apple.com", "agrp": "com.apple.cfnetwork", "mdat": when},
		{"acct": "0Z825FXfO144", "labl": "PCS com.apple.Accessibility - 0Z825FXf", "svce": "com.apple.Accessibility"},
		{"srvr": "apple.com", "labl": "Website Metadata for apple.com"},
		{"svce": "Cloudflare", "acct": "me@example.com", "v_Data": []byte("pw"), "labl": "Cloudflare"},
		{"srvr": "idmsa.apple.com", "acct": "me@gmail.com", "v_Data": sidecar, "agrp": "com.apple.password-manager",
			"labl": "Password Manager Metadata: idmsa.apple.com (me@gmail.com)"},
		{"srvr": "cards", "acct": "x", "v_Data": []byte{0, 1, 2, 3}, "agrp": "com.apple.safari.credit-cards"},
		{"srvr": "pk", "acct": "", "v_Data": bytes.Repeat([]byte{1}, 97), "agrp": "com.apple.webkit.webauthn"},
	})
	if store.Len() != 2 {
		t.Fatalf("expected 2 credentials, got %d: %+v", store.Len(), store.All())
	}
	hits := store.Match("idmsa.apple.com")
	if len(hits) != 1 || hits[0].Username != "me@gmail.com" {
		t.Fatalf("%+v", hits)
	}
	c := hits[0]
	if c.Notes != "my notes" || c.Title != "Custom" || c.MDat != float64(when.Unix()) || c.LastUsed != 700000000+appleEpoch || c.TOTP == "" {
		t.Fatalf("sidecar merge: %+v", c)
	}
	if store.Match("dash.cloudflare.com")[0].Password != "pw" {
		t.Fatal("svce label-only item")
	}
	if n := len(store.Match("apple.com")); n != 1 {
		t.Fatalf("apple.com matched %d", n)
	}
}

func TestHandleNeverLeaksTOTPSecret(t *testing.T) {
	block := map[string]any{"secret": []byte("12345678901234567890"), "issuer": "Example"}
	store := NewStore([]Credential{{Domain: "example.com", Username: "alice", Password: "pw", TOTP: totp.URIFromSidecar(block)}})
	resp := Handle(map[string]any{"cmd": "match", "domain": "example.com"}, store, nil)
	creds := resp["credentials"].([]map[string]any)
	code := creds[0]["totp"].(*totp.Code)
	if len(code.Code) != 6 {
		t.Fatalf("%+v", code)
	}
	var buf bytes.Buffer
	if err := WriteMessage(&buf, resp); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(buf.Bytes(), []byte("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")) || bytes.Contains(buf.Bytes(), []byte("otpauth")) {
		t.Fatal("secret crossed the wire")
	}
	back, err := ReadMessage(&buf)
	if err != nil || back["ok"] != true {
		t.Fatalf("framing round trip %v %v", back, err)
	}
	if r := Handle(map[string]any{"cmd": "totp", "domain": "example.com", "username": "bob"}, store, nil); r["ok"] != false {
		t.Fatal("unknown user should fail")
	}
	if r := Handle(map[string]any{"cmd": "ping"}, store, nil); r["count"] != 1 {
		t.Fatalf("ping %v", r)
	}
}

func TestMatchAliases(t *testing.T) {
	aliases := []hme.Alias{{Address: "quiet-otter@icloud.com", Domain: "claude.ai"}, {Address: "x@icloud.com", Domain: "other.org"}, {Address: "none", Domain: ""}}
	hits := MatchAliases("www.claude.ai", aliases)
	if len(hits) != 1 || hits[0].Address != "quiet-otter@icloud.com" {
		t.Fatalf("%+v", hits)
	}
	resp := Handle(map[string]any{"cmd": "match", "domain": "claude.ai"}, NewStore(nil), aliases)
	if len(resp["aliases"].([]map[string]any)) != 1 {
		t.Fatalf("%v", resp)
	}
}

func TestClassifyPayload(t *testing.T) {
	if k, text, _ := ClassifyPayload([]byte("hunter2")); k != KindPassword || text != "hunter2" {
		t.Fatal("plain password")
	}
	if k, _, _ := ClassifyPayload([]byte{0xff, 0xfe, 0x00}); k != KindBinary {
		t.Fatal("binary")
	}
	if k, _, _ := ClassifyPayload([]byte("<?xml version")); k != KindPlumbing {
		t.Fatal("xml plumbing")
	}
	card, _ := plist.Marshal(map[string]any{"CardNumber": "4111"}, plist.BinaryFormat)
	if k, _, _ := ClassifyPayload(card); k != KindCard {
		t.Fatal("card")
	}
}

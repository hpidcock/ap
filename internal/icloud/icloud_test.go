package icloud

import "testing"

func TestExtractWebservicesDerivesEscrowFromPartition(t *testing.T) {
	ws := ExtractWebservices(map[string]any{
		"webservices": map[string]any{
			"ckdatabasews": map[string]any{"url": "https://p57-ckdatabasews.icloud.com:443", "status": "active"},
			"push":         map[string]any{"url": "https://p57-pushws.icloud.com:443"},
		},
	})
	if ws["keychainsync"] != "https://p57-escrowproxy.icloud.com:443" {
		t.Fatalf("keychainsync = %q", ws["keychainsync"])
	}
	if ws := ExtractWebservices(map[string]any{"webservices": map[string]any{
		"x": map[string]any{"url": "https://setup.icloud.com"}}}); ws["keychainsync"] != "" {
		t.Fatalf("unexpected derivation %q", ws["keychainsync"])
	}
}

func TestExtractWebservices(t *testing.T) {
	settings := map[string]any{
		"webservices": map[string]any{
			"ckdatabasews": map[string]any{"url": "https://p1-ckdatabasews.icloud.com:443", "status": "active"},
			"broken":       map[string]any{"status": "off"},
		},
		"com.apple.mobileme": map[string]any{
			"com.apple.Dataclass.KeychainSync": map[string]any{"escrowProxyUrl": "https://p1-escrowproxy.icloud.com:443"},
			"com.apple.Dataclass.KeyValue":     map[string]any{"configURL": "https://p1-kv"},
			"com.apple.Dataclass.Nope":         "not a dict",
		},
	}
	ws := ExtractWebservices(settings)
	if ws["ckdatabasews"] == "" || ws["keychainsync"] != "https://p1-escrowproxy.icloud.com:443" ||
		ws["com.apple.Dataclass.KeychainSync"] == "" || ws["keyvalue"] != "https://p1-kv" {
		t.Fatalf("%v", ws)
	}
	if _, ok := ws["broken"]; ok {
		t.Fatal("entries without a url must be dropped")
	}
}

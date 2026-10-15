package remote

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRemoteLive provisions a throwaway machine through the real default server and
// asks it for headers. Run with AP_REMOTE_LIVE=1 (talks to the server and to Apple).
func TestRemoteLive(t *testing.T) {
	if os.Getenv("AP_REMOTE_LIVE") == "" {
		t.Skip("set AP_REMOTE_LIVE=1 to provision a throwaway machine against the real server")
	}
	url := os.Getenv("AP_ANISETTE")
	if url == "" {
		url = DefaultURL
	}
	r := New(url, filepath.Join(t.TempDir(), "remote.json"), t.Logf)
	info, ua, err := r.ClientInfo()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("client info %q user agent %q", info, ua)
	h, err := r.Headers()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"X-Apple-I-MD", "X-Apple-I-MD-M", "X-Mme-Device-Id", "X-Apple-I-MD-LU"} {
		if h[k] == "" {
			t.Fatalf("missing %s in %v", k, h)
		}
	}
	st, _ := r.State()
	t.Logf("provisioned device %s with %d-byte blob; headers: MD %d chars, MD-M %d chars, RINFO %s",
		st.DeviceID(), len(st.ADIPB), len(h["X-Apple-I-MD"]), len(h["X-Apple-I-MD-M"]), h["X-Apple-I-MD-RINFO"])
}

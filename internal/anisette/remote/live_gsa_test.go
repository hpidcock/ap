package remote

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hpidcock/ap/internal/device"
	"github.com/hpidcock/ap/internal/gsa"
	"github.com/hpidcock/ap/internal/logx"
)

// TestRemoteLiveGSA provisions through the server named by AP_ANISETTE and then sends
// GrandSlam inits for a nonexistent account, repeatedly, with the machine identity kept
// in AP_REMOTE_STATE (default: a temp file). Apple validates the machine data before it
// looks at the account, so the status tells whether this server's data is accepted:
// -80045 means the platform check failed, hsc 434 asks for a resync, and an account
// error means it passed.
func TestRemoteLiveGSA(t *testing.T) {
	if os.Getenv("AP_REMOTE_LIVE") == "" {
		t.Skip("set AP_REMOTE_LIVE=1")
	}
	_ = logx.InitFromEnv()
	url := os.Getenv("AP_ANISETTE")
	if url == "" {
		url = DefaultURL
	}
	statePath := os.Getenv("AP_REMOTE_STATE")
	if statePath == "" {
		statePath = filepath.Join(t.TempDir(), "remote.json")
	}
	probe := func(label string, r *Remote) {
		info, ua, err := r.ClientInfo()
		if err != nil {
			t.Fatal(err)
		}
		device.SetClientInfo(info, ua)
		if _, err := r.Headers(); err != nil {
			t.Fatalf("%s: %v", url, err)
		}
		dev := &device.Device{DeviceID: device.NewUUID(), Serial: "C02TEST", LocalUserUUID: device.NewUUID()}
		c := gsa.NewClient(dev, r)
		_, _, err = c.Authenticate("nobody-"+device.NewUUID()[:8]+"@example.com", "not-a-password", label)
		t.Logf("%s: %v", label, err)
	}
	r := New(url, statePath, t.Logf)
	probe("first", r)
	probe("second, cached data", r)
	r.cached = nil
	probe("third, refetched from server", r)
	if os.Getenv("AP_REMOTE_SLOW") != "" {
		time.Sleep(35 * time.Second)
		probe("fourth, after 35s", r)
	}
	probe("fifth, new process", New(url, statePath, t.Logf))
}

package remote

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hpidcock/ap/internal/device"
	"github.com/hpidcock/ap/internal/gsa"
)

// TestRemoteLiveGSA provisions through the server named by AP_ANISETTE and then sends a
// GrandSlam init for a nonexistent account. Apple validates the machine data before it
// looks at the account, so the status code tells whether this server's data is accepted:
// -80045 means the platform check failed, an account error means it passed.
func TestRemoteLiveGSA(t *testing.T) {
	if os.Getenv("AP_REMOTE_LIVE") == "" {
		t.Skip("set AP_REMOTE_LIVE=1")
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
	device.SetClientInfo(info, ua)
	if _, err := r.Headers(); err != nil {
		t.Fatalf("%s: %v", url, err)
	}
	dev := &device.Device{DeviceID: device.NewUUID(), Serial: "C02TEST", LocalUserUUID: device.NewUUID()}
	c := gsa.NewClient(dev, r)
	_, _, err = c.Authenticate("nobody-"+device.NewUUID()[:8]+"@example.com", "not-a-password", "probe")
	t.Logf("%s (%s): %v", url, info, err)
}

//go:build live

package local

// Live test: provisions a fresh machine identity with Apple and generates machine data.
// Needs network and the ADI libraries:
//
//	AP_ANISETTE_LIBDIR=~/.config/ap/anisette/lib go test -tags live ./internal/anisette/local -v

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLocalLive(t *testing.T) {
	libdir := os.Getenv("AP_ANISETTE_LIBDIR")
	if libdir == "" {
		t.Skip("AP_ANISETTE_LIBDIR not set")
	}
	cfg := t.TempDir()
	if err := os.MkdirAll(filepath.Join(cfg, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range LibraryNames {
		data, err := os.ReadFile(filepath.Join(libdir, n))
		if err != nil {
			t.Skipf("ADI libraries not available: %v", err)
		}
		if err := os.WriteFile(filepath.Join(cfg, "lib", n), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	l := NewLocal(cfg, t.Logf)
	defer l.Close()
	h, err := l.Headers()
	if err != nil {
		t.Fatal(err)
	}
	if h["X-Apple-I-MD"] == "" || h["X-Apple-I-MD-M"] == "" || h["X-Mme-Device-Id"] == "" {
		t.Fatalf("headers %v", h)
	}
	if _, ok := h["X-MMe-Client-Info"]; ok {
		t.Fatal("client info must not be forwarded as anisette data")
	}
	if _, err := os.Stat(filepath.Join(cfg, "adi.pb")); err != nil {
		t.Fatalf("adi.pb not written: %v", err)
	}
	// A second instance reuses the stored provisioning.
	l2 := NewLocal(cfg, t.Logf)
	defer l2.Close()
	if h2, err := l2.Headers(); err != nil || h2["X-Mme-Device-Id"] != h["X-Mme-Device-Id"] {
		t.Fatalf("second instance: %v %v", h2, err)
	}
}

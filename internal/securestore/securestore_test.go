package securestore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("AP_NO_KEYRING", "1")
	blob, err := Seal([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Open(blob)
	if err != nil || string(out) != "secret" {
		t.Fatalf("%q %v", out, err)
	}
	blob[len(blob)-1] ^= 1
	if _, err := Open(blob); err == nil {
		t.Fatal("tampered box opened")
	}
	path := filepath.Join(t.TempDir(), "f.enc")
	if err := WriteFile(path, []byte("x")); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
	if data, err := ReadFile(path); err != nil || string(data) != "x" {
		t.Fatalf("%q %v", data, err)
	}
}

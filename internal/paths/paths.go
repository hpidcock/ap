// Package paths holds the filesystem locations used by ap. Everything lives under
// $XDG_CONFIG_HOME/ap (default ~/.config/ap). The directory is kept private (0700)
// because it holds tokens and the device identity.
package paths

import (
	"os"
	"path/filepath"
)

// ConfigDir returns (and creates) the private configuration directory.
func ConfigDir() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	dir := filepath.Join(base, "ap")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	_ = os.Chmod(dir, 0o700)
	return dir, nil
}

func in(name string) string {
	dir, err := ConfigDir()
	if err != nil {
		return name
	}
	return filepath.Join(dir, name)
}

// DeviceFile is the persistent local device identity (not secret, but private).
func DeviceFile() string { return in("device.json") }

// SessionFile is the encrypted auth session.
func SessionFile() string { return in("session.enc") }

// FallbackKeyFile holds the master key when no Secret Service keyring is available.
func FallbackKeyFile() string { return in("master.key") }

// VaultFile is the encrypted credential vault.
func VaultFile() string { return in("vault.enc") }

// AliasesFile is the encrypted Hide My Email alias cache.
func AliasesFile() string { return in("aliases.enc") }

// SyncLockFile serialises concurrent `ap sync` runs.
func SyncLockFile() string { return in("sync.lock") }

// SyncAttemptFile debounces the background sync trigger from the native host.
func SyncAttemptFile() string { return in("sync.attempt") }

// AnisetteDir is where the embedded anisette server keeps its state
// (Apple's ADI libraries, the machine identity and the provisioning data).
func AnisetteDir() string { return in("anisette") }

// WritePrivate writes data to path with mode 0600 from creation, so a secret never
// exists world-readable even briefly.
func WritePrivate(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

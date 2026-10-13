// Package securestore encrypts the files ap keeps on disk (the auth session, the
// credential vault and the Hide My Email cache) with a libsodium-compatible secret
// box. The 32-byte master key lives in the login keyring (Secret Service) and falls
// back to a 0600 key file when no keyring is available.
package securestore

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/nacl/secretbox"

	"github.com/hpidcock/ap/internal/paths"
)

const (
	keyringService = "ap"
	keyringUser    = "master-key"
	keySize        = 32
)

// ErrCannotDecrypt means the file exists but the current master key does not open it
// (the keyring entry was lost or replaced).
var ErrCannotDecrypt = errors.New("cannot decrypt with the current master key")

var (
	keyOnce sync.Once
	keyVal  [keySize]byte
	keyErr  error
)

func decodeKey(stored string) ([]byte, bool) {
	raw := strings.TrimSpace(stored)
	if len(raw) == keySize {
		return []byte(raw), true
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(key) != keySize {
		return nil, false
	}
	return key, true
}

func keyFromKeyring() ([]byte, bool) {
	if os.Getenv("AP_NO_KEYRING") != "" {
		return nil, false
	}
	stored, err := keyring.Get(keyringService, keyringUser)
	if err == nil {
		if key, ok := decodeKey(stored); ok {
			return key, true
		}
		log.Printf("warning: keyring holds an unusable master key; replacing it")
	} else if !errors.Is(err, keyring.ErrNotFound) {
		log.Printf("warning: Secret Service unavailable (%v); using key file fallback", err)
		return nil, false
	}
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, false
	}
	if err := keyring.Set(keyringService, keyringUser, base64.StdEncoding.EncodeToString(key)); err != nil {
		log.Printf("warning: could not store the master key in the keyring (%v); using key file fallback", err)
		return nil, false
	}
	return key, true
}

func keyFromFile() ([]byte, error) {
	path := paths.FallbackKeyFile()
	if data, err := os.ReadFile(path); err == nil {
		if key, ok := decodeKey(string(data)); ok {
			return key, nil
		}
		log.Printf("warning: master key file %s is unusable; writing a fresh key", path)
	}
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := paths.WritePrivate(path, []byte(base64.StdEncoding.EncodeToString(key))); err != nil {
		return nil, err
	}
	log.Printf("warning: stored master key at %s (0600) - less safe than the keyring", path)
	return key, nil
}

// MasterKey returns the process-wide master key, resolving it once.
func MasterKey() (*[keySize]byte, error) {
	keyOnce.Do(func() {
		key, ok := keyFromKeyring()
		if !ok {
			key, keyErr = keyFromFile()
			if keyErr != nil {
				return
			}
		}
		copy(keyVal[:], key)
	})
	if keyErr != nil {
		return nil, keyErr
	}
	return &keyVal, nil
}

// Seal encrypts plaintext as nonce(24) || box, the PyNaCl SecretBox layout.
func Seal(plaintext []byte) ([]byte, error) {
	key, err := MasterKey()
	if err != nil {
		return nil, err
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	return secretbox.Seal(nonce[:], plaintext, &nonce, key), nil
}

// Open decrypts a Seal output.
func Open(blob []byte) ([]byte, error) {
	key, err := MasterKey()
	if err != nil {
		return nil, err
	}
	if len(blob) < 24 {
		return nil, ErrCannotDecrypt
	}
	var nonce [24]byte
	copy(nonce[:], blob[:24])
	out, ok := secretbox.Open(nil, blob[24:], &nonce, key)
	if !ok {
		return nil, ErrCannotDecrypt
	}
	return out, nil
}

// WriteFile seals data and writes it to path with mode 0600.
func WriteFile(path string, data []byte) error {
	blob, err := Seal(data)
	if err != nil {
		return err
	}
	return paths.WritePrivate(path, blob)
}

// ReadFile reads and opens a sealed file. A missing file yields (nil, os.ErrNotExist).
func ReadFile(path string) ([]byte, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out, err := Open(blob)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return out, nil
}

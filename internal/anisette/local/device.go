// Package local generates anisette machine data in-process. It is a Go port of the ADI
// side of Dadoum's anisette-v3-server / Provision: Apple's CoreADI library is extracted
// from the Apple Music for Android APK on first use, loaded with a small ELF loader,
// provisioned against Apple's servers once, and then asked for a one-time password
// whenever ap talks to Apple.
package local

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"

	"github.com/hpidcock/ap/internal/device"
)

// ClientInfo is the machine description reported to Apple (same as upstream).
const ClientInfo = "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"

// DSID is the anonymous dsid used for provisioning.
const DSID int64 = -2

// Machine is the persisted anisette device identity (device.json, upstream-compatible keys).
type Machine struct {
	UUID          string `json:"UUID"`
	ClientInfo    string `json:"clientInfo"`
	ADIIdentifier string `json:"identifier"`
	LocalUUID     string `json:"localUUID"`

	path string
}

// LoadOrCreateMachine reads device.json or generates a new identity.
func LoadOrCreateMachine(path string) (*Machine, bool, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		var m Machine
		if json.Unmarshal(data, &m) == nil && m.UUID != "" && m.ADIIdentifier != "" {
			m.path = path
			return &m, false, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	m := &Machine{
		UUID:          device.NewUUID(),
		ClientInfo:    ClientInfo,
		ADIIdentifier: randomHex(16, false), // 8 random bytes: the Android ID ADI expects
		LocalUUID:     randomHex(64, true),
		path:          path,
	}
	if err := m.Save(); err != nil {
		return nil, false, err
	}
	return m, true, nil
}

func randomHex(n int, upper bool) string {
	b := make([]byte, n/2)
	_, _ = rand.Read(b)
	s := hex.EncodeToString(b)
	if upper {
		return strings.ToUpper(s)
	}
	return s
}

// Save writes device.json.
func (m *Machine) Save() error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.path, data, 0o600)
}

// Package device is the persistent local device identity - generated once and reused
// forever, so a stable X-Mme-Device-Id lets Apple remember the 2FA approval and stop
// re-prompting. Anisette supplies the volatile X-Apple-I-MD* machine data and may
// override these values.
package device

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/hpidcock/ap/internal/anisette"
	"github.com/hpidcock/ap/internal/paths"
)

// Description is the hardware/OS part of every X-Mme-Client-Info ap sends. Since
// 2026-10-12 Apple rejects requests whose client info claims macOS while the anisette
// machine data comes from the Android CoreADI library (GSA: ec=-80045, setup.icloud.com:
// status 1), so ap describes itself as the Android device the library really is.
const Description = "<Pixel 7> <Android;14;UQ1A.240205.002>"

// Device is the local identity.
type Device struct {
	DeviceID      string `json:"device_id"`
	Serial        string `json:"serial"`
	LocalUserUUID string `json:"local_user_uuid"`
}

// NewUUID returns an upper-case random UUIDv4 string.
func NewUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return strings.ToUpper(h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32])
}

// LoadOrCreate reads the identity file or generates and saves a new one.
func LoadOrCreate() (*Device, error) {
	path := paths.DeviceFile()
	data, err := os.ReadFile(path)
	if err == nil {
		var d Device
		if err := json.Unmarshal(data, &d); err == nil && d.DeviceID != "" {
			return &d, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	d := &Device{
		DeviceID: NewUUID(),
		// Mac-like 12-char serial; replaced by anisette's if it provides one.
		Serial:        "C02" + strings.ToUpper(strings.ReplaceAll(NewUUID(), "-", ""))[:9],
		LocalUserUUID: NewUUID(),
	}
	if err := d.Save(); err != nil {
		return nil, err
	}
	return d, nil
}

// Save writes the identity file (0600).
func (d *Device) Save() error {
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	return paths.WritePrivate(paths.DeviceFile(), data)
}

// Delete removes the identity file.
func Delete() error {
	err := os.Remove(paths.DeviceFile())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func locale() string {
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		v := os.Getenv(k)
		if v == "" || v == "C" || v == "POSIX" {
			continue
		}
		if i := strings.IndexAny(v, ".@"); i >= 0 {
			v = v[:i]
		}
		if strings.Contains(v, "_") {
			return v
		}
	}
	return "en_US"
}

// MetaHeaders are the fallback identity headers; anisette values override the X-Apple-I-MD* ones.
func (d *Device) MetaHeaders() map[string]string {
	now := time.Now().UTC().Truncate(time.Second)
	loc := locale()
	return map[string]string{
		"X-Apple-I-Client-Time": now.Format("2006-01-02T15:04:05Z"),
		"X-Apple-I-TimeZone":    "UTC",
		"loc":                   loc,
		"X-Apple-Locale":        loc,
		"X-Apple-I-MD-RINFO":    "17106176",
		"X-Apple-I-MD-LU":       base64.StdEncoding.EncodeToString([]byte(strings.ToUpper(d.LocalUserUUID))),
		"X-Mme-Device-Id":       strings.ToUpper(d.DeviceID),
		"X-Apple-I-SRL-NO":      d.Serial,
	}
}

// IdentityHeaders merges device + anisette headers: device identity first, anisette
// machine data second so anisette wins on the volatile X-Apple-I-MD* fields.
func IdentityHeaders(d *Device, a anisette.Provider) (map[string]string, error) {
	h := d.MetaHeaders()
	ah, err := a.Headers()
	if err != nil {
		return nil, err
	}
	for k, v := range ah {
		h[k] = v
	}
	return h, nil
}

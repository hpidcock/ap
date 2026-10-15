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
// 2026-10-12 Apple checks it against the platform of the library that produced the
// anisette machine data (a mismatch is ec=-80045 on GrandSlam and status 1 on
// setup.icloud.com), and since 2026-10-15 it blocks Android outright (HTTP 503), which is
// the only platform ap's in-process library can claim. The anisette provider therefore
// decides: SetClientInfo is called at startup with what the provider's machine data is
// valid for, and this default only stands for the in-process provider.
var Description = "<MacBookPro18,3> <Mac OS X;13.4.1;22F8>"

var gsaClientInfo, gsaUserAgent string

// SetClientInfo records the client info and user agent the anisette machine data is
// bound to. GrandSlam gets them verbatim; the other services keep their own app part
// behind the same device description.
func SetClientInfo(clientInfo, userAgent string) {
	gsaClientInfo, gsaUserAgent = clientInfo, userAgent
	if d := DescriptionOf(clientInfo); d != "" {
		Description = d
	}
}

// DescriptionOf returns the first two <...> groups of a client-info string, or "".
func DescriptionOf(clientInfo string) string {
	var groups []string
	for rest := clientInfo; len(groups) < 2; {
		start := strings.Index(rest, "<")
		if start < 0 {
			break
		}
		end := strings.Index(rest[start:], ">")
		if end < 0 {
			break
		}
		groups = append(groups, rest[start:start+end+1])
		rest = rest[start+end+1:]
	}
	if len(groups) != 2 {
		return ""
	}
	return groups[0] + " " + groups[1]
}

// GSAClientInfo is the X-MMe-Client-Info for gsa.apple.com.
func GSAClientInfo() string {
	if gsaClientInfo != "" {
		return gsaClientInfo
	}
	return Description + " <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
}

// GSAUserAgent is the User-Agent for gsa.apple.com.
func GSAUserAgent() string {
	if gsaUserAgent != "" {
		return gsaUserAgent
	}
	return "akd/1.0 CFNetwork/808.1.4"
}

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

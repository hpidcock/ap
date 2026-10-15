// Package provisioning holds the Apple-facing half of the anisette machine-provisioning
// handshake (lookup -> midStartProvisioning -> midFinishProvisioning). It is shared by
// the in-process CoreADI provider, which answers the handshake itself, and the remote
// anisette-v3 provider, which relays it to a server over a websocket.
package provisioning

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/hpidcock/ap/internal/logx"
	"github.com/hpidcock/ap/internal/plistx"
)

const (
	// LookupURL serves the GrandSlam URL bag.
	LookupURL = "https://gsa.apple.com/grandslam/GsService2/lookup"
	// BagClientInfo is sent on the lookup only. The bag differs by platform and the Mac
	// one carries the provisioning endpoints every client uses; isideload does the same.
	BagClientInfo = "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
	// Fallbacks for when the bag cannot be fetched; these are the values it has carried
	// for years.
	DefaultStartURL  = "https://gsa.apple.com/grandslam/MidService/startMachineProvisioning"
	DefaultFinishURL = "https://gsa.apple.com/grandslam/MidService/finishMachineProvisioning"
)

// Session identifies the machine being provisioned to Apple.
type Session struct {
	HTTP          *http.Client
	ClientInfo    string // X-MMe-Client-Info the machine data will be bound to
	UserAgent     string
	DeviceID      string // X-Mme-Device-Id
	LocalUserUUID string // X-Apple-I-MD-LU
	// URLBag overrides the lookup (tests, or a cached bag). Keys: midStartProvisioning,
	// midFinishProvisioning.
	URLBag map[string]string
	// LookupURL overrides LookupURL (tests).
	LookupURL string
}

func (s *Session) headers(req *http.Request, clientInfo string) {
	req.Header.Set("User-Agent", s.UserAgent)
	// AuthKit does not use the plist content type here.
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Connection", "close")
	req.Header.Set("X-Mme-Device-Id", s.DeviceID)
	req.Header.Set("X-MMe-Client-Info", clientInfo)
	req.Header.Set("X-Apple-I-MD-LU", s.LocalUserUUID)
	req.Header.Set("X-Apple-Client-App-Name", "Setup")
	req.Header.Set("X-Apple-I-Client-Time", time.Now().UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z"))
}

func (s *Session) do(method, url string, body []byte, clientInfo string) (map[string]any, error) {
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	s.headers(req, clientInfo)
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}
	data, err := plistx.Decode(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: HTTP %d: unreadable plist (%d bytes)", url, resp.StatusCode, len(raw))
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("%s: HTTP %d: %v", url, resp.StatusCode, statusOf(data))
	}
	return data, nil
}

func statusOf(data map[string]any) string {
	st := plistx.Dict(plistx.Dict(data["Response"])["Status"])
	if st == nil {
		return "no Status block"
	}
	return fmt.Sprintf("ec=%v em=%q", st["ec"], plistx.Str(st["em"]))
}

// LoadURLBag fetches the GsService2 URL bag into URLBag.
func (s *Session) LoadURLBag() error {
	lookup := s.LookupURL
	if lookup == "" {
		lookup = LookupURL
	}
	data, err := s.do(http.MethodGet, lookup, nil, BagClientInfo)
	if err != nil {
		return err
	}
	bag := map[string]string{}
	for k, v := range plistx.Dict(data["urls"]) {
		bag[k] = plistx.Str(v)
	}
	if bag["midStartProvisioning"] == "" || bag["midFinishProvisioning"] == "" {
		return fmt.Errorf("provisioning: URL bag is missing the mid* endpoints (%d urls)", len(bag))
	}
	s.URLBag = bag
	logx.Debugf("provisioning", "URL bag: %d urls, start=%s finish=%s", len(bag), bag["midStartProvisioning"], bag["midFinishProvisioning"])
	return nil
}

func (s *Session) urls() (start, finish string) {
	if len(s.URLBag) == 0 {
		if err := s.LoadURLBag(); err != nil {
			logx.Errorf("provisioning", err, "URL bag unavailable, using the default endpoints")
			return DefaultStartURL, DefaultFinishURL
		}
	}
	return s.URLBag["midStartProvisioning"], s.URLBag["midFinishProvisioning"]
}

const startBody = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Header</key>
	<dict/>
	<key>Request</key>
	<dict/>
</dict>
</plist>`

const finishBody = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Header</key>
	<dict/>
	<key>Request</key>
	<dict>
		<key>cpim</key>
		<string>%s</string>
	</dict>
</dict>
</plist>`

// Start asks Apple for the server provisioning intermediate metadata (spim, base64 as
// Apple returned it).
func (s *Session) Start() (string, error) {
	start, _ := s.urls()
	data, err := s.do(http.MethodPost, start, []byte(startBody), s.ClientInfo)
	if err != nil {
		return "", fmt.Errorf("midStartProvisioning: %w", err)
	}
	spim := plistx.Str(plistx.Dict(data["Response"])["spim"])
	if spim == "" {
		return "", fmt.Errorf("midStartProvisioning returned no spim: %s", statusOf(data))
	}
	logx.Debugf("provisioning", "midStartProvisioning ok: spim %d chars", len(spim))
	return spim, nil
}

// Finish sends the client provisioning intermediate metadata (cpim, base64) and returns
// Apple's ptm and tk (base64) plus the routing info.
func (s *Session) Finish(cpim string) (ptm, tk, rinfo string, err error) {
	_, finish := s.urls()
	data, err := s.do(http.MethodPost, finish, []byte(fmt.Sprintf(finishBody, cpim)), s.ClientInfo)
	if err != nil {
		return "", "", "", fmt.Errorf("midFinishProvisioning: %w", err)
	}
	resp := plistx.Dict(data["Response"])
	ptm, tk = plistx.Str(resp["ptm"]), plistx.Str(resp["tk"])
	if ptm == "" || tk == "" {
		return "", "", "", fmt.Errorf("midFinishProvisioning returned no ptm/tk: %s", statusOf(data))
	}
	rinfo = plistx.Str(resp["X-Apple-I-MD-RINFO"])
	logx.Debugf("provisioning", "midFinishProvisioning ok: ptm %d chars, tk %d chars, rinfo=%s", len(ptm), len(tk), rinfo)
	return ptm, tk, rinfo, nil
}

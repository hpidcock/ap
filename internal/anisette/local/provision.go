package local

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/hpidcock/ap/internal/anisette/local/adi"
	"github.com/hpidcock/ap/internal/httpx"
	"github.com/hpidcock/ap/internal/plistx"
)

// ProvisioningSession runs the GrandSlam machine-provisioning handshake
// (lookup -> midStartProvisioning -> midFinishProvisioning) against the ADI instance.
type ProvisioningSession struct {
	ADI     *adi.ADI
	Machine *Machine
	HTTP    *http.Client
	urlBag  map[string]string
}

// NewProvisioningSession returns a session.
func NewProvisioningSession(a *adi.ADI, m *Machine) *ProvisioningSession {
	return &ProvisioningSession{ADI: a, Machine: m, HTTP: httpx.Client(60 * time.Second)}
}

func (p *ProvisioningSession) headers(req *http.Request) {
	req.Header.Set("User-Agent", "akd/1.0 CFNetwork/1404.0.5 Darwin/22.3.0")
	// they are somehow not using the plist content-type in AuthKit
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("X-Mme-Device-Id", p.Machine.UUID)
	req.Header.Set("X-MMe-Client-Info", p.Machine.ClientInfo)
	req.Header.Set("X-Apple-I-MD-LU", p.Machine.LocalUUID)
	req.Header.Set("X-Apple-Client-App-Name", "Setup")
	req.Header.Set("X-Apple-I-Client-Time", time.Now().UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z"))
}

func (p *ProvisioningSession) do(method, url string, body []byte) (map[string]any, error) {
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	p.headers(req)
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	data, err := plistx.Decode(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: HTTP %d: unreadable plist: %w", url, resp.StatusCode, err)
	}
	return data, nil
}

// LoadURLBag fetches the GsService2 URL bag.
func (p *ProvisioningSession) LoadURLBag() error {
	data, err := p.do(http.MethodGet, "https://gsa.apple.com/grandslam/GsService2/lookup", nil)
	if err != nil {
		return err
	}
	p.urlBag = map[string]string{}
	for k, v := range plistx.Dict(data["urls"]) {
		p.urlBag[k] = plistx.Str(v)
	}
	if p.urlBag["midStartProvisioning"] == "" || p.urlBag["midFinishProvisioning"] == "" {
		return fmt.Errorf("provisioning: URL bag is missing the mid* endpoints")
	}
	return nil
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

// Provision runs the full handshake for dsID and leaves adi.pb in the provisioning path.
func (p *ProvisioningSession) Provision(dsID int64) error {
	if len(p.urlBag) == 0 {
		if err := p.LoadURLBag(); err != nil {
			return err
		}
	}
	start, err := p.do(http.MethodPost, p.urlBag["midStartProvisioning"], []byte(startBody))
	if err != nil {
		return err
	}
	spimStr := plistx.Str(plistx.Dict(start["Response"])["spim"])
	spim, err := base64.StdEncoding.DecodeString(spimStr)
	if err != nil || len(spim) == 0 {
		return fmt.Errorf("provisioning: midStartProvisioning returned no spim: %v", start)
	}
	cpim, sess, err := p.ADI.StartProvisioning(dsID, spim)
	if err != nil {
		return err
	}
	finish, err := p.do(http.MethodPost, p.urlBag["midFinishProvisioning"],
		[]byte(fmt.Sprintf(finishBody, base64.StdEncoding.EncodeToString(cpim))))
	if err != nil {
		_ = p.ADI.DestroyProvisioning(sess)
		return err
	}
	resp := plistx.Dict(finish["Response"])
	ptm, err1 := base64.StdEncoding.DecodeString(plistx.Str(resp["ptm"]))
	tk, err2 := base64.StdEncoding.DecodeString(plistx.Str(resp["tk"]))
	if err1 != nil || err2 != nil || len(ptm) == 0 || len(tk) == 0 {
		_ = p.ADI.DestroyProvisioning(sess)
		return fmt.Errorf("provisioning: midFinishProvisioning returned no ptm/tk: %v", finish)
	}
	if _, err := strconv.ParseUint(plistx.Str(resp["X-Apple-I-MD-RINFO"]), 10, 64); err != nil {
		// informational only; upstream parses it and ignores it
		_ = err
	}
	if err := p.ADI.EndProvisioning(sess, ptm, tk); err != nil {
		_ = p.ADI.DestroyProvisioning(sess)
		return err
	}
	return nil
}

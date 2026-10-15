// Package gsa implements GrandSlam (gsa.apple.com) SRP-6a authentication plus the 2FA
// endpoints. It produces the decrypted server provisioning data (spd), which carries the
// account DSID and the PET (password-equivalent token).
package gsa

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/hpidcock/ap/internal/anisette"
	"github.com/hpidcock/ap/internal/device"
	"github.com/hpidcock/ap/internal/httpx"
	"github.com/hpidcock/ap/internal/logx"
	"github.com/hpidcock/ap/internal/plistx"
	"github.com/hpidcock/ap/internal/srp"
)

// Static identity strings sent with every GSA request; the device part comes from
// device.Description (see there for why it is Android). These match what iloader /
// isideload send since Apple's 2026-10-12 change.
const (
	UserAgent  = "akd/1.0 CFNetwork/808.1.4"
	ClientInfo = device.Description + " <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
	Endpoint   = "https://gsa.apple.com/grandslam/GsService2"
)

// Error is a GrandSlam failure.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

func errorf(format string, a ...any) error { return &Error{Msg: fmt.Sprintf(format, a...)} }

// Client talks to GsService2 with an explicit device + anisette identity.
type Client struct {
	Device   *device.Device
	Anisette anisette.Provider
	HTTP     *http.Client

	// Stashed for diagnostics (set by Authenticate).
	LastInitResponse     map[string]any
	LastCompleteResponse map[string]any
	LastSessionKey       []byte
}

// NewClient returns a GSA client.
func NewClient(dev *device.Device, anis anisette.Provider) *Client {
	return &Client{Device: dev, Anisette: anis, HTTP: httpx.Client(10 * time.Second)}
}

func debugf(format string, a ...any) { logx.Debugf("gsa", format, a...) }

func (c *Client) cpd() (map[string]any, error) {
	cpd := map[string]any{
		"bootstrap": true,
		"icscrec":   true,
		"pbe":       false,
		"prkgen":    true,
		"svct":      "iCloud",
	}
	h, err := device.IdentityHeaders(c.Device, c.Anisette)
	if err != nil {
		return nil, err
	}
	for k, v := range h {
		cpd[k] = v
	}
	return cpd, nil
}

func (c *Client) request(params map[string]any) (map[string]any, error) {
	cpd, err := c.cpd()
	if err != nil {
		return nil, err
	}
	req := map[string]any{"cpd": cpd}
	for k, v := range params {
		req[k] = v
	}
	body := map[string]any{"Header": map[string]any{"Version": "1.0.1"}, "Request": req}
	op := plistx.Str(params["o"])
	if op == "" {
		op = "request"
	}
	data, err := plistx.EncodeXML(body)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequest(http.MethodPost, Endpoint, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "text/x-xml-plist")
	httpReq.Header.Set("Accept", "*/*")
	httpReq.Header.Set("User-Agent", UserAgent)
	httpReq.Header.Set("X-MMe-Client-Info", ClientInfo)
	resp, raw, err := c.doWithRetry(httpReq, data, op)
	if err != nil {
		return nil, err
	}
	payload, perr := plistx.Decode(raw)
	var response map[string]any
	if perr == nil {
		response = plistx.Dict(payload["Response"])
	}
	if response == nil || resp.StatusCode/100 != 2 {
		return nil, errorf("GSA %s failed: HTTP %d: %s", op, resp.StatusCode, Status(response))
	}
	debugf("%s: HTTP %d %s keys=%v", op, resp.StatusCode, Status(response), logx.Keys(response))
	return response, nil
}

// throttleBackoff is the wait before each retry of a throttled (429/503) GSA request,
// overridden by a Retry-After header when Apple sends one.
var throttleBackoff = []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second}

// doWithRetry sends a GSA request, retrying on 429/503. gsa.apple.com throttles after a
// burst of sign-ins (each login is at least two round trips), and one burst is normal
// during `ap login`.
func (c *Client) doWithRetry(req *http.Request, body []byte, op string) (*http.Response, []byte, error) {
	for attempt := 0; ; attempt++ {
		req.Body = io.NopCloser(bytes.NewReader(body))
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return nil, nil, errorf("GSA %s failed: %v", op, err)
		}
		raw, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, nil, errorf("GSA %s failed: %v", op, err)
		}
		throttled := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable
		if !throttled || attempt >= len(throttleBackoff) {
			return resp, raw, nil
		}
		wait := throttleBackoff[attempt]
		if ra, err := time.ParseDuration(resp.Header.Get("Retry-After") + "s"); err == nil && ra > 0 && ra < 2*time.Minute {
			wait = ra
		}
		debugf("%s: HTTP %d (throttled), retrying in %s", op, resp.StatusCode, wait)
		time.Sleep(wait)
	}
}

// Status formats the Status block of a GSA response for error messages.
func Status(r map[string]any) string {
	s := plistx.Dict(r["Status"])
	if s == nil {
		s = r
	}
	return fmt.Sprintf("ec=%v em=%q au=%q hsc=%v", s["ec"], plistx.Str(s["em"]), plistx.Str(s["au"]), s["hsc"])
}

// EncryptPassword is Apple's pre-SRP password KDF: SHA256 -> (hex for s2k_fo) -> PBKDF2-SHA256.
func EncryptPassword(password string, salt []byte, iterations int, protocol string) ([]byte, error) {
	p := sha256.Sum256([]byte(password))
	in := p[:]
	if protocol == "s2k_fo" {
		in = []byte(hex.EncodeToString(p[:]))
	}
	return pbkdf2.Key(sha256.New, string(in), salt, iterations, 32)
}

// Authenticate runs the SRP init/complete exchange and returns (complete response, spd).
func (c *Client) Authenticate(username, password, stage string) (map[string]any, map[string]any, error) {
	usr, err := srp.NewClient(username)
	if err != nil {
		return nil, nil, err
	}
	initResp, err := c.request(map[string]any{
		"A2k": usr.PublicA(), "ps": []any{"s2k", "s2k_fo"}, "u": username, "o": "init"})
	if err != nil {
		return nil, nil, err
	}
	c.LastInitResponse = initResp
	if !plistx.Has(initResp["sp"]) {
		return nil, nil, errorf("%s: init failed: %s", stage, Status(initResp))
	}
	protocol := plistx.Str(initResp["sp"])
	if protocol != "s2k" && protocol != "s2k_fo" {
		return nil, nil, errorf("unsupported protocol %s", protocol)
	}
	salt := plistx.Bytes(initResp["s"])
	bPub := plistx.Bytes(initResp["B"])
	iterations := int(plistx.Int(initResp["i"]))
	debugf("%s: init ok protocol=%s iterations=%d salt=%d bytes B=%d bytes", stage, protocol, iterations, len(salt), len(bPub))
	p, err := EncryptPassword(password, salt, iterations, protocol)
	if err != nil {
		return nil, nil, err
	}
	m1, err := usr.ProcessChallenge(salt, bPub, p)
	if err != nil {
		return nil, nil, errorf("failed to process SRP challenge (wrong password?)")
	}
	complete, err := c.request(map[string]any{
		"c": initResp["c"], "M1": m1, "u": username, "o": "complete"})
	if err != nil {
		return nil, nil, err
	}
	c.LastCompleteResponse = complete
	m2 := plistx.Bytes(complete["M2"])
	if m2 == nil {
		return nil, nil, errorf("%s: complete failed: %s", stage, Status(complete))
	}
	if !usr.VerifyServer(m2) {
		return nil, nil, errorf("server session verification failed (imposter?)")
	}
	c.LastSessionKey = usr.SessionKey()
	spdRaw, err := decryptCBC(usr.SessionKey(), plistx.Bytes(complete["spd"]))
	if err != nil {
		return nil, nil, errorf("could not decrypt spd: %v", err)
	}
	spd, err := plistx.Decode(spdRaw)
	if err != nil {
		return nil, nil, errorf("could not parse spd: %v", err)
	}
	debugf("%s: spd keys %v tokens %v", stage, logx.Keys(spd), logx.Keys(plistx.Dict(spd["t"])))
	return complete, spd, nil
}

func decryptCBC(sessionKey, data []byte) ([]byte, error) {
	key := srp.DeriveKey(sessionKey, "extra data key:")
	iv := srp.DeriveKey(sessionKey, "extra data iv:")[:16]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("bad spd length %d", len(data))
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
	pad := int(out[len(out)-1])
	if pad < 1 || pad > aes.BlockSize || pad > len(out) {
		return nil, fmt.Errorf("bad PKCS7 padding")
	}
	for _, b := range out[len(out)-pad:] {
		if int(b) != pad {
			return nil, fmt.Errorf("bad PKCS7 padding")
		}
	}
	return out[:len(out)-pad], nil
}

func (c *Client) twoFAHeaders(dsid, idmsToken string) (http.Header, error) {
	h := http.Header{}
	h.Set("Content-Type", "text/x-xml-plist")
	h.Set("User-Agent", "Xcode")
	h.Set("Accept", "text/x-xml-plist")
	h.Set("Accept-Language", "en-us")
	h.Set("X-Apple-Identity-Token", base64.StdEncoding.EncodeToString([]byte(dsid+":"+idmsToken)))
	h.Set("X-Apple-App-Info", "com.apple.gs.xcode.auth")
	h.Set("X-Xcode-Version", "11.2 (11B41)")
	h.Set("X-Mme-Client-Info", ClientInfo)
	ih, err := device.IdentityHeaders(c.Device, c.Anisette)
	if err != nil {
		return nil, err
	}
	for k, v := range ih {
		h.Set(k, v)
	}
	return h, nil
}

func (c *Client) do(method, url string, h http.Header, body []byte) (*http.Response, []byte, error) {
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header = h
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw, nil
}

// TriggerTrustedFactor asks Apple to push a code to the trusted devices.
func (c *Client) TriggerTrustedFactor(dsid, idmsToken string) error {
	h, err := c.twoFAHeaders(dsid, idmsToken)
	if err != nil {
		return err
	}
	resp, raw, err := c.do(http.MethodGet, "https://gsa.apple.com/auth/verify/trusteddevice", h, nil)
	if err != nil {
		return errorf("could not ask Apple to push a 2FA code: %v", err)
	}
	debugf("trusteddevice push: HTTP %d (%d bytes)", resp.StatusCode, len(raw))
	if resp.StatusCode/100 != 2 {
		return errorf("Apple refused to push a 2FA code (HTTP %d)", resp.StatusCode)
	}
	return nil
}

// SubmitTrustedFactor validates a trusted-device code.
func (c *Client) SubmitTrustedFactor(code, dsid, idmsToken string) error {
	h, err := c.twoFAHeaders(dsid, idmsToken)
	if err != nil {
		return err
	}
	h.Set("security-code", code)
	resp, raw, err := c.do(http.MethodGet, "https://gsa.apple.com/grandslam/GsService2/validate", h, nil)
	if err != nil {
		return err
	}
	return checkCode(resp, raw, "trusted-device")
}

// TriggerSMSFactor asks Apple to send an SMS code.
func (c *Client) TriggerSMSFactor(dsid, idmsToken string, phoneID int) error {
	h, err := c.twoFAHeaders(dsid, idmsToken)
	if err != nil {
		return err
	}
	h.Set("Content-Type", "application/json")
	body, _ := json.Marshal(map[string]any{"phoneNumber": map[string]any{"id": phoneID}, "mode": "sms"})
	resp, raw, err := c.do(http.MethodPut, "https://gsa.apple.com/auth/verify/phone/", h, body)
	if err != nil {
		return errorf("could not ask Apple to send an SMS code: %v", err)
	}
	debugf("sms push (phone %d): HTTP %d (%d bytes)", phoneID, resp.StatusCode, len(raw))
	if resp.StatusCode/100 != 2 {
		return errorf("Apple refused to send an SMS code (HTTP %d)", resp.StatusCode)
	}
	return nil
}

// SubmitSMSFactor validates an SMS code.
func (c *Client) SubmitSMSFactor(code, dsid, idmsToken string, phoneID int) error {
	h, err := c.twoFAHeaders(dsid, idmsToken)
	if err != nil {
		return err
	}
	h.Set("Content-Type", "application/json")
	body, _ := json.Marshal(map[string]any{
		"phoneNumber": map[string]any{"id": phoneID}, "mode": "sms",
		"securityCode": map[string]any{"code": code}})
	resp, raw, err := c.do(http.MethodPost, "https://gsa.apple.com/auth/verify/phone/securitycode", h, body)
	if err != nil {
		return err
	}
	return checkCode(resp, raw, "SMS")
}

// A rejected code comes back as HTTP 200 with a bare plist carrying ec/em.
func checkCode(resp *http.Response, raw []byte, kind string) error {
	body, _ := plistx.Decode(raw)
	debugf("%s code validation: HTTP %d %s", kind, resp.StatusCode, Status(body))
	if plistx.Int(body["ec"]) != 0 || resp.StatusCode/100 != 2 {
		reason := plistx.Str(body["em"])
		if reason == "" {
			reason = fmt.Sprint(resp.StatusCode)
		}
		return errorf("%s 2FA code rejected: %s", kind, reason)
	}
	return nil
}

// TwoFactorFunc is called with the factor kind ("trusted" | "sms") and returns the code.
type TwoFactorFunc func(kind string) (string, error)

// AuthenticateWith2FA returns the decrypted spd, handling 2FA transparently.
func AuthenticateWith2FA(c *Client, username, password string, twofa TwoFactorFunc) (map[string]any, error) {
	r, spd, err := c.Authenticate(username, password, "sign-in")
	if err != nil {
		return nil, err
	}
	status := plistx.Dict(r["Status"])
	au := plistx.Str(status["au"])
	// Since Apple's October 2026 change the complete response may carry no "au" at all
	// and instead hsc=409: a code has already been pushed to the trusted devices, and the
	// spd holds no PET until that code is validated.
	codeAlreadySent := au == "" && plistx.Int(status["hsc"]) == 409
	debugf("sign-in: au=%q hsc=%v codeAlreadySent=%v", au, status["hsc"], codeAlreadySent)
	if au == "trustedDeviceSecondaryAuth" || au == "secondaryAuth" || codeAlreadySent {
		dsid := plistx.Str(spd["adsid"])
		if dsid == "" {
			dsid = plistx.Str(spd["DsPrsId"])
		}
		idms := plistx.Str(spd["GsIdmsToken"])
		if idms == "" {
			idms = plistx.Str(spd["GsIdMS"])
		}
		if dsid == "" || idms == "" {
			return nil, errorf("2FA required but missing dsid/GsIdMS in spd")
		}
		if au != "secondaryAuth" {
			if !codeAlreadySent {
				if err := c.TriggerTrustedFactor(dsid, idms); err != nil {
					return nil, err
				}
			}
			code, err := twofa("trusted")
			if err != nil {
				return nil, err
			}
			if err := c.SubmitTrustedFactor(code, dsid, idms); err != nil {
				return nil, err
			}
		} else {
			if err := c.TriggerSMSFactor(dsid, idms, 1); err != nil {
				return nil, err
			}
			code, err := twofa("sms")
			if err != nil {
				return nil, err
			}
			if err := c.SubmitSMSFactor(code, dsid, idms, 1); err != nil {
				return nil, err
			}
		}
		// Re-authenticate: the device is now trusted, so this should NOT prompt again.
		r, spd, err = c.Authenticate(username, password, "re-auth after 2FA (password already verified)")
		if err != nil {
			return nil, err
		}
		status = plistx.Dict(r["Status"])
		if plistx.Str(status["au"]) != "" || plistx.Int(status["hsc"]) == 409 {
			return nil, errorf("still being asked for 2FA after submitting a code (%s)", Status(r))
		}
	}
	return spd, nil
}

// ExtractPET returns (dsid, pet, expiry_ms) from spd. The PET is a password-equivalent token.
func ExtractPET(spd map[string]any) (string, string, int64, error) {
	dsid := plistx.Str(spd["adsid"])
	if dsid == "" {
		dsid = plistx.Str(spd["DsPrsId"])
	}
	tokens := plistx.Dict(spd["t"])
	entry := plistx.Dict(tokens["com.apple.gs.idms.pet"])
	pet := plistx.Str(entry["token"])
	if dsid == "" || pet == "" {
		return "", "", 0, errorf("no PET in spd (tokens present: %v; run with --debug for the GSA status)", logx.Keys(tokens))
	}
	debugf("PET for dsid %s expires %s", dsid, time.UnixMilli(plistx.Int(entry["expiry"])).Format(time.RFC3339))
	return dsid, pet, plistx.Int(entry["expiry"]), nil
}

// Package icloud reaches iCloud services with the long-lived mmeAuthToken (no password,
// no 2FA): loginDelegates mints it from a fresh PET, get_account_settings returns the
// service-URL map. See RESEARCH.md stage 1.
package icloud

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hpidcock/ap/internal/anisette"
	"github.com/hpidcock/ap/internal/device"
	"github.com/hpidcock/ap/internal/httpx"
	"github.com/hpidcock/ap/internal/plistx"
)

const (
	LoginDelegatesURL  = "https://setup.icloud.com/setup/iosbuddy/loginDelegates"
	AccountSettingsURL = "https://setup.icloud.com/setup/get_account_settings"

	// AOSKit/accountsd identity for the iCloud setup endpoints (distinct from the GSA akd UA).
	UserAgent  = "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0"
	ClientInfo = "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.accountsd/113)>"
)

// Error is an iCloud setup failure.
type Error struct {
	Msg        string
	HTTPStatus int
}

func (e *Error) Error() string { return e.Msg }

// Basic builds an HTTP Basic Authorization value.
func Basic(user, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+secret))
}

func post(url string, headers map[string]string, body []byte) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpx.Client(20 * time.Second).Do(req)
	if err != nil {
		return 0, nil, &Error{Msg: fmt.Sprintf("%s: %v", url, err)}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	return resp.StatusCode, raw, err
}

// LoginMobileMe exchanges the fresh PET for the persistent mmeAuthToken.
// Returns (dsid, mmeAuthToken, service-data, raw response).
func LoginMobileMe(username, pet, adsid, clientID string, dev *device.Device, anis anisette.Provider) (string, string, map[string]any, map[string]any, error) {
	body, err := plistx.EncodeXML(map[string]any{
		"apple-id":  username,
		"delegates": map[string]any{"com.apple.mobileme": map[string]any{}},
		"password":  pet,
		"client-id": clientID,
	})
	if err != nil {
		return "", "", nil, nil, err
	}
	headers := map[string]string{
		"X-Apple-ADSID":     adsid,
		"User-Agent":        UserAgent,
		"X-Mme-Client-Info": ClientInfo,
		"Accept":            "*/*",
	}
	ih, err := device.IdentityHeaders(dev, anis)
	if err != nil {
		return "", "", nil, nil, err
	}
	for k, v := range ih {
		headers[k] = v
	}
	headers["Authorization"] = Basic(username, pet) // apple-id:PET (NOT dsid:PET)
	status, raw, err := post(LoginDelegatesURL, headers, body)
	if err != nil {
		return "", "", nil, nil, err
	}
	data, err := plistx.Decode(raw)
	if err != nil {
		return "", "", nil, nil, &Error{Msg: fmt.Sprintf("loginDelegates returned HTTP %d with an unreadable body", status), HTTPStatus: status}
	}
	mm := plistx.Dict(plistx.Dict(data["delegates"])["com.apple.mobileme"])
	st, ok := mm["status"]
	if !ok {
		st = data["status"]
	}
	if plistx.Int(st) != 0 || st == nil {
		msg := plistx.Str(mm["status-message"])
		if msg == "" {
			msg = plistx.Str(data["status-message"])
		}
		if msg == "" {
			msg = "unknown error"
		}
		return "", "", nil, nil, &Error{Msg: fmt.Sprintf("loginDelegates status %v: %s", st, msg), HTTPStatus: status}
	}
	serviceData := plistx.Dict(mm["service-data"])
	dsid := plistx.Str(data["dsid"])
	if dsid == "" {
		dsid = plistx.Str(plistx.Dict(serviceData["appleAccountInfo"])["dsid"])
	}
	token := plistx.Str(plistx.Dict(serviceData["tokens"])["mmeAuthToken"])
	return dsid, token, serviceData, data, nil
}

// FetchAccountSettings fetches the account/webservices settings with
// `Basic base64(dsid:mmeAuthToken)`. Returns (http status, parsed plist).
func FetchAccountSettings(dsid, mmeToken string, dev *device.Device, anis anisette.Provider) (int, map[string]any, error) {
	if dsid == "" || mmeToken == "" {
		return 0, nil, &Error{Msg: "no mmeAuthToken stored; run `ap login` to mint one"}
	}
	headers := map[string]string{
		"Authorization":     Basic(dsid, mmeToken),
		"X-Mme-Client-Info": ClientInfo,
		"User-Agent":        UserAgent,
		"Accept":            "*/*",
	}
	ih, err := device.IdentityHeaders(dev, anis)
	if err != nil {
		return 0, nil, err
	}
	for k, v := range ih {
		headers[k] = v
	}
	status, raw, err := post(AccountSettingsURL, headers, nil)
	if err != nil {
		return 0, nil, err
	}
	data, err := plistx.Decode(raw)
	if err != nil {
		return status, nil, &Error{Msg: fmt.Sprintf("get_account_settings returned HTTP %d with an unreadable body", status), HTTPStatus: status}
	}
	return status, data, nil
}

// ExtractWebservices flattens the service-URL map, tolerating both shapes:
//
//   - modern:  settings["webservices"][name] = {"url": ..., "status": ...}
//   - classic: settings["com.apple.mobileme"]["com.apple.Dataclass.X"] = {"url": ...}
//
// Services carrying their endpoint under a non-"url" key (KeychainSync ->
// escrowProxyUrl, KeyValue -> configURL, Ubiquity -> wsUrl) are captured too, and the
// classic keys are also exposed as their lower-cased last component ("keychainsync").
func ExtractWebservices(settings map[string]any) map[string]string {
	out := map[string]string{}
	for name, v := range plistx.Dict(settings["webservices"]) {
		d := plistx.Dict(v)
		if u := plistx.Str(d["url"]); u != "" {
			out[name] = u
		}
	}
	altKeys := []string{"url", "escrowProxyUrl", "configURL", "wsUrl"}
	for name, v := range plistx.Dict(settings["com.apple.mobileme"]) {
		d := plistx.Dict(v)
		if d == nil {
			continue
		}
		var u string
		for _, k := range altKeys {
			if s := plistx.Str(d[k]); s != "" {
				u = s
				break
			}
		}
		if u == "" {
			continue
		}
		if _, ok := out[name]; !ok {
			out[name] = u
		}
		short := strings.ToLower(name[strings.LastIndex(name, ".")+1:])
		if _, ok := out[short]; !ok {
			out[short] = u
		}
	}
	return out
}

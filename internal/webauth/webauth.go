// Package webauth is the idmsa.apple.com web-session login - a second Apple auth
// surface (the icloud.com browser flow), separate from the device GSA flow. It cannot
// join the Octagon circle, but it reaches web-scoped webservices the device path never
// sees - `premiummailsettings` (Hide My Email). SRP-6a, same variant as gsa.
package webauth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hpidcock/ap/internal/gsa"
	"github.com/hpidcock/ap/internal/httpx"
	"github.com/hpidcock/ap/internal/session"
	"github.com/hpidcock/ap/internal/srp"
)

const (
	AuthEndpoint  = "https://idmsa.apple.com/appleauth/auth"
	SetupEndpoint = "https://setup.icloud.com/setup/ws/1"
	ICloudOrigin  = "https://www.icloud.com"

	// WidgetKey is icloud.com's public OAuth widget key (not account-specific).
	WidgetKey = "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d"

	userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 " +
		"(KHTML, like Gecko) Version/18.3.1 Safari/605.1.15"
)

// Response headers Apple uses to thread session state across calls -> session_data keys.
var headerData = map[string]string{
	"X-Apple-ID-Account-Country": "account_country",
	"X-Apple-ID-Session-Id":      "session_id",
	"X-Apple-Session-Token":      "session_token",
	"X-Apple-TwoSV-Trust-Token":  "trust_token",
	"X-Apple-Auth-Attributes":    "auth_attributes",
	"scnt":                       "scnt",
}

// Error is a web-session failure.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

func errorf(format string, a ...any) error { return &Error{Msg: fmt.Sprintf(format, a...)} }

// recordingJar wraps a cookie jar so the cookies it has been handed can be exported with
// their domains (the standard jar only answers per-URL queries).
type recordingJar struct {
	mu    sync.Mutex
	inner *cookiejar.Jar
	all   map[string]*http.Cookie
}

func newRecordingJar() *recordingJar {
	j, _ := cookiejar.New(nil)
	return &recordingJar{inner: j, all: map[string]*http.Cookie{}}
}

func (j *recordingJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	for _, c := range cookies {
		cc := *c
		if cc.Domain == "" {
			cc.Domain = u.Hostname()
		}
		if cc.Path == "" {
			cc.Path = "/"
		}
		j.all[strings.TrimPrefix(cc.Domain, ".")+"|"+cc.Path+"|"+cc.Name] = &cc
	}
	j.mu.Unlock()
	j.inner.SetCookies(u, cookies)
}

func (j *recordingJar) Cookies(u *url.URL) []*http.Cookie { return j.inner.Cookies(u) }

func (j *recordingJar) export() []session.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	var out []session.Cookie
	for _, c := range j.all {
		if c.MaxAge < 0 || (!c.Expires.IsZero() && c.Expires.Before(time.Now())) {
			continue
		}
		sc := session.Cookie{Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path, Secure: c.Secure}
		if !c.Expires.IsZero() {
			sc.Expires = c.Expires.Unix()
		}
		out = append(out, sc)
	}
	return out
}

func (j *recordingJar) load(cookies []session.Cookie) {
	for _, c := range cookies {
		host := strings.TrimPrefix(c.Domain, ".")
		if host == "" {
			continue
		}
		hc := &http.Cookie{Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path, Secure: c.Secure}
		if c.Expires != 0 {
			hc.Expires = time.Unix(c.Expires, 0)
		}
		j.SetCookies(&url.URL{Scheme: "https", Host: host, Path: "/"}, []*http.Cookie{hc})
	}
}

// Session is one idmsa web-session login. FrameTag is a random per-session `auth-<uuid>`
// threaded through the OAuth headers - generate once, persist, reuse.
type Session struct {
	FrameTag    string
	SessionData map[string]string
	NeedsTwoFA  bool
	HTTP        *http.Client
	jar         *recordingJar
}

// NewSession restores (or starts) a web session.
func NewSession(frameTag string, data map[string]string, cookies []session.Cookie) *Session {
	jar := newRecordingJar()
	jar.load(cookies)
	sd := map[string]string{}
	for k, v := range data {
		sd[k] = v
	}
	return &Session{FrameTag: frameTag, SessionData: sd, HTTP: httpx.ClientWithJar(20*time.Second, jar), jar: jar}
}

// Export returns the persistable state.
func (s *Session) Export() *session.WebAuth {
	return &session.WebAuth{FrameTag: s.FrameTag, SessionData: s.SessionData, Cookies: s.jar.export()}
}

func (s *Session) authHeaders() http.Header {
	h := http.Header{}
	set := func(k, v string) { h.Set(k, v) }
	set("Accept", "application/json")
	set("Content-Type", "application/json")
	set("Origin", "https://idmsa.apple.com")
	set("Referer", "https://idmsa.apple.com/")
	set("X-Apple-Widget-Key", WidgetKey)
	set("X-Apple-OAuth-Client-Id", WidgetKey)
	set("X-Apple-OAuth-Client-Type", "firstPartyAuth")
	set("X-Apple-OAuth-Redirect-URI", ICloudOrigin)
	set("X-Apple-OAuth-Require-Grant-Code", "true")
	set("X-Apple-OAuth-Response-Mode", "web_message")
	set("X-Apple-OAuth-Response-Type", "code")
	set("X-Apple-OAuth-State", s.FrameTag)
	set("X-Apple-Frame-Id", s.FrameTag)
	set("X-Requested-With", "XMLHttpRequest")
	set("X-Apple-Mandate-Security-Upgrade", "0")
	set("X-Apple-I-Require-UE", "true")
	if v := s.SessionData["auth_attributes"]; v != "" {
		set("X-Apple-Auth-Attributes", v)
	}
	if v := s.SessionData["scnt"]; v != "" {
		set("scnt", v)
	}
	if v := s.SessionData["session_id"]; v != "" {
		set("X-Apple-ID-Session-Id", v)
	}
	return h
}

func setupHeaders() http.Header {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("Origin", ICloudOrigin)
	h.Set("Referer", ICloudOrigin+"/")
	return h
}

func (s *Session) capture(resp *http.Response) {
	for header, key := range headerData {
		if v := resp.Header.Get(header); v != "" {
			s.SessionData[key] = v
		}
	}
}

func (s *Session) do(method, rawURL string, headers http.Header, params url.Values, body any) (*http.Response, []byte, error) {
	if params != nil {
		rawURL += "?" + params.Encode()
	}
	var rdr io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, nil, err
		}
		rdr = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, rawURL, rdr)
	if err != nil {
		return nil, nil, err
	}
	req.Header = headers.Clone()
	if req.Header == nil {
		req.Header = http.Header{}
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return nil, nil, errorf("%s %s: %v", method, rawURL, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	s.capture(resp)
	return resp, raw, nil
}

func jsonOrNil(raw []byte) map[string]any {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m
}

// reason extracts Apple's error text from a JSON error body.
func reason(data map[string]any) string {
	if data == nil {
		return ""
	}
	for _, k := range []string{"errorMessage", "reason", "errorReason"} {
		if s, ok := data[k].(string); ok && s != "" {
			return s
		}
	}
	if s, ok := data["error"].(string); ok {
		return s
	}
	return ""
}

func ok(resp *http.Response) bool { return resp.StatusCode/100 == 2 }

func reasonOr(data map[string]any, resp *http.Response) string {
	if r := reason(data); r != "" {
		return r
	}
	return resp.Status
}

// authStart loads the widget and sets the idmsa session cookies (e.g. `aasp`).
func (s *Session) authStart() error {
	params := url.Values{
		"frame_id": {s.FrameTag}, "language": {"en_US"}, "skVersion": {"7"},
		"iframeId": {s.FrameTag}, "client_id": {WidgetKey},
		"redirect_uri": {ICloudOrigin}, "response_type": {"code"},
		"response_mode": {"web_message"}, "state": {s.FrameTag}, "authVersion": {"latest"},
	}
	h := http.Header{}
	h.Set("Accept", "*/*")
	resp, _, err := s.do(http.MethodGet, AuthEndpoint+"/authorize/signin", h, params, nil)
	if err != nil {
		return err
	}
	if !ok(resp) {
		return errorf("could not start the web session (HTTP %d)", resp.StatusCode)
	}
	return nil
}

func (s *Session) federate(username string) error {
	resp, _, err := s.do(http.MethodPost, AuthEndpoint+"/federate", s.authHeaders(),
		url.Values{"isRememberMeEnabled": {"true"}},
		map[string]any{"accountName": username, "rememberMe": true})
	if err != nil {
		return err
	}
	if !ok(resp) {
		return errorf("federate failed (HTTP %d)", resp.StatusCode)
	}
	return nil
}

func (s *Session) srpInit(username string, a []byte) (map[string]any, error) {
	resp, raw, err := s.do(http.MethodPost, AuthEndpoint+"/signin/init", s.authHeaders(), nil,
		map[string]any{"a": base64.StdEncoding.EncodeToString(a), "accountName": username,
			"protocols": []string{"s2k", "s2k_fo"}})
	if err != nil {
		return nil, err
	}
	data := jsonOrNil(raw)
	if data == nil || reason(data) != "" || !ok(resp) {
		return nil, errorf("SRP init failed (HTTP %d): %s", resp.StatusCode, reasonOr(data, resp))
	}
	return data, nil
}

// Signin runs authorize/signin -> federate -> signin/init -> signin/complete. A 409
// (HSA2 challenge pending) sets NeedsTwoFA rather than failing.
func (s *Session) Signin(username, password, trustToken string) error {
	username = strings.ToLower(username) // Apple lowercases the account name for the SRP proof
	if err := s.authStart(); err != nil {
		return err
	}
	if err := s.federate(username); err != nil {
		return err
	}
	usr, err := srp.NewClient(username)
	if err != nil {
		return err
	}
	init, err := s.srpInit(username, usr.PublicAPadded())
	if err != nil {
		return err
	}
	salt, err := base64.StdEncoding.DecodeString(fmt.Sprint(init["salt"]))
	if err != nil {
		return errorf("SRP init returned a bad salt")
	}
	bBytes, err := base64.StdEncoding.DecodeString(fmt.Sprint(init["b"]))
	if err != nil {
		return errorf("SRP init returned a bad B")
	}
	iter, _ := init["iteration"].(float64)
	protocol, _ := init["protocol"].(string)
	p, err := gsa.EncryptPassword(password, salt, int(iter), protocol)
	if err != nil {
		return err
	}
	m1, err := usr.ProcessChallenge(salt, bBytes, p)
	if err != nil {
		return errorf("SRP challenge processing failed (invalid server-supplied B)")
	}
	m2 := usr.ExpectedM2()
	trust := []string{}
	if trustToken != "" {
		trust = []string{trustToken}
	}
	resp, raw, err := s.do(http.MethodPost, AuthEndpoint+"/signin/complete", s.authHeaders(),
		url.Values{"isRememberMeEnabled": {"true"}},
		map[string]any{"accountName": username, "m1": base64.StdEncoding.EncodeToString(m1),
			"m2": base64.StdEncoding.EncodeToString(m2), "c": init["c"], "rememberMe": true,
			"trustTokens": trust})
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusConflict {
		s.NeedsTwoFA = true
		return nil
	}
	s.NeedsTwoFA = false
	if ok(resp) {
		return nil
	}
	return errorf("sign-in failed (HTTP %d): %s", resp.StatusCode, reasonOr(jsonOrNil(raw), resp))
}

// RequestPushNotification explicitly pushes a 2FA code to trusted devices (the SRP 409
// no longer auto-triggers it). Call once right after Signin reports NeedsTwoFA.
func (s *Session) RequestPushNotification() error {
	resp, _, err := s.do(http.MethodPut, AuthEndpoint+"/verify/trusteddevice/securitycode", s.authHeaders(), nil, nil)
	if err != nil {
		return err
	}
	if !ok(resp) {
		return errorf("could not request a 2FA push (HTTP %d)", resp.StatusCode)
	}
	return nil
}

// Submit2FA posts the 6-digit code and then asks for the browser to be trusted.
func (s *Session) Submit2FA(code string) error {
	resp, raw, err := s.do(http.MethodPost, AuthEndpoint+"/verify/trusteddevice/securitycode", s.authHeaders(), nil,
		map[string]any{"securityCode": map[string]any{"code": code}})
	if err != nil {
		return err
	}
	if !ok(resp) {
		return errorf("2FA code rejected (HTTP %d): %s", resp.StatusCode, reasonOr(jsonOrNil(raw), resp))
	}
	trust, _, err := s.do(http.MethodGet, AuthEndpoint+"/2sv/trust", s.authHeaders(), nil, nil)
	if err != nil {
		return err
	}
	if !ok(trust) {
		return errorf("could not trust the session (HTTP %d)", trust.StatusCode)
	}
	s.NeedsTwoFA = false
	return nil
}

// AccountLogin calls setup/ws/1/accountLogin with the session token. Returns the
// account payload (dsInfo, webservices, hsaChallengeRequired/hsaTrustedBrowser).
func (s *Session) AccountLogin() (map[string]any, error) {
	body := map[string]any{
		"accountCountryCode": s.SessionData["account_country"],
		"dsWebAuthToken":     s.SessionData["session_token"],
		"extended_login":     true,
		"trustToken":         s.SessionData["trust_token"],
	}
	resp, raw, err := s.do(http.MethodPost, SetupEndpoint+"/accountLogin", setupHeaders(), nil, body)
	if err != nil {
		return nil, err
	}
	data := jsonOrNil(raw)
	if data == nil {
		return nil, errorf("accountLogin returned non-JSON (HTTP %d)", resp.StatusCode)
	}
	if r := reason(data); r != "" || !ok(resp) {
		return nil, errorf("accountLogin failed (HTTP %d): %s", resp.StatusCode, reasonOr(data, resp))
	}
	return data, nil
}

// HSAChallengeRequired is true if accountLogin still needs a 2FA code.
func HSAChallengeRequired(account map[string]any) bool {
	ds, _ := account["dsInfo"].(map[string]any)
	hsa, _ := ds["hsaVersion"].(float64)
	challenge, _ := account["hsaChallengeRequired"].(bool)
	trusted, _ := account["hsaTrustedBrowser"].(bool)
	return int(hsa) == 2 && (challenge || !trusted)
}

// ExtractWebservices flattens accountLogin's webservices map to {name: url}.
func ExtractWebservices(account map[string]any) map[string]string {
	out := map[string]string{}
	ws, _ := account["webservices"].(map[string]any)
	for name, v := range ws {
		d, _ := v.(map[string]any)
		u, _ := d["url"].(string)
		st, _ := d["status"].(string)
		if u != "" && st != "off" {
			out[name] = u
		}
	}
	return out
}

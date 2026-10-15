// Package remote is the anisette-v3 client: the machine data comes from an anisette-v3
// server (Dadoum's protocol, as used by SideStore, isideload and iloader). ap keeps the
// machine's identity - a random identifier and the provisioning blob Apple issued for it -
// in a private file, and asks the server to turn them into a one-time password before
// each request to Apple. The server never sees the Apple ID, password or any token.
//
// This exists because Apple started validating the client-info string against the
// platform of the library that produced the machine data, and blocks the Android library
// ap runs in process (see device.Description). The servers run platforms Apple still
// accepts and tell ap which client info to present.
package remote

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hpidcock/ap/internal/anisette"
	"github.com/hpidcock/ap/internal/anisette/provisioning"
	"github.com/hpidcock/ap/internal/httpx"
	"github.com/hpidcock/ap/internal/logx"
	"github.com/hpidcock/ap/internal/paths"
)

// DefaultURL is the server used when none is configured: the one isideload and iloader
// default to since 2026-10-14.
const DefaultURL = "https://ani.jkcoxson.com"

// headerTTL is how long one set of machine data is reused before asking the server
// again; isideload refreshes after 60s.
const headerTTL = 30 * time.Second

// State is the persisted machine identity for one server.
type State struct {
	Server        string `json:"server"`
	Identifier    []byte `json:"identifier"`               // 16 random bytes; the server derives the ADI identifier from them
	ADIPB         []byte `json:"adi_pb,omitempty"`         // provisioning blob issued by Apple through the server
	ClientInfo    string `json:"client_info,omitempty"`    // last client info the server announced
	UserAgent     string `json:"user_agent,omitempty"`     // last user agent the server announced
	ProvisionedAt int64  `json:"provisioned_at,omitempty"` // unix seconds
}

// Provisioned reports whether Apple has issued a provisioning blob for this identity.
func (s *State) Provisioned() bool { return len(s.ADIPB) > 0 && len(s.Identifier) == 16 }

// DeviceID is the X-Mme-Device-Id: the identifier formatted as a UUID. Lower case, like
// isideload, because the server receives it verbatim during a resync.
func (s *State) DeviceID() string {
	h := hex.EncodeToString(s.Identifier)
	if len(h) != 32 {
		return ""
	}
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// LocalUserUUID is the X-Apple-I-MD-LU: hex SHA-256 of the identifier (lower case, as
// the server receives it during a resync).
func (s *State) LocalUserUUID() string {
	sum := sha256.Sum256(s.Identifier)
	return hex.EncodeToString(sum[:])
}

func newState(server string) *State {
	s := &State{Server: server, Identifier: make([]byte, 16)}
	_, _ = rand.Read(s.Identifier)
	return s
}

// Remote is an anisette.Provider backed by an anisette-v3 server.
type Remote struct {
	URL       string
	StatePath string
	HTTP      *http.Client
	Logf      func(string, ...any)
	// URLBag, when set, bypasses Apple's URL-bag lookup during provisioning (tests).
	URLBag map[string]string
	// AppleHTTP is used for the provisioning requests to Apple.
	AppleHTTP *http.Client
	// Timeout bounds every server call, including the websocket session.
	Timeout time.Duration

	mu         sync.Mutex
	state      *State
	clientInfo string
	userAgent  string
	cached     map[string]string
	cachedAt   time.Time
}

// New returns a provider for the server at url, keeping its state in statePath.
func New(url, statePath string, logf func(string, ...any)) *Remote {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Remote{
		URL: strings.TrimRight(url, "/"), StatePath: statePath, Logf: logf,
		HTTP:      httpx.Client(30 * time.Second),
		AppleHTTP: httpx.ClientNoKeepAlive(60 * time.Second),
		Timeout:   60 * time.Second,
	}
}

// --- state --------------------------------------------------------------------------

func (r *Remote) loadStateLocked() error {
	if r.state != nil {
		return nil
	}
	data, err := os.ReadFile(r.StatePath)
	switch {
	case err == nil:
		var s State
		if json.Unmarshal(data, &s) == nil && len(s.Identifier) == 16 {
			if s.Server == r.URL {
				r.state = &s
				logx.Debugf("anisette", "remote state loaded: server=%s device=%s provisioned=%v", s.Server, s.DeviceID(), s.Provisioned())
				return nil
			}
			r.Logf("anisette server changed (%s -> %s): this machine will be provisioned again", s.Server, r.URL)
		} else {
			r.Logf("anisette state at %s is unreadable; starting a fresh machine identity", r.StatePath)
		}
	case !errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("anisette state: %w", err)
	}
	r.state = newState(r.URL)
	return r.saveStateLocked()
}

func (r *Remote) saveStateLocked() error {
	data, err := json.MarshalIndent(r.state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(r.StatePath), 0o700); err != nil {
		return fmt.Errorf("anisette state: %w", err)
	}
	if err := paths.WritePrivate(r.StatePath, data); err != nil {
		return fmt.Errorf("anisette state: %w", err)
	}
	return nil
}

// Reset forgets the machine identity so the next request provisions a new one.
func (r *Remote) Reset() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.state, r.cached = newState(r.URL), nil
	return r.saveStateLocked()
}

// State returns a copy of the persisted identity (for status output).
func (r *Remote) State() (State, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.loadStateLocked(); err != nil {
		return State{}, err
	}
	return *r.state, nil
}

// --- server calls -------------------------------------------------------------------

func (r *Remote) serverError(what string, err error) error {
	return &anisette.Error{Msg: fmt.Sprintf("anisette server %s: %s: %v", r.URL, what, err)}
}

func (r *Remote) getJSON(path string, body any, out any) error {
	var req *http.Request
	var err error
	if body == nil {
		req, err = http.NewRequest(http.MethodGet, r.URL+path, nil)
	} else {
		data, merr := json.Marshal(body)
		if merr != nil {
			return merr
		}
		req, err = http.NewRequest(http.MethodPost, r.URL+path, bytes.NewReader(data))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ap")
	resp, err := r.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("non-JSON response (HTTP %d): %s", resp.StatusCode, logx.Body(resp.Header.Get("Content-Type"), raw, 200))
	}
	return nil
}

// ClientInfo returns the client-info string and user agent the server's machine data is
// valid for. The server is asked once per process; its last answer is kept in the state
// file so an unreachable server does not stop the cached value being used.
func (r *Remote) ClientInfo() (clientInfo, userAgent string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.clientInfoLocked()
}

func (r *Remote) clientInfoLocked() (string, string, error) {
	if r.clientInfo != "" {
		return r.clientInfo, r.userAgent, nil
	}
	if err := r.loadStateLocked(); err != nil {
		return "", "", err
	}
	var info struct {
		ClientInfo string `json:"client_info"`
		UserAgent  string `json:"user_agent"`
	}
	if err := r.getJSON("/v3/client_info", nil, &info); err != nil || info.ClientInfo == "" {
		if r.state.ClientInfo != "" {
			logx.Errorf("anisette", err, "client_info unavailable, using the cached %q", r.state.ClientInfo)
			r.clientInfo, r.userAgent = r.state.ClientInfo, r.state.UserAgent
			return r.clientInfo, r.userAgent, nil
		}
		if err == nil {
			err = errors.New("empty client_info")
		}
		return "", "", r.serverError("client_info", err)
	}
	if info.UserAgent == "" {
		info.UserAgent = "akd/1.0 CFNetwork/808.1.4"
	}
	if info.ClientInfo != r.state.ClientInfo {
		if r.state.ClientInfo != "" {
			r.Logf("anisette server now presents %q (was %q)", info.ClientInfo, r.state.ClientInfo)
		}
		r.state.ClientInfo, r.state.UserAgent = info.ClientInfo, info.UserAgent
		if err := r.saveStateLocked(); err != nil {
			return "", "", err
		}
	}
	r.clientInfo, r.userAgent = info.ClientInfo, info.UserAgent
	logx.Debugf("anisette", "server %s client_info=%q user_agent=%q", r.URL, info.ClientInfo, info.UserAgent)
	return r.clientInfo, r.userAgent, nil
}

// errNotProvisioned is what the server says when Apple no longer accepts the blob.
var errNotProvisioned = errors.New("server rejected the provisioning blob (-45061)")

// getHeadersLocked asks the server for machine data; with sim set it is a resync (the
// X-Apple-I-MD-DATA GrandSlam returned with hsc 434), which the server feeds to ADI
// before answering.
func (r *Remote) getHeadersLocked(sim string) (otp, mid, rinfo string, err error) {
	var resp struct {
		Result  string `json:"result"`
		Message string `json:"message"`
		OTP     string `json:"X-Apple-I-MD"`
		MID     string `json:"X-Apple-I-MD-M"`
		RINFO   string `json:"X-Apple-I-MD-RINFO"`
	}
	body := map[string]string{
		"identifier": base64.StdEncoding.EncodeToString(r.state.Identifier),
		"adi_pb":     base64.StdEncoding.EncodeToString(r.state.ADIPB),
	}
	if sim != "" {
		body["sim"] = sim
		body["device_id"] = r.state.DeviceID()
		body["md_lu"] = r.state.LocalUserUUID()
	}
	if err := r.getJSON("/v3/get_headers", body, &resp); err != nil {
		return "", "", "", r.serverError("get_headers", err)
	}
	switch resp.Result {
	case "Headers":
		if resp.OTP == "" || resp.MID == "" {
			return "", "", "", r.serverError("get_headers", errors.New("answer lacks X-Apple-I-MD / X-Apple-I-MD-M"))
		}
		if resp.RINFO == "" {
			resp.RINFO = "17106176"
		}
		return resp.OTP, resp.MID, resp.RINFO, nil
	case "GetHeadersError":
		if strings.Contains(resp.Message, "-45061") {
			return "", "", "", errNotProvisioned
		}
		return "", "", "", r.serverError("get_headers", errors.New(resp.Message))
	default:
		return "", "", "", r.serverError("get_headers", fmt.Errorf("unexpected result %q", resp.Result))
	}
}

// AllHeaders produces the complete header set (the anisette-v1 response body shape),
// provisioning first if needed and re-provisioning once if the server reports that
// Apple no longer accepts the stored blob.
func (r *Remote) AllHeaders() (map[string]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.loadStateLocked(); err != nil {
		return nil, err
	}
	if r.cached != nil && time.Since(r.cachedAt) < headerTTL {
		return copyMap(r.cached), nil
	}
	clientInfo, _, err := r.clientInfoLocked()
	if err != nil {
		return nil, err
	}
	for attempt := 0; ; attempt++ {
		if !r.state.Provisioned() {
			if err := r.provisionLocked(); err != nil {
				return nil, err
			}
		}
		otp, mid, rinfo, err := r.getHeadersLocked("")
		if errors.Is(err, errNotProvisioned) && attempt == 0 {
			r.Logf("Apple no longer accepts this machine's provisioning; provisioning again...")
			r.state = newState(r.URL)
			r.state.ClientInfo, r.state.UserAgent = r.clientInfo, r.userAgent
			if err := r.saveStateLocked(); err != nil {
				return nil, err
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		r.cacheLocked(clientInfo, otp, mid, rinfo)
		logx.Tracef("anisette", "machine data from %s for device %s", r.URL, r.state.DeviceID())
		return copyMap(r.cached), nil
	}
}

func (r *Remote) cacheLocked(clientInfo, otp, mid, rinfo string) {
	now := time.Now()
	zone, _ := now.Zone()
	r.cached = map[string]string{
		"X-Apple-I-Client-Time": now.UTC().Format("2006-01-02T15:04:05Z"),
		"X-Apple-I-MD":          otp,
		"X-Apple-I-MD-M":        mid,
		"X-Apple-I-MD-RINFO":    rinfo,
		"X-Apple-I-MD-LU":       r.state.LocalUserUUID(),
		"X-Apple-I-SRL-NO":      "0",
		"X-MMe-Client-Info":     clientInfo,
		"X-Apple-I-TimeZone":    zone,
		"X-Apple-Locale":        "en_US",
		"X-Mme-Device-Id":       r.state.DeviceID(),
	}
	r.cachedAt = now
}

// Resync implements anisette.Resyncer: GrandSlam answered hsc 434 with X-Apple-I-MD-DATA,
// which the server feeds to ADI; the fresh machine data replaces the cached set.
func (r *Remote) Resync(simBase64 string) (map[string]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.loadStateLocked(); err != nil {
		return nil, err
	}
	if !r.state.Provisioned() {
		return nil, &anisette.Error{Msg: "anisette resync requested before provisioning"}
	}
	clientInfo, _, err := r.clientInfoLocked()
	if err != nil {
		return nil, err
	}
	otp, mid, rinfo, err := r.getHeadersLocked(simBase64)
	if err != nil {
		return nil, &anisette.Error{Msg: fmt.Sprintf("anisette resync: %v", err)}
	}
	r.cacheLocked(clientInfo, otp, mid, rinfo)
	logx.Debugf("anisette", "resynced machine data for device %s", r.state.DeviceID())
	return anisette.Filter(copyMap(r.cached))
}

func copyMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// Headers implements anisette.Provider: the forwarded subset of AllHeaders.
func (r *Remote) Headers() (map[string]string, error) {
	h, err := r.AllHeaders()
	if err != nil {
		var aerr *anisette.Error
		if errors.As(err, &aerr) {
			return nil, err
		}
		return nil, &anisette.Error{Msg: fmt.Sprintf("anisette (remote %s): %v", r.URL, err)}
	}
	return anisette.Filter(h)
}

// EnsureReady provisions without producing headers.
func (r *Remote) EnsureReady() error {
	_, err := r.AllHeaders()
	return err
}

// --- provisioning -------------------------------------------------------------------

// provisioning session messages (server -> client); the client answers with plain
// JSON objects. See Dadoum/anisette-v3-server.
type wsMessage struct {
	Result  string `json:"result"`
	CPIM    string `json:"cpim"`
	ADIPB   string `json:"adi_pb"`
	Message string `json:"message"`
}

func (r *Remote) provisionLocked() error {
	clientInfo, userAgent, err := r.clientInfoLocked()
	if err != nil {
		return err
	}
	r.Logf("provisioning this machine with Apple through %s (once)...", r.URL)
	apple := &provisioning.Session{
		HTTP: r.AppleHTTP, ClientInfo: clientInfo, UserAgent: userAgent,
		DeviceID: r.state.DeviceID(), LocalUserUUID: r.state.LocalUserUUID(), URLBag: r.URLBag,
	}
	wsURL := strings.Replace(strings.Replace(r.URL, "https://", "wss://", 1), "http://", "ws://", 1) + "/v3/provisioning_session"
	ws, err := dialWS(wsURL, r.Timeout)
	if err != nil {
		return r.serverError("provisioning_session", err)
	}
	defer ws.Close()
	send := func(v any) error {
		data, _ := json.Marshal(v)
		return ws.WriteText(string(data))
	}
	for step := 0; step < 8; step++ {
		text, err := ws.ReadText()
		if err != nil {
			return r.serverError("provisioning_session", err)
		}
		var msg wsMessage
		if err := json.Unmarshal([]byte(text), &msg); err != nil {
			return r.serverError("provisioning_session", fmt.Errorf("non-JSON message %q", logx.Body("text", []byte(text), 200)))
		}
		logx.Debugf("anisette", "provisioning: server says %s", msg.Result)
		switch msg.Result {
		case "GiveIdentifier":
			err = send(map[string]string{"identifier": base64.StdEncoding.EncodeToString(r.state.Identifier)})
		case "GiveStartProvisioningData":
			spim, serr := apple.Start()
			if serr != nil {
				return &anisette.Error{Msg: fmt.Sprintf("anisette provisioning: %v", serr)}
			}
			err = send(map[string]string{"spim": spim})
		case "GiveEndProvisioningData":
			if msg.CPIM == "" {
				return r.serverError("provisioning_session", errors.New("GiveEndProvisioningData without cpim"))
			}
			ptm, tk, _, ferr := apple.Finish(msg.CPIM)
			if ferr != nil {
				return &anisette.Error{Msg: fmt.Sprintf("anisette provisioning: %v", ferr)}
			}
			err = send(map[string]string{"ptm": ptm, "tk": tk})
		case "ProvisioningSuccess":
			blob, derr := base64.StdEncoding.DecodeString(msg.ADIPB)
			if derr != nil || len(blob) == 0 {
				return r.serverError("provisioning_session", errors.New("ProvisioningSuccess without a usable adi_pb"))
			}
			r.state.ADIPB, r.state.ProvisionedAt = blob, time.Now().Unix()
			r.state.ClientInfo, r.state.UserAgent = clientInfo, userAgent
			if err := r.saveStateLocked(); err != nil {
				return err
			}
			r.Logf("provisioning done")
			logx.Debugf("anisette", "provisioned device %s: adi_pb %d bytes", r.state.DeviceID(), len(blob))
			return nil
		case "Timeout":
			return r.serverError("provisioning_session", errors.New("server timed out waiting for this client"))
		case "InvalidIdentifier":
			return r.serverError("provisioning_session", errors.New("server rejected the identifier"))
		case "StartProvisioningError", "EndProvisioningError":
			return r.serverError("provisioning_session", fmt.Errorf("%s: %s", msg.Result, msg.Message))
		default:
			return r.serverError("provisioning_session", fmt.Errorf("unexpected message %q", msg.Result))
		}
		if err != nil {
			return r.serverError("provisioning_session", err)
		}
	}
	return r.serverError("provisioning_session", errors.New("too many steps without a result"))
}

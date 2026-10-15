package remote

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testClientInfo = "<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKit/1 (com.apple.iTunes/12.12.4.1)>"

// fakeV3 is an anisette-v3 server plus the two Apple provisioning endpoints.
type fakeV3 struct {
	t            *testing.T
	srv          *httptest.Server
	provisions   atomic.Int32
	headerCalls  atomic.Int32
	mu           sync.Mutex
	validBlobs   map[string]bool
	lastIdent    string
	appleHeaders []http.Header
}

func newFakeV3(t *testing.T) *fakeV3 {
	f := &fakeV3{t: t, validBlobs: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/v3/client_info", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"client_info": testClientInfo, "user_agent": "akd/1.0 CFNetwork/808.1.4"})
	})
	mux.HandleFunc("/v3/get_headers", func(w http.ResponseWriter, r *http.Request) {
		f.headerCalls.Add(1)
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		blob, _ := base64.StdEncoding.DecodeString(body["adi_pb"])
		f.mu.Lock()
		ok := f.validBlobs[string(blob)]
		f.mu.Unlock()
		if !ok {
			_ = json.NewEncoder(w).Encode(map[string]string{"result": "GetHeadersError", "message": "provision.adi.ADIException: ADI error: -45061 (request id: x)"})
			return
		}
		otp := "OTP-" + string(blob)
		if sim := body["sim"]; sim != "" {
			if body["device_id"] == "" || body["md_lu"] == "" {
				t.Errorf("resync without device_id/md_lu: %v", body)
			}
			otp = "SYNC-" + sim
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"result": "Headers", "X-Apple-I-MD": otp, "X-Apple-I-MD-M": "MID", "X-Apple-I-MD-RINFO": "17106176"})
	})
	mux.HandleFunc("/v3/provisioning_session", f.provisioningSession)
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.appleHeaders = append(f.appleHeaders, r.Header.Clone())
		f.mu.Unlock()
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>Response</key><dict><key>spim</key><string>U1BJTQ==</string></dict></dict></plist>`)
	})
	mux.HandleFunc("/finish", func(w http.ResponseWriter, r *http.Request) {
		raw := make([]byte, 4096)
		n, _ := r.Body.Read(raw)
		if !strings.Contains(string(raw[:n]), "<string>Q1BJTQ==</string>") {
			t.Errorf("finish body lacks the cpim: %s", raw[:n])
		}
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>Response</key><dict><key>ptm</key><string>UFRN</string><key>tk</key><string>VEs=</string><key>X-Apple-I-MD-RINFO</key><string>17106176</string></dict></dict></plist>`)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeV3) provisioningSession(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		f.t.Fatal("no hijacker")
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		f.t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
		acceptKey(r.Header.Get("Sec-WebSocket-Key")))
	ws := &wsConn{conn: conn, r: rw.Reader}
	send := func(v any) {
		data, _ := json.Marshal(v)
		if err := ws.WriteText(string(data)); err != nil {
			f.t.Error(err)
		}
	}
	recv := func() map[string]string {
		text, err := ws.ReadText()
		if err != nil {
			f.t.Error(err)
			return nil
		}
		var m map[string]string
		_ = json.Unmarshal([]byte(text), &m)
		return m
	}
	send(map[string]string{"result": "GiveIdentifier"})
	ident := recv()["identifier"]
	if raw, err := base64.StdEncoding.DecodeString(ident); err != nil || len(raw) != 16 {
		f.t.Errorf("bad identifier %q", ident)
	}
	send(map[string]string{"result": "GiveStartProvisioningData"})
	if spim := recv()["spim"]; spim != "U1BJTQ==" {
		f.t.Errorf("spim = %q", spim)
	}
	send(map[string]string{"result": "GiveEndProvisioningData", "cpim": "Q1BJTQ=="})
	end := recv()
	if end["ptm"] != "UFRN" || end["tk"] != "VEs=" {
		f.t.Errorf("end = %v", end)
	}
	n := f.provisions.Add(1)
	blob := fmt.Sprintf("blob%d", n)
	f.mu.Lock()
	f.validBlobs[blob] = true
	f.lastIdent = ident
	f.mu.Unlock()
	send(map[string]string{"result": "ProvisioningSuccess", "adi_pb": base64.StdEncoding.EncodeToString([]byte(blob))})
	// Drain the client's close frame.
	_, _ = ws.ReadText()
}

func newRemote(t *testing.T, f *fakeV3, statePath string) *Remote {
	r := New(f.srv.URL, statePath, nil)
	r.HTTP, r.AppleHTTP = f.srv.Client(), f.srv.Client()
	r.URLBag = map[string]string{"midStartProvisioning": f.srv.URL + "/start", "midFinishProvisioning": f.srv.URL + "/finish"}
	r.Timeout = 10 * time.Second
	return r
}

func TestProvisionAndHeaders(t *testing.T) {
	f := newFakeV3(t)
	statePath := filepath.Join(t.TempDir(), "remote.json")
	r := newRemote(t, f, statePath)

	info, ua, err := r.ClientInfo()
	if err != nil || info != testClientInfo || ua != "akd/1.0 CFNetwork/808.1.4" {
		t.Fatalf("ClientInfo = %q %q %v", info, ua, err)
	}
	h, err := r.Headers()
	if err != nil {
		t.Fatal(err)
	}
	if f.provisions.Load() != 1 {
		t.Fatalf("provisions = %d", f.provisions.Load())
	}
	st, _ := r.State()
	if h["X-Apple-I-MD"] != "OTP-blob1" || h["X-Apple-I-MD-M"] != "MID" || h["X-Mme-Device-Id"] != st.DeviceID() || h["X-Apple-I-MD-LU"] != st.LocalUserUUID() {
		t.Fatalf("headers = %v", h)
	}
	if _, ok := h["X-MMe-Client-Info"]; ok {
		t.Fatal("client info must not be forwarded as a header")
	}
	if len(st.DeviceID()) != 36 || len(st.LocalUserUUID()) != 64 {
		t.Fatalf("ids: %q %q", st.DeviceID(), st.LocalUserUUID())
	}
	// Apple saw the server's client info and this machine's ids during provisioning.
	ah := f.appleHeaders[0]
	if ah.Get("X-MMe-Client-Info") != testClientInfo || ah.Get("X-Mme-Device-Id") != st.DeviceID() || ah.Get("X-Apple-I-MD-LU") != st.LocalUserUUID() || ah.Get("Connection") != "close" {
		t.Fatalf("apple headers = %v", ah)
	}
	// Within the TTL the server is not asked again.
	if _, err := r.Headers(); err != nil || f.headerCalls.Load() != 1 {
		t.Fatalf("cached call: err=%v calls=%d", err, f.headerCalls.Load())
	}
	// A resync replaces the cached data without re-provisioning.
	if hs, err := r.Resync("U0lN"); err != nil || hs["X-Apple-I-MD"] != "SYNC-U0lN" {
		t.Fatalf("resync: %v %v", hs, err)
	}
	if h, _ := r.Headers(); h["X-Apple-I-MD"] != "SYNC-U0lN" || f.provisions.Load() != 1 {
		t.Fatalf("after resync: %v provisions=%d", h, f.provisions.Load())
	}
	// A new process loads the state and does not re-provision.
	r2 := newRemote(t, f, statePath)
	if _, err := r2.Headers(); err != nil || f.provisions.Load() != 1 {
		t.Fatalf("reload: err=%v provisions=%d", err, f.provisions.Load())
	}
	// Apple stops accepting the blob: the server says -45061 and ap provisions a new identity.
	f.mu.Lock()
	f.validBlobs = map[string]bool{}
	f.mu.Unlock()
	r3 := newRemote(t, f, statePath)
	h3, err := r3.Headers()
	if err != nil {
		t.Fatal(err)
	}
	if f.provisions.Load() != 2 || h3["X-Apple-I-MD"] != "OTP-blob2" || h3["X-Mme-Device-Id"] == st.DeviceID() {
		t.Fatalf("reprovision: provisions=%d headers=%v", f.provisions.Load(), h3)
	}
	// Switching servers resets the identity.
	f2 := newFakeV3(t)
	r4 := newRemote(t, f2, statePath)
	if _, err := r4.Headers(); err != nil || f2.provisions.Load() != 1 {
		t.Fatalf("server switch: err=%v provisions=%d", err, f2.provisions.Load())
	}
	st4, _ := r4.State()
	if st4.Server != f2.srv.URL || st4.DeviceID() == st.DeviceID() {
		t.Fatalf("state after switch: %+v", st4)
	}
}

func TestProvisioningServerError(t *testing.T) {
	f := newFakeV3(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/v3/client_info", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"client_info": testClientInfo, "user_agent": "x"})
	})
	mux.HandleFunc("/v3/provisioning_session", func(w http.ResponseWriter, r *http.Request) {
		conn, rw, _ := w.(http.Hijacker).Hijack()
		defer conn.Close()
		fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", acceptKey(r.Header.Get("Sec-WebSocket-Key")))
		ws := &wsConn{conn: conn, r: rw.Reader}
		_ = ws.WriteText(`{"result":"GiveIdentifier"}`)
		_, _ = ws.ReadText()
		_ = ws.WriteText(`{"result":"StartProvisioningError","message":"ADI error -45070"}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	r := newRemote(t, f, filepath.Join(t.TempDir(), "s.json"))
	r.URL = srv.URL
	_, err := r.Headers()
	if err == nil || !strings.Contains(err.Error(), "StartProvisioningError") || !strings.Contains(err.Error(), "-45070") {
		t.Fatalf("err = %v", err)
	}
}

func TestWebsocketFraming(t *testing.T) {
	a, b := net.Pipe()
	ca := &wsConn{conn: a, r: bufio.NewReader(a)}
	cb := &wsConn{conn: b, r: bufio.NewReader(b)}
	big := strings.Repeat("x", 70000)
	go func() {
		_ = ca.WriteText("hello")
		_ = ca.writeFrame(opPing, []byte("p"))
		// A fragmented message: text without FIN, then a continuation with FIN.
		_, _ = a.Write(maskedFrame(0x00|opText, []byte("frag")))
		_ = ca.writeFrame(opContinuation, []byte("ment"))
		_ = ca.WriteText(big)
		_ = ca.writeFrame(opClose, []byte{0x03, 0xe8, 'b', 'y', 'e'})
	}()
	if s, err := cb.ReadText(); err != nil || s != "hello" {
		t.Fatalf("got %q %v", s, err)
	}
	// The pong answered to the ping arrives at a; read it so the pipe does not block.
	go func() { _, _, _, _ = ca.readFrame() }()
	if s, err := cb.ReadText(); err != nil || s != "fragment" {
		t.Fatalf("got %q %v", s, err)
	}
	if s, err := cb.ReadText(); err != nil || s != big {
		t.Fatalf("big: len %d %v", len(s), err)
	}
	go func() { _, _, _, _ = ca.readFrame() }() // the close echo
	if _, err := cb.ReadText(); err == nil || !strings.Contains(err.Error(), "1000 bye") {
		t.Fatalf("close: %v", err)
	}
}

// maskedFrame builds a masked frame with an explicit first byte (to clear FIN).
func maskedFrame(first byte, payload []byte) []byte {
	out := []byte{first, 0x80 | byte(len(payload)), 1, 2, 3, 4}
	for i, c := range payload {
		out = append(out, c^out[2+i%4])
	}
	return out
}

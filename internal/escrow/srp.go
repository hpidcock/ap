// Package escrow turns the device passcode into the escrow bottle entropy (escrowproxy
// SRP-6a) and decrypts the bottle into the recovered old peer identity.
//
// IRREVERSIBLE: escrowproxy enforces a hard 10-attempt limit; the HSM cluster destroys
// the escrow record on the 10th failed attempt. TryRecoverEscrow refuses to run without
// confirmIrreversible=true, which the CLI passes only after a typed confirmation.
// ListRecords (GETRECORDS) is non-destructive and spends no attempt.
package escrow

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/hpidcock/ap/internal/anisette"
	"github.com/hpidcock/ap/internal/device"
	"github.com/hpidcock/ap/internal/httpx"
	"github.com/hpidcock/ap/internal/logx"
	"github.com/hpidcock/ap/internal/plistx"
	"github.com/hpidcock/ap/internal/srp"
)

var (
	// N and G are the RFC 5054 2048-bit group.
	N    = srp.N
	G    = srp.G
	nLen = srp.NLen
)

// GateError is raised when a live escrowproxy call fails or is attempted without consent.
type GateError struct{ Msg string }

func (e *GateError) Error() string { return e.Msg }

func gateErrorf(format string, a ...any) error { return &GateError{Msg: fmt.Sprintf(format, a...)} }

func h(parts ...[]byte) []byte {
	d := sha256.New()
	for _, p := range parts {
		d.Write(p)
	}
	return d.Sum(nil)
}

func pad(x *big.Int) []byte { return srp.Pad(x) }

// trim is the minimal big-endian encoding (at least one byte).
func trim(x *big.Int) []byte {
	if x.Sign() == 0 {
		return []byte{0}
	}
	return x.Bytes()
}

// UnpackMessage splits a KeyVault message: len(4) | header | (n+1) BE offsets | body,
// where each body section is len(4)||data.
func UnpackMessage(bin []byte, headerLen, sectionCount int) ([]byte, [][]byte, error) {
	if len(bin) < 4+headerLen+(sectionCount+1)*4 {
		return nil, nil, errors.New("escrow: message too short")
	}
	header := bin[4 : headerLen+4]
	totalHeader := headerLen + 4 + (sectionCount+1)*4
	offsets := bin[headerLen+4 : headerLen+4+sectionCount*4]
	sections := make([][]byte, 0, sectionCount)
	for i := 0; i < sectionCount; i++ {
		off := int(binary.BigEndian.Uint32(offsets[i*4:]))
		start := totalHeader + off
		if start+4 > len(bin) {
			return nil, nil, errors.New("escrow: section offset out of range")
		}
		size := int(binary.BigEndian.Uint32(bin[start:]))
		if start+4+size > len(bin) {
			return nil, nil, errors.New("escrow: section size out of range")
		}
		sections = append(sections, bin[start+4:start+4+size])
	}
	return header, sections, nil
}

// Message builds a KeyVault message.
type Message struct {
	Header   []byte
	sections [][]byte
}

// Section appends a len-prefixed section.
func (m *Message) Section(data []byte) {
	buf := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(buf, uint32(len(data)))
	copy(buf[4:], data)
	m.sections = append(m.sections, buf)
}

// SectionSized appends a section padded to a fixed slot size.
func (m *Message) SectionSized(data []byte, size int) error {
	total := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(total, uint32(len(data)))
	copy(total[4:], data)
	if len(total) > size {
		return fmt.Errorf("escrow: section size %d < actual %d", size, len(total))
	}
	m.sections = append(m.sections, append(total, make([]byte, size-len(total))...))
	return nil
}

// Pack serialises the message.
func (m *Message) Pack() []byte {
	var body []byte
	var idx []uint32
	for _, s := range m.sections {
		idx = append(idx, uint32(len(body)))
		body = append(body, s...)
	}
	idx = append(idx, uint32(len(body)))
	out := make([]byte, 4)
	out = append(out, m.Header...)
	for _, o := range idx {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], o)
		out = append(out, b[:]...)
	}
	out = append(out, body...)
	binary.BigEndian.PutUint32(out, uint32(len(out)))
	return out
}

// SRPClient is the escrowproxy SRP-6a client (trimmed-A/B convention of the vendored
// rustcrypto-srp fork: A and B are trimmed in u, M1, M2; only g is padded).
type SRPClient struct {
	a *big.Int
	A *big.Int
}

// NewSRPClient creates a client from the ephemeral secret bytes.
func NewSRPClient(aBytes []byte) *SRPClient {
	a := new(big.Int).SetBytes(aBytes)
	return &SRPClient{a: a, A: new(big.Int).Exp(G, a, N)}
}

// PublicA returns A trimmed.
func (c *SRPClient) PublicA() []byte { return trim(c.A) }

// Process returns (K, M1) for username (the dsid), the passcode, salt and server B.
func (c *SRPClient) Process(username, password, salt, bPub []byte) ([]byte, []byte) {
	B := new(big.Int).SetBytes(bPub)
	aPub := trim(c.A)
	bNorm := trim(B)
	k := new(big.Int).SetBytes(h(pad(N), pad(G)))
	x := new(big.Int).SetBytes(h(salt, h(append(append(append([]byte{}, username...), ':'), password...))))
	u := new(big.Int).SetBytes(h(aPub, bNorm))
	// S = (B - k*g^x)^(a + u*x) mod N
	kgx := new(big.Int).Mul(k, new(big.Int).Exp(G, x, N))
	kgx.Mod(kgx, N)
	base := new(big.Int).Sub(B, kgx)
	base.Mod(base, N)
	exp := new(big.Int).Add(c.a, new(big.Int).Mul(u, x))
	S := new(big.Int).Exp(base, exp, N)
	K := h(trim(S))
	hN, hg := h(pad(N)), h(pad(G))
	hx := make([]byte, len(hN))
	for i := range hN {
		hx[i] = hN[i] ^ hg[i]
	}
	M1 := h(hx, h(username), salt, aPub, bNorm, K)
	return K, M1
}

// ServerProof is the expected M2 = H(A || M1 || K).
func ServerProof(aPub, M1, K []byte) []byte { return h(aPub, M1, K) }

func aesCBCDecrypt(key, iv, ct []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) < 16 || len(ct) == 0 || len(ct)%16 != 0 {
		return nil, errors.New("escrow: bad CBC input")
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv[:16]).CryptBlocks(out, ct)
	// PKCS7 unpad (OpenSSL default); tolerate missing padding like the reference.
	if p := int(out[len(out)-1]); p >= 1 && p <= 16 && p <= len(out) {
		valid := true
		for _, b := range out[len(out)-p:] {
			if int(b) != p {
				valid = false
				break
			}
		}
		if valid {
			out = out[:len(out)-p]
		}
	}
	return out, nil
}

// Recovery drives the escrowproxy commands. Auth is HTTP Basic(apple-id email : fresh GSA PET).
type Recovery struct {
	Host     string
	Email    string
	PET      string
	Anisette anisette.Provider
	HTTP     *http.Client
	// Invoke lets tests intercept the POST; nil uses the live transport.
	Invoke func(command string, request map[string]any) (map[string]any, error)
}

// UserAction is the verbatim label escrowproxy expects.
const UserAction = "com.apple.sbd: escrow recovery"

// CommandVariant maps the URL slug to the SCREAMING_SNAKE_CASE body command.
var CommandVariant = map[string]string{
	"srp_init": "SRP_INIT", "recover": "RECOVER", "get_records": "GETRECORDS",
	"get_club_cert": "GETCLUB", "enroll": "ENROLL", "delete": "DELETE",
}

const (
	escrowUserAgent     = "com.apple.sbd/638.100.48 com.apple.iCloudHelper/282"
	escrowMmeClientInfo = device.Description + " <com.apple.AuthKit/1 (com.apple.sbd/638.100.48)>"
)

// NewRecovery returns a Recovery for the KeychainSync escrow proxy host.
func NewRecovery(host, email, pet string, anis anisette.Provider) *Recovery {
	return &Recovery{Host: strings.TrimRight(host, "/"), Email: email, PET: pet, Anisette: anis,
		HTTP: httpx.Client(30 * time.Second)}
}

// Headers builds the escrowproxy request headers (anisette plus a fixed
// X-Mme-Client-Info that overwrites anisette's).
func (r *Recovery) Headers() (map[string]string, error) {
	hdr := map[string]string{
		"User-Agent":            escrowUserAgent,
		"Accept":                "*/*",
		"Accept-Language":       "en-US,en;q=0.9",
		"X-Apple-I-Locale":      "en_US",
		"x-apple-i-device-type": "1",
		"Content-Type":          "application/x-apple-plst",
	}
	if r.Anisette != nil {
		ah, err := r.Anisette.Headers()
		if err != nil {
			return nil, err
		}
		for k, v := range ah {
			hdr[k] = v
		}
	}
	hdr["X-Mme-Client-Info"] = escrowMmeClientInfo
	return hdr, nil
}

func (r *Recovery) invoke(command string, request map[string]any) (map[string]any, error) {
	if r.Invoke != nil {
		return r.Invoke(command, request)
	}
	body, err := plistx.EncodeXML(request)
	if err != nil {
		return nil, err
	}
	hdr, err := r.Headers()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, r.Host+"/escrowproxy/api/"+command, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	req.SetBasicAuth(r.Email, r.PET)
	resp, err := r.HTTP.Do(req)
	if err != nil {
		return nil, gateErrorf("escrowproxy/%s: %v", command, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	data, perr := plistx.Decode(raw)
	logx.Debugf("escrow", "%s: HTTP %d, %d bytes, keys=%v", command, resp.StatusCode, len(raw), logx.Keys(data))
	if resp.StatusCode/100 != 2 {
		return nil, gateErrorf("escrowproxy/%s HTTP %d: %v", command, resp.StatusCode, data)
	}
	if perr != nil {
		return nil, gateErrorf("escrowproxy/%s: unreadable response: %v", command, perr)
	}
	return data, nil
}

// Request builds the plist body for a command (URL slug in, SCREAMING_SNAKE body command out).
func (r *Recovery) Request(commandURL, label, txn string, extra map[string]any) map[string]any {
	cmd, ok := CommandVariant[commandURL]
	if !ok {
		cmd = commandURL
	}
	req := map[string]any{
		"command": cmd, "label": label, "transactionUUID": txn,
		"userActionLabel": UserAction, "version": 1,
	}
	for k, v := range extra {
		if v != nil {
			req[k] = v
		}
	}
	return req
}

// RecordMeta is one GETRECORDS entry.
type RecordMeta struct {
	Label string
	Meta  map[string]any
}

// ListRecords lists the account's escrow records with the metadata that identifies each
// backed-up device. NON-DESTRUCTIVE: spends no escrow attempt and needs no passcode.
func (r *Recovery) ListRecords() ([]RecordMeta, error) {
	txn := device.NewUUID()
	resp, err := r.invoke("get_records", r.Request("get_records", "com.apple.securebackup.record", txn, nil))
	if err != nil {
		return nil, err
	}
	entries := plistx.List(resp["metadataList"])
	if entries == nil {
		entries = plistx.List(resp["metadata_list"])
	}
	var out []RecordMeta
	for _, e := range entries {
		entry := plistx.Dict(e)
		meta := map[string]any{}
		if b64 := plistx.Str(entry["metadata"]); b64 != "" {
			if raw, err := base64.StdEncoding.DecodeString(b64); err == nil {
				if m, err := plistx.Decode(raw); err == nil {
					meta = m
				}
			}
		}
		out = append(out, RecordMeta{Label: plistx.Str(entry["label"]), Meta: meta})
	}
	return out, nil
}

// TryRecoverEscrow runs the full SRP recovery and returns the EscrowBottle's
// BottledPeerEntropy. IRREVERSIBLE (consumes 1 of 10 attempts).
func (r *Recovery) TryRecoverEscrow(label string, passcode []byte, confirmIrreversible bool) ([]byte, error) {
	if !confirmIrreversible {
		return nil, gateErrorf("REFUSED: TryRecoverEscrow consumes one of 10 irreversible escrow attempts " +
			"(the 10th failed passcode destroys the record forever). Pass confirmIrreversible=true " +
			"only after the user has explicitly confirmed.")
	}
	txn := device.NewUUID()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	client := NewSRPClient(secret)

	// 1) srp_init: send A, get salt + B + dsid (+ optional clubTypeID)
	init, err := r.invoke("srp_init", r.Request("srp_init", label, txn,
		map[string]any{"blob": base64.StdEncoding.EncodeToString(client.PublicA())}))
	if err != nil {
		return nil, err
	}
	dsid := plistx.Str(init["dsid"])
	clubTypeID := plistx.Int(init["clubTypeID"])
	logx.Debugf("escrow", "srp_init ok: label=%s dsid=%s clubTypeID=%d", label, dsid, clubTypeID)
	respBlob, err := base64.StdEncoding.DecodeString(plistx.Str(init["respBlob"]))
	if err != nil {
		return nil, gateErrorf("srp_init: bad respBlob")
	}
	header, sections, err := UnpackMessage(respBlob, 24, 3)
	if err != nil {
		return nil, gateErrorf("srp_init: %v", err)
	}
	idSection, salt, bPub := sections[0], sections[1], sections[2]

	// 2) SRP-6a: derive K + proof M1 (username = the dsid escrowproxy returned)
	K, M1 := client.Process([]byte(dsid), passcode, salt, bPub)

	// 3) recover: send header(unk1=165, ver) + id + M1
	ver := uint32(0)
	if clubTypeID == 1 {
		ver = 2
	}
	hdr := append([]byte{}, header...)
	binary.BigEndian.PutUint32(hdr[0:4], 165)
	binary.BigEndian.PutUint32(hdr[4:8], ver)
	payload := &Message{Header: hdr}
	if err := payload.SectionSized(idSection, 20); err != nil {
		return nil, err
	}
	payload.Section(M1)
	rec, err := r.invoke("recover", r.Request("recover", label, txn,
		map[string]any{"blob": base64.StdEncoding.EncodeToString(payload.Pack())}))
	if err != nil {
		return nil, err
	}

	// 4) verify server proof + decrypt with the SRP session key K
	recBlob, err := base64.StdEncoding.DecodeString(plistx.Str(rec["respBlob"]))
	if err != nil {
		return nil, gateErrorf("recover: bad respBlob")
	}
	hdrLen := 24
	if clubTypeID == 1 {
		hdrLen = 40
	}
	rh, payloads, err := UnpackMessage(recBlob, hdrLen, 3)
	if err != nil {
		return nil, gateErrorf("recover: %v", err)
	}
	if subtle.ConstantTimeCompare(ServerProof(client.PublicA(), M1, K), payloads[0]) != 1 {
		return nil, gateErrorf("escrowproxy server proof (M2) mismatch - aborting")
	}
	version := binary.BigEndian.Uint32(rh[4:8])
	logx.Debugf("escrow", "recover ok: server proof verified, record version %d", version)
	var inner []byte
	switch version {
	case 0:
		inner, err = aesCBCDecrypt(K, payloads[1], payloads[2])
	case 2:
		var block cipher.Block
		block, err = aes.NewCipher(K)
		if err == nil {
			var gcm cipher.AEAD
			gcm, err = cipher.NewGCMWithNonceSize(block, len(payloads[1]))
			if err == nil {
				inner, err = gcm.Open(nil, payloads[1], payloads[2], nil)
			}
		}
	default:
		return nil, gateErrorf("unsupported escrow record version %d", version)
	}
	if err != nil {
		return nil, gateErrorf("recover: could not decrypt the record: %v", err)
	}

	// 5) inner blob -> PBKDF2(passcode) -> AES-128-CBC -> EscrowBottle plist
	ih, ipayloads, err := UnpackMessage(inner, 16, 6)
	if err != nil {
		return nil, gateErrorf("recover: inner: %v", err)
	}
	rounds := int(binary.BigEndian.Uint32(ih[8:12]))
	salt2 := ipayloads[1]
	logx.Debugf("escrow", "inner record: pbkdf2 rounds=%d", rounds)
	derived, err := pbkdf2.Key(sha256.New, string(passcode), salt2, rounds, 16)
	if err != nil {
		return nil, err
	}
	bottlePlist, err := aesCBCDecrypt(derived, salt2, ipayloads[3])
	if err != nil {
		return nil, gateErrorf("recover: bottle decrypt: %v", err)
	}
	bottle, err := plistx.Decode(bottlePlist)
	if err != nil {
		return nil, gateErrorf("recover: bottle is not a plist (wrong passcode?)")
	}
	entropy := plistx.Bytes(bottle["BottledPeerEntropy"])
	if entropy == nil {
		return nil, gateErrorf("recover: bottle has no BottledPeerEntropy (keys %v)", logx.Keys(bottle))
	}
	logx.Debugf("escrow", "bottle decrypted: keys=%v entropy=%d bytes", logx.Keys(bottle), len(entropy))
	return entropy, nil
}

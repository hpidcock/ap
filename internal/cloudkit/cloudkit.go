// Package cloudkit is the CloudKit transport the keychain rides on: CKCode function
// invokes (Cuttlefish RPCs) and CKKS record fetches, each a gzipped, length-delimited
// RequestOperation authed with the cloudKitToken. See RESEARCH.md stage 2.
package cloudkit

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hpidcock/ap/internal/anisette"
	"github.com/hpidcock/ap/internal/device"
	"github.com/hpidcock/ap/internal/httpx"
	"github.com/hpidcock/ap/internal/proto"
)

const (
	CKCodeInvokeURL     = "https://gateway.icloud.com/ckcoderouter/api/client/code/invoke"
	CKDatabaseSyncURL   = "https://gateway.icloud.com/ckdatabase/api/client/record/sync"
	CKAppInitURL        = "https://gateway.icloud.com/setup/setup/ck/v1/ckAppInit"
	CKMmeClientInfo     = "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.cloudkit.CloudKitDaemon/1970 (com.apple.cloudd/1970)>"
	CuttlefishContainer = "com.apple.security.keychain"
	CuttlefishBundle    = "com.apple.security.cuttlefish" // CKCode (Cuttlefish) requests
	SecuritydBundle     = "com.apple.securityd"           // CKKS record fetches
	CuttlefishService   = "Cuttlefish"

	envProduction        = 1
	dbPrivate            = 1
	isolationZone        = 1
	identifierTypeDevice = 2
	opTypeFunctionInvoke = 1101
	fieldFunctionInvoke  = 1101
	resultSuccess        = 1
)

// Error is a CloudKit transport/operation failure.
type Error struct {
	Msg         string
	Code        uint64
	Description string
	HTTPStatus  int
}

func (e *Error) Error() string { return e.Msg }

// MaybeGunzip decompresses a body that starts with the gzip magic.
func MaybeGunzip(payload []byte) ([]byte, error) {
	if len(payload) >= 2 && payload[0] == 0x1f && payload[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		return io.ReadAll(zr)
	}
	return payload, nil
}

// Delimit is CloudKit's `delimited=true` framing: a uleb128 length prefix + the message.
func Delimit(message []byte) []byte {
	return append(proto.EncodeVarint(uint64(len(message))), message...)
}

// Undelimit splits a stream of length-delimited messages.
func Undelimit(buf []byte) ([][]byte, error) {
	var out [][]byte
	for pos := 0; pos < len(buf); {
		ln, n, err := proto.ReadVarint(buf[pos:])
		if err != nil {
			return nil, err
		}
		pos += n
		if uint64(len(buf)-pos) < ln {
			return nil, proto.ErrTruncated
		}
		out = append(out, buf[pos:pos+int(ln)])
		pos += int(ln)
	}
	return out, nil
}

// Identifier builds a CloudKit Identifier{ name(1), type(2) }.
func Identifier(name string, typ uint64) []byte {
	return new(proto.Writer).String(1, name).Uint64(2, typ).Finish()
}

// DeviceConfig is what RequestOperation.Header wants to know about the device.
type DeviceConfig struct {
	DeviceUUID      string // deviceIdentifier.name + deviceHardwareID
	Serial          string
	Name            string
	SoftwareVersion string
	HardwareVersion string
}

func (d DeviceConfig) withDefaults() DeviceConfig {
	if d.Name == "" {
		d.Name = "Mac"
	}
	if d.SoftwareVersion == "" {
		d.SoftwareVersion = "Mac OS X;13.4.1;22F8"
	}
	if d.HardwareVersion == "" {
		d.HardwareVersion = "MacBookPro18,3"
	}
	if d.Serial == "" {
		d.Serial = "0000000000"
	}
	return d
}

// BuildHeader builds RequestOperation.Header. userToken stays empty - the cloudKitToken
// goes in the x-cloudkit-authtoken HTTP header, not this body field.
func BuildHeader(cfg DeviceConfig, container, bundle string) []byte {
	cfg = cfg.withDefaults()
	sum := sha1.Sum([]byte(cfg.DeviceUUID))
	return new(proto.Writer).
		String(2, container).
		String(3, bundle).
		Message(7, Identifier(cfg.DeviceUUID, identifierTypeDevice)).
		String(8, cfg.SoftwareVersion).
		String(9, cfg.HardwareVersion).
		String(10, "com.apple.cloudkit.CloudKitDaemon").
		String(11, "1970").
		String(18, "5.0").                      // mmcsProtocolVersion
		Uint64(19, envProduction).              // applicationContainerEnvironment
		String(21, cfg.Name).                   // deviceAssignedName
		String(22, cfg.DeviceUUID).             // deviceHardwareID
		Uint64(23, dbPrivate).                  // targetDatabase
		Uint64(25, isolationZone).              // isolationLevel
		Uint64(29, 0).                          // unk1
		String(32, hex.EncodeToString(sum[:])). // unk2
		String(33, cfg.Serial).                 // deviceSerial
		Uint64(34, 0).                          // unk3
		Uint64(35, 1).                          // unk4
		Finish()
}

// BuildRequestOperation wraps an op-specific request in a RequestOperation. The request
// rides in its own high field number (functionInvokeRequest=1101, retrieveChangesRequest=213).
func BuildRequestOperation(header []byte, opType uint64, requestField int, request []byte) []byte {
	operation := new(proto.Writer).String(1, device.NewUUID()).Uint64(2, opType).Bool(4, true).Finish()
	return new(proto.Writer).Message(1, header).Message(2, operation).Message(requestField, request).Finish()
}

func operationID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return strings.ToUpper(hex.EncodeToString(b[:]))
}

// containerHeaders is the shared header block for ckAppInit and every CKCode/record op.
func containerHeaders(bundle, container, mmeClientInfo string) http.Header {
	if mmeClientInfo == "" {
		mmeClientInfo = CKMmeClientInfo
	}
	h := http.Header{}
	set := func(k, v string) { h.Set(k, v) }
	set("accept", "application/x-protobuf")
	set("accept-encoding", "gzip")
	set("accept-language", "en-US,en;q=0.9")
	set("cache-control", "no-transform")
	set("content-encoding", "gzip")
	set("content-type", `application/x-protobuf; desc="https://gateway.icloud.com:443/static/protobuf/CloudDB/CloudDBClient.desc"; messageType=RequestOperation; delimited=true`)
	set("user-agent", "CloudKit/1970 (19H384)")
	set("x-apple-c2-metric-triggers", "0")
	set("x-apple-operation-group-id", operationID())
	set("x-apple-operation-id", operationID())
	set("x-apple-request-uuid", device.NewUUID())
	set("x-cloudkit-bundleid", bundle)
	set("x-cloudkit-containerid", container)
	set("x-cloudkit-databasescope", "Private")
	set("x-cloudkit-duetpreclearedmode", "None")
	set("x-cloudkit-environment", "Production")
	set("x-mme-client-info", mmeClientInfo)
	return h
}

// CKAppInit returns the per-container cloudKitUserId CloudKit wants in x-cloudkit-userid
// (it is NOT the dsid). Authed with Basic(dsid, mmeAuthToken).
func CKAppInit(container, bundle, dsid, mmeToken string, anis anisette.Provider) (string, error) {
	h := containerHeaders(bundle, container, "")
	h.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(dsid+":"+mmeToken)))
	ah, err := anis.Headers()
	if err != nil {
		return "", err
	}
	for k, v := range ah {
		h.Set(k, v)
	}
	req, err := http.NewRequest(http.MethodPost, CKAppInitURL+"?container="+container, bytes.NewReader(nil))
	if err != nil {
		return "", err
	}
	req.Header = h
	resp, err := httpx.Client(30 * time.Second).Do(req)
	if err != nil {
		return "", &Error{Msg: fmt.Sprintf("network error talking to ckAppInit: %v", err)}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusUnauthorized {
		return "", &Error{Msg: "ckAppInit rejected the mmeAuthToken (HTTP 401) - re-run `ap login` to refresh it", HTTPStatus: 401}
	}
	raw, _ = MaybeGunzip(raw)
	var out struct {
		CloudKitUserID string `json:"cloudKitUserId"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.CloudKitUserID == "" {
		return "", &Error{Msg: fmt.Sprintf("ckAppInit returned HTTP %d without a cloudKitUserId", resp.StatusCode), HTTPStatus: resp.StatusCode}
	}
	return out.CloudKitUserID, nil
}

// Result is a parsed ResponseOperation.
type Result struct {
	Code             uint64
	ErrorDescription string
	Fields           proto.Fields
}

// OK reports success.
func (r *Result) OK() bool { return r.Code == resultSuccess }

// SerializedResult is functionInvokeResponse(1101).serializedResult(1).
func (r *Result) SerializedResult() []byte {
	if !r.Fields.Has(fieldFunctionInvoke) {
		return nil
	}
	return proto.MustDecode(r.Fields.Bytes(fieldFunctionInvoke)).Bytes(1)
}

// Field returns the raw bytes of an operation-specific response field.
func (r *Result) Field(num int) []byte { return r.Fields.Bytes(num) }

// ParseResponseOperation decodes the first ResponseOperation.
func ParseResponseOperation(raw []byte) (*Result, error) {
	f, err := proto.Decode(raw)
	if err != nil {
		return nil, err
	}
	res := &Result{Code: resultSuccess, Fields: f}
	if f.Has(3) {
		rf := proto.MustDecode(f.Bytes(3))
		if rf.Has(1) {
			res.Code = rf.Uint64(1)
		}
		if rf.Has(2) {
			res.ErrorDescription = proto.MustDecode(rf.Bytes(2)).String(4)
		}
	}
	return res, nil
}

// Transport performs CloudKit operations for the keychain container. Every call makes a
// live HTTPS request.
type Transport struct {
	CKToken       string
	UserID        string
	Device        DeviceConfig
	Anisette      anisette.Provider
	Container     string
	MmeClientInfo string
	HTTP          *http.Client
}

// NewTransport returns a transport for the Cuttlefish container.
func NewTransport(ckToken, userID string, dev DeviceConfig, anis anisette.Provider) *Transport {
	return &Transport{CKToken: ckToken, UserID: userID, Device: dev, Anisette: anis,
		Container: CuttlefishContainer, HTTP: httpx.Client(30 * time.Second)}
}

func (t *Transport) headers(bundle, routingHint string) (http.Header, error) {
	h := containerHeaders(bundle, t.Container, t.MmeClientInfo)
	h.Set("x-cloudkit-userid", t.UserID)
	h.Set("x-cloudkit-authtoken", t.CKToken)
	if routingHint != "" {
		h.Set("x-cloudkit-functionroutinghint", routingHint)
	}
	ah, err := t.Anisette.Headers()
	if err != nil {
		return nil, err
	}
	for k, v := range ah {
		h.Set(k, v)
	}
	return h, nil
}

func (t *Transport) perform(url string, opType uint64, requestField int, request []byte, bundle, routingHint string) (*Result, error) {
	header := BuildHeader(t.Device, t.Container, bundle)
	req := BuildRequestOperation(header, opType, requestField, request)
	var body bytes.Buffer
	zw := gzip.NewWriter(&body)
	_, _ = zw.Write(Delimit(req))
	_ = zw.Close()
	h, err := t.headers(bundle, routingHint)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequest(http.MethodPost, url, &body)
	if err != nil {
		return nil, err
	}
	httpReq.Header = h
	resp, err := t.HTTP.Do(httpReq)
	if err != nil {
		return nil, &Error{Msg: fmt.Sprintf("network error talking to %s: %v", url, err)}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	raw, err = MaybeGunzip(raw)
	if err != nil {
		return nil, &Error{Msg: fmt.Sprintf("bad gzip body from %s: %v", url, err), HTTPStatus: resp.StatusCode}
	}
	messages, err := Undelimit(raw)
	if err != nil || len(messages) == 0 {
		return nil, &Error{Msg: fmt.Sprintf("CloudKit returned HTTP %d with no parseable response", resp.StatusCode), HTTPStatus: resp.StatusCode}
	}
	result, err := ParseResponseOperation(messages[0])
	if err != nil {
		return nil, &Error{Msg: fmt.Sprintf("bad ResponseOperation: %v", err), HTTPStatus: resp.StatusCode}
	}
	if !result.OK() {
		desc := result.ErrorDescription
		if desc == "" {
			desc = "unknown"
		}
		return nil, &Error{Msg: "CloudKit operation failed: " + desc, Code: result.Code,
			Description: result.ErrorDescription, HTTPStatus: resp.StatusCode}
	}
	return result, nil
}

// Invoke performs a CKCode function invoke (Cuttlefish RPC).
func (t *Transport) Invoke(op string, parameters []byte) (*Result, error) {
	fir := proto.EncodeFunctionInvokeRequest(CuttlefishService, op, parameters)
	return t.perform(CKCodeInvokeURL, opTypeFunctionInvoke, fieldFunctionInvoke, fir,
		CuttlefishBundle, CuttlefishService+"/"+op)
}

// FetchRecords performs a RecordRetrieveChanges op -> retrieveChangesResponse(213) bytes.
func (t *Transport) FetchRecords(zoneRequest []byte) ([]byte, error) {
	result, err := t.perform(CKDatabaseSyncURL, OpTypeRecordRetrieveChanges, FieldRetrieveChanges, zoneRequest, SecuritydBundle, "")
	if err != nil {
		return nil, err
	}
	return result.Field(FieldRetrieveChanges), nil
}

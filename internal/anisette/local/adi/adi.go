// Package adi wraps Apple's CoreADI (Apple Device Identification) as exposed by the
// Apple Music for Android libstoreservicescore.so, loaded with the androidlib loader.
// The exported names are obfuscated but stable; the table below is from Dadoum/Provision.
package adi

/*
#include <stdint.h>
#include <stdlib.h>

typedef int (*adi_load_library_t)(const char*);
typedef int (*adi_set_android_id_t)(const char*, unsigned int);
typedef int (*adi_set_provisioning_path_t)(const char*);
typedef int (*adi_provisioning_erase_t)(uint64_t);
typedef int (*adi_synchronize_t)(uint64_t, uint8_t*, unsigned int, uint8_t**, unsigned int*, uint8_t**, unsigned int*);
typedef int (*adi_provisioning_destroy_t)(unsigned int);
typedef int (*adi_provisioning_end_t)(unsigned int, uint8_t*, unsigned int, uint8_t*, unsigned int);
typedef int (*adi_provisioning_start_t)(uint64_t, uint8_t*, unsigned int, uint8_t**, unsigned int*, unsigned int*);
typedef int (*adi_get_login_code_t)(uint64_t);
typedef int (*adi_dispose_t)(void*);
typedef int (*adi_otp_request_t)(uint64_t, uint8_t**, unsigned int*, uint8_t**, unsigned int*);

static int call_load_library(void* f, const char* p) { return ((adi_load_library_t)f)(p); }
static int call_set_android_id(void* f, const char* id, unsigned int n) { return ((adi_set_android_id_t)f)(id, n); }
static int call_set_provisioning_path(void* f, const char* p) { return ((adi_set_provisioning_path_t)f)(p); }
static int call_provisioning_erase(void* f, uint64_t ds) { return ((adi_provisioning_erase_t)f)(ds); }
static int call_synchronize(void* f, uint64_t ds, uint8_t* sim, unsigned int simlen, uint8_t** mid, unsigned int* midlen, uint8_t** srm, unsigned int* srmlen) {
	return ((adi_synchronize_t)f)(ds, sim, simlen, mid, midlen, srm, srmlen);
}
static int call_provisioning_destroy(void* f, unsigned int s) { return ((adi_provisioning_destroy_t)f)(s); }
static int call_provisioning_end(void* f, unsigned int s, uint8_t* ptm, unsigned int ptmlen, uint8_t* tk, unsigned int tklen) {
	return ((adi_provisioning_end_t)f)(s, ptm, ptmlen, tk, tklen);
}
static int call_provisioning_start(void* f, uint64_t ds, uint8_t* spim, unsigned int spimlen, uint8_t** cpim, unsigned int* cpimlen, unsigned int* session) {
	return ((adi_provisioning_start_t)f)(ds, spim, spimlen, cpim, cpimlen, session);
}
static int call_get_login_code(void* f, uint64_t ds) { return ((adi_get_login_code_t)f)(ds); }
static int call_dispose(void* f, void* p) { return ((adi_dispose_t)f)(p); }
static int call_otp_request(void* f, uint64_t ds, uint8_t** mid, unsigned int* midlen, uint8_t** otp, unsigned int* otplen) {
	return ((adi_otp_request_t)f)(ds, mid, midlen, otp, otplen);
}
*/
import "C"

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/hpidcock/ap/internal/anisette/local/androidlib"
)

// Error is a CoreADI error code.
type Error struct{ Code int }

func (e *Error) Error() string {
	var msg string
	switch e.Code {
	case -45001:
		msg = "invalid parameters, or missing initialization bits (set an identifier and a valid provisioning path first)"
	case -45002:
		msg = "invalid parameters (for decipher)"
	case -45003:
		msg = "invalid Trust Key"
	case -45006:
		msg = "ptm and tk are not matching the transmitted cpim"
	case -45018:
		msg = "invalid input data header"
	case -45019:
		msg = "unknown ADI function"
	case -45020:
		msg = "invalid input data"
	case -45025:
		msg = "unknown session"
	case -45026:
		msg = "empty session"
	case -45031:
		msg = "invalid data (header)"
	case -45032:
		msg = "data too short"
	case -45033:
		msg = "invalid data (body)"
	case -45034:
		msg = "unknown ADI call flags"
	case -45036:
		msg = "time error"
	case -45046:
		msg = "identifier generation failure: empty hardware ids"
	case -45054:
		msg = "generic libc/file manipulation error"
	case -45061:
		msg = "not provisioned"
	case -45062:
		msg = "cannot erase provisioning: not provisioned"
	case -45063:
		msg = "provisioning first step is already pending"
	case -45066:
		msg = "2nd step fail: session already consumed"
	case -45075:
		msg = "library loading error"
	default:
		msg = "unknown ADI error"
	}
	return fmt.Sprintf("ADI: %s (%d)", msg, e.Code)
}

// ErrNotProvisioned is the code ADIGetLoginCode returns for an unprovisioned machine.
const ErrNotProvisioned = -45061

func check(rc C.int) error {
	if rc != 0 {
		return &Error{Code: int(rc)}
	}
	return nil
}

// ADI is one loaded CoreADI instance. CoreADI keeps global state (identifier,
// provisioning path), so callers that need different state load separate instances.
type ADI struct {
	lib *androidlib.Library

	fnLoadLibrary, fnSetAndroidID, fnSetProvisioningPath                                unsafe.Pointer
	fnErase, fnSynchronize, fnDestroy, fnEnd, fnStart, fnGetLoginCode, fnDispose, fnOTP unsafe.Pointer

	provisioningPath string
	identifier       string
}

var symbolNames = map[string]string{
	"loadLibrary":         "kq56gsgHG6",
	"setAndroidID":        "Sph98paBcz",
	"setProvisioningPath": "nf92ngaK92",
	"provisioningErase":   "p435tmhbla",
	"synchronize":         "tn46gtiuhw",
	"provisioningDestroy": "fy34trz2st",
	"provisioningEnd":     "uv5t6nhkui",
	"provisioningStart":   "rsegvyrt87",
	"getLoginCode":        "aslgmuibau",
	"dispose":             "jk24uiwqrg",
	"otpRequest":          "qi864985u0",
}

// New loads libstoreservicescore.so from libraryDir and points it at libCoreADI.so there.
func New(libraryDir string) (*ADI, error) {
	ssc := filepath.Join(libraryDir, "libstoreservicescore.so")
	if _, err := os.Stat(ssc); err != nil {
		return nil, err
	}
	androidlib.SearchDir = libraryDir
	lib, err := androidlib.Load(ssc)
	if err != nil {
		return nil, err
	}
	a := &ADI{lib: lib}
	get := func(key string) (unsafe.Pointer, error) { return lib.Symbol(symbolNames[key]) }
	var errs []error
	a.fnLoadLibrary, err = get("loadLibrary")
	errs = append(errs, err)
	a.fnSetAndroidID, err = get("setAndroidID")
	errs = append(errs, err)
	a.fnSetProvisioningPath, err = get("setProvisioningPath")
	errs = append(errs, err)
	a.fnErase, err = get("provisioningErase")
	errs = append(errs, err)
	a.fnSynchronize, err = get("synchronize")
	errs = append(errs, err)
	a.fnDestroy, err = get("provisioningDestroy")
	errs = append(errs, err)
	a.fnEnd, err = get("provisioningEnd")
	errs = append(errs, err)
	a.fnStart, err = get("provisioningStart")
	errs = append(errs, err)
	a.fnGetLoginCode, err = get("getLoginCode")
	errs = append(errs, err)
	a.fnDispose, err = get("dispose")
	errs = append(errs, err)
	a.fnOTP, err = get("otpRequest")
	errs = append(errs, err)
	for _, e := range errs {
		if e != nil {
			lib.Close()
			return nil, e
		}
	}
	cdir := C.CString(libraryDir)
	defer C.free(unsafe.Pointer(cdir))
	if err := check(C.call_load_library(a.fnLoadLibrary, cdir)); err != nil {
		lib.Close()
		return nil, fmt.Errorf("loading libCoreADI: %w", err)
	}
	return a, nil
}

// Close unloads the libraries.
func (a *ADI) Close() error {
	if a.lib == nil {
		return nil
	}
	err := a.lib.Close()
	a.lib = nil
	return err
}

// ProvisioningPath is the directory holding adi.pb.
func (a *ADI) ProvisioningPath() string { return a.provisioningPath }

// SetProvisioningPath tells ADI where to read/write adi.pb.
func (a *ADI) SetProvisioningPath(path string) error {
	cs := C.CString(path)
	defer C.free(unsafe.Pointer(cs))
	if err := check(C.call_set_provisioning_path(a.fnSetProvisioningPath, cs)); err != nil {
		return err
	}
	a.provisioningPath = path
	return nil
}

// Identifier is the ADI machine identifier.
func (a *ADI) Identifier() string { return a.identifier }

// SetIdentifier sets the Android ID (16 hex chars).
func (a *ADI) SetIdentifier(id string) error {
	cs := C.CString(id)
	defer C.free(unsafe.Pointer(cs))
	if err := check(C.call_set_android_id(a.fnSetAndroidID, cs, C.uint(len(id)))); err != nil {
		return err
	}
	a.identifier = id
	return nil
}

// EraseProvisioning deletes the stored provisioning for dsID.
func (a *ADI) EraseProvisioning(dsID int64) error {
	return check(C.call_provisioning_erase(a.fnErase, C.uint64_t(uint64(dsID))))
}

// IsMachineProvisioned reports whether adi.pb is present and valid for dsID.
func (a *ADI) IsMachineProvisioned(dsID int64) (bool, error) {
	rc := int(C.call_get_login_code(a.fnGetLoginCode, C.uint64_t(uint64(dsID))))
	switch rc {
	case 0:
		return true, nil
	case ErrNotProvisioned:
		return false, nil
	}
	return false, &Error{Code: rc}
}

func (a *ADI) dispose(p unsafe.Pointer) {
	if p != nil {
		_ = C.call_dispose(a.fnDispose, p)
	}
}

func cbuf(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

func take(a *ADI, p *C.uint8_t, n C.uint) []byte {
	if p == nil {
		return nil
	}
	out := C.GoBytes(unsafe.Pointer(p), C.int(n))
	a.dispose(unsafe.Pointer(p))
	return out
}

// RequestOTP returns (one-time password, machine identifier).
func (a *ADI) RequestOTP(dsID int64) (otp, mid []byte, err error) {
	var cmid, cotp *C.uint8_t
	var midLen, otpLen C.uint
	if err := check(C.call_otp_request(a.fnOTP, C.uint64_t(uint64(dsID)), &cmid, &midLen, &cotp, &otpLen)); err != nil {
		return nil, nil, err
	}
	return take(a, cotp, otpLen), take(a, cmid, midLen), nil
}

// StartProvisioning feeds the server's SPIM and returns (CPIM, session).
func (a *ADI) StartProvisioning(dsID int64, spim []byte) ([]byte, uint32, error) {
	var ccpim *C.uint8_t
	var cpimLen, session C.uint
	if err := check(C.call_provisioning_start(a.fnStart, C.uint64_t(uint64(dsID)), cbuf(spim), C.uint(len(spim)), &ccpim, &cpimLen, &session)); err != nil {
		return nil, 0, err
	}
	return take(a, ccpim, cpimLen), uint32(session), nil
}

// EndProvisioning finishes a session with the server's PTM and TK.
func (a *ADI) EndProvisioning(session uint32, ptm, tk []byte) error {
	return check(C.call_provisioning_end(a.fnEnd, C.uint(session), cbuf(ptm), C.uint(len(ptm)), cbuf(tk), C.uint(len(tk))))
}

// DestroyProvisioning abandons a session.
func (a *ADI) DestroyProvisioning(session uint32) error {
	return check(C.call_provisioning_destroy(a.fnDestroy, C.uint(session)))
}

// Synchronize returns (machine identifier, synchronization resume metadata).
func (a *ADI) Synchronize(dsID int64, sim []byte) (mid, srm []byte, err error) {
	var cmid, csrm *C.uint8_t
	var midLen, srmLen C.uint
	if err := check(C.call_synchronize(a.fnSynchronize, C.uint64_t(uint64(dsID)), cbuf(sim), C.uint(len(sim)), &cmid, &midLen, &csrm, &srmLen)); err != nil {
		return nil, nil, err
	}
	return take(a, cmid, midLen), take(a, csrm, srmLen), nil
}

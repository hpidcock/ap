package local

import (
	"encoding/base64"
	"fmt"
	"github.com/hpidcock/ap/internal/logx"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/hpidcock/ap/internal/anisette"
	"github.com/hpidcock/ap/internal/anisette/local/adi"
)

// Local generates anisette machine data in-process: it loads Apple's CoreADI from
// configDir/lib (downloading the libraries on first use), keeps the machine identity in
// configDir/device.json and the provisioning data in configDir/adi.pb, and answers
// Headers() with a fresh one-time password. It satisfies anisette.Provider and is what
// `ap login` / `ap sync` use.
type Local struct {
	ConfigDir string
	Logf      func(string, ...any)

	mu      sync.Mutex // serialises every CoreADI call and the lazy initialisation
	adi     *adi.ADI
	machine *Machine
	libDir  string
}

// NewLocal returns a lazily-initialised in-process provider.
func NewLocal(configDir string, logf func(string, ...any)) *Local {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Local{ConfigDir: configDir, Logf: logf}
}

// LibDir is where the ADI libraries live.
func (l *Local) LibDir() string { return filepath.Join(l.ConfigDir, "lib") }

// Machine returns the machine identity (initialising if needed).
func (l *Local) Machine() (*Machine, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.initLocked(); err != nil {
		return nil, err
	}
	return l.machine, nil
}

// withLock runs fn while holding an exclusive lock on configDir/anisette.lock, so two
// ap processes (a manual login and a timer-driven sync, say) never provision the same
// machine identity at once.
func (l *Local) withLock(fn func() error) error {
	f, err := os.OpenFile(filepath.Join(l.ConfigDir, "anisette.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN) //nolint:errcheck
	return fn()
}

// initLocked loads the libraries and machine identity once. Caller holds l.mu.
func (l *Local) initLocked() error {
	if l.adi != nil {
		return nil
	}
	if err := os.MkdirAll(l.ConfigDir, 0o700); err != nil {
		return err
	}
	l.libDir = l.LibDir()
	return l.withLock(func() error {
		if err := EnsureLibraries(l.libDir, l.Logf); err != nil {
			return err
		}
		m, created, err := LoadOrCreateMachine(filepath.Join(l.ConfigDir, "device.json"))
		if err != nil {
			return err
		}
		if created {
			l.Logf("created a new anisette machine identity")
		}
		logx.Debugf("anisette", "libs=%s machine uuid=%s client-info=%q", l.libDir, m.UUID, m.ClientInfo)
		a, err := adi.New(l.libDir)
		if err != nil {
			return err
		}
		if err := a.SetProvisioningPath(l.ConfigDir); err != nil {
			a.Close()
			return fmt.Errorf("ADISetProvisioningPath: %w", err)
		}
		if err := a.SetIdentifier(m.ADIIdentifier); err != nil {
			a.Close()
			return fmt.Errorf("ADISetAndroidID: %w", err)
		}
		l.adi, l.machine = a, m
		return nil
	})
}

// ensureProvisionedLocked provisions the machine with Apple if needed. Caller holds l.mu.
func (l *Local) ensureProvisionedLocked() error {
	ok, err := l.adi.IsMachineProvisioned(DSID)
	if err != nil {
		return fmt.Errorf("ADIGetLoginCode/IsMachineProvisioned: %w", err)
	}
	if ok {
		return nil
	}
	logx.Debugf("anisette", "machine not provisioned yet")
	return l.withLock(func() error {
		// Another process may have provisioned while we waited for the lock.
		if ok, err := l.adi.IsMachineProvisioned(DSID); err != nil || ok {
			return err
		}
		l.Logf("provisioning this machine with Apple (once)...")
		if err := NewProvisioningSession(l.adi, l.machine).Provision(DSID); err != nil {
			logx.Errorf("anisette", err, "provisioning failed")
			return fmt.Errorf("anisette provisioning: %w", err)
		}
		l.Logf("provisioning done")
		return nil
	})
}

// EnsureReady downloads, loads and provisions without producing headers.
func (l *Local) EnsureReady() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.initLocked(); err != nil {
		return err
	}
	return l.ensureProvisionedLocked()
}

// AllHeaders produces the complete header set (the anisette-v1 response body shape).
func (l *Local) AllHeaders() (map[string]string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.initLocked(); err != nil {
		return nil, err
	}
	if err := l.ensureProvisionedLocked(); err != nil {
		return nil, err
	}
	otp, mid, err := l.adi.RequestOTP(DSID)
	if err != nil {
		return nil, fmt.Errorf("ADIOTPRequest: %w", err)
	}
	logx.Tracef("anisette", "machine data generated: otp %d bytes, mid %d bytes", len(otp), len(mid))
	now := time.Now()
	zone, _ := now.Zone()
	return map[string]string{
		"X-Apple-I-Client-Time": now.UTC().Format("2006-01-02T15:04:05Z"),
		"X-Apple-I-MD":          base64.StdEncoding.EncodeToString(otp),
		"X-Apple-I-MD-M":        base64.StdEncoding.EncodeToString(mid),
		"X-Apple-I-MD-RINFO":    "17106176",
		"X-Apple-I-MD-LU":       l.machine.LocalUUID,
		"X-Apple-I-SRL-NO":      "0",
		"X-MMe-Client-Info":     l.machine.ClientInfo,
		"X-Apple-I-TimeZone":    zone,
		"X-Apple-Locale":        "en_US",
		"X-Mme-Device-Id":       l.machine.UUID,
	}, nil
}

// Headers implements anisette.Provider: the forwarded subset of AllHeaders.
func (l *Local) Headers() (map[string]string, error) {
	h, err := l.AllHeaders()
	if err != nil {
		return nil, &anisette.Error{Msg: fmt.Sprintf("anisette (in-process): %v", err)}
	}
	return anisette.Filter(h)
}

// Close releases the libraries.
func (l *Local) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.adi != nil {
		err := l.adi.Close()
		l.adi = nil
		return err
	}
	return nil
}

package local

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/hpidcock/ap/internal/anisette/local/adi"
	"github.com/hpidcock/ap/internal/anisette/provisioning"
	"github.com/hpidcock/ap/internal/httpx"
)

// ProvisioningSession runs the GrandSlam machine-provisioning handshake against the ADI
// instance, which answers the server's challenge in process.
type ProvisioningSession struct {
	ADI     *adi.ADI
	Machine *Machine
	Apple   *provisioning.Session
}

// NewProvisioningSession returns a session.
func NewProvisioningSession(a *adi.ADI, m *Machine) *ProvisioningSession {
	return &ProvisioningSession{ADI: a, Machine: m, Apple: &provisioning.Session{
		HTTP:          httpx.ClientNoKeepAlive(60 * time.Second),
		ClientInfo:    m.ClientInfo,
		UserAgent:     "akd/1.0 CFNetwork/1404.0.5 Darwin/22.3.0",
		DeviceID:      m.UUID,
		LocalUserUUID: m.LocalUUID,
	}}
}

// Provision runs the full handshake for dsID and leaves adi.pb in the provisioning path.
func (p *ProvisioningSession) Provision(dsID int64) error {
	spimStr, err := p.Apple.Start()
	if err != nil {
		return err
	}
	spim, err := base64.StdEncoding.DecodeString(spimStr)
	if err != nil || len(spim) == 0 {
		return fmt.Errorf("provisioning: spim is not base64")
	}
	cpim, sess, err := p.ADI.StartProvisioning(dsID, spim)
	if err != nil {
		return err
	}
	ptmStr, tkStr, _, err := p.Apple.Finish(base64.StdEncoding.EncodeToString(cpim))
	if err != nil {
		_ = p.ADI.DestroyProvisioning(sess)
		return err
	}
	ptm, err1 := base64.StdEncoding.DecodeString(ptmStr)
	tk, err2 := base64.StdEncoding.DecodeString(tkStr)
	if err1 != nil || err2 != nil || len(ptm) == 0 || len(tk) == 0 {
		_ = p.ADI.DestroyProvisioning(sess)
		return fmt.Errorf("provisioning: ptm/tk are not base64")
	}
	if err := p.ADI.EndProvisioning(sess, ptm, tk); err != nil {
		_ = p.ADI.DestroyProvisioning(sess)
		return err
	}
	return nil
}

// Package session is the encrypted record of everything ap learns while signed in:
// the Apple account identifiers, the long-lived iCloud tokens, the cached service URL
// map, the Octagon peer identity and the idmsa web-session state. Secrets never sit
// on disk in the clear; see securestore.
package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/hpidcock/ap/internal/logx"
	"github.com/hpidcock/ap/internal/paths"
	"github.com/hpidcock/ap/internal/securestore"
)

// AppToken is one GrandSlam app token from the spd `t` dictionary.
type AppToken struct {
	Token    string `json:"token,omitempty"`
	Expiry   int64  `json:"expiry,omitempty"`
	Duration int64  `json:"duration,omitempty"`
}

// MME holds the mobileme (loginDelegates) credentials.
type MME struct {
	DSID           string            `json:"dsid,omitempty"`
	MmeAuthToken   string            `json:"mmeAuthToken,omitempty"`
	Tokens         map[string]string `json:"tokens,omitempty"`
	MintedAt       int64             `json:"minted_at,omitempty"`
	CloudKitUserID string            `json:"cloudKitUserId,omitempty"`
}

// SignedBlob is a hex-encoded (data, signature) pair.
type SignedBlob struct {
	Data string `json:"data"`
	Sig  string `json:"sig"`
}

// PeerKeys are the two P-384 private keys of the Octagon self peer, X9.63 hex.
type PeerKeys struct {
	Curve              string `json:"curve"`
	SigningPrivX963    string `json:"signing_priv_x963"`
	EncryptionPrivX963 string `json:"encryption_priv_x963"`
}

// Sponsor is the escrow-recovered identity that vouched for us. Its encryption key is
// what lets a later sync fetch the user-controllable views' TLKs (Passwords/Manatee).
type Sponsor struct {
	PeerID             string `json:"peer_id"`
	EncryptionPrivX963 string `json:"encryption_priv_x963"`
}

// Octagon is the persisted self-peer identity and trust state.
type Octagon struct {
	PeerID    string      `json:"peer_id,omitempty"`
	Keys      *PeerKeys   `json:"keys,omitempty"`
	Permanent *SignedBlob `json:"permanent,omitempty"`
	Stable    *SignedBlob `json:"stable,omitempty"`
	Dynamic   *SignedBlob `json:"dynamic,omitempty"`
	CreatedAt int64       `json:"created_at,omitempty"`
	Joined    bool        `json:"joined,omitempty"`
	Sponsor   *Sponsor    `json:"sponsor,omitempty"`
}

// Cookie is one persisted web-session cookie.
type Cookie struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Domain  string `json:"domain"`
	Path    string `json:"path"`
	Secure  bool   `json:"secure"`
	Expires int64  `json:"expires,omitempty"`
}

// WebAuth is the idmsa web-session state (Hide My Email).
type WebAuth struct {
	FrameTag    string            `json:"frame_tag,omitempty"`
	SessionData map[string]string `json:"session_data,omitempty"`
	Cookies     []Cookie          `json:"cookies,omitempty"`
}

// Session is the whole signed-in state.
type Session struct {
	Username    string              `json:"username,omitempty"`
	Password    string              `json:"password,omitempty"`
	DSID        string              `json:"dsid,omitempty"`         // adsid GUID
	DSIDNumeric string              `json:"dsid_numeric,omitempty"` // DsPrsId
	PET         string              `json:"pet,omitempty"`
	PETExpiry   int64               `json:"pet_expiry,omitempty"`
	LoggedInAt  int64               `json:"logged_in_at,omitempty"`
	GsIdms      string              `json:"gsidms,omitempty"`
	SKB64       string              `json:"sk_b64,omitempty"`
	AppTokens   map[string]AppToken `json:"app_tokens,omitempty"`
	MME         *MME                `json:"mme,omitempty"`
	Webservices map[string]string   `json:"webservices,omitempty"`
	Octagon     *Octagon            `json:"octagon,omitempty"`
	WebAuth     *WebAuth            `json:"webauth,omitempty"`
}

// EnsureMME returns the MME block, creating it if needed.
func (s *Session) EnsureMME() *MME {
	if s.MME == nil {
		s.MME = &MME{}
	}
	if s.MME.Tokens == nil {
		s.MME.Tokens = map[string]string{}
	}
	return s.MME
}

// IsJoined reports whether this peer is a trusted keychain member.
func (s *Session) IsJoined() bool {
	return s.Octagon != nil && (s.Octagon.Joined || s.Octagon.Sponsor != nil)
}

// Save encrypts and writes the session.
func Save(s *Session) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := securestore.WriteFile(paths.SessionFile(), data); err != nil {
		logx.Errorf("session", err, "save failed")
		return fmt.Errorf("could not save the session: %w", err)
	}
	logx.Debugf("session", "saved %d bytes: %s", len(data), s.Summary())
	return nil
}

// Summary describes what the session holds, for logs - never any token values.
func (s *Session) Summary() string {
	if s == nil {
		return "none"
	}
	mme := "no mme"
	if s.MME != nil {
		mme = fmt.Sprintf("mme{dsid=%v auth=%v ck-user=%v tokens=%d}", s.MME.DSID != "", s.MME.MmeAuthToken != "", s.MME.CloudKitUserID != "", len(s.MME.Tokens))
	}
	oct := "no octagon"
	if s.Octagon != nil {
		oct = fmt.Sprintf("octagon{peer=%v joined=%v sponsor=%v}", s.Octagon.PeerID != "", s.Octagon.Joined, s.Octagon.Sponsor != nil)
	}
	return fmt.Sprintf("user=%q pet=%v password-saved=%v webservices=%d apptokens=%d webauth=%v %s %s",
		s.Username, s.PET != "", s.Password != "", len(s.Webservices), len(s.AppTokens), s.WebAuth != nil, mme, oct)
}

// Load reads the session; (nil, nil) when none is stored.
func Load() (*Session, error) {
	data, err := securestore.ReadFile(paths.SessionFile())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		if errors.Is(err, securestore.ErrCannotDecrypt) {
			return nil, fmt.Errorf("%w (the keyring entry was lost or replaced). Run `ap logout`, then `ap login` to sign in again", err)
		}
		return nil, err
	}
	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("corrupt session: %w", err)
	}
	logx.Debugf("session", "loaded %d bytes: %s", len(data), s.Summary())
	return &s, nil
}

// Clear removes the stored session.
func Clear() error {
	err := os.Remove(paths.SessionFile())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

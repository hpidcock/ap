package octagon

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/hpidcock/ap/internal/anisette"
	"github.com/hpidcock/ap/internal/cloudkit"
	"github.com/hpidcock/ap/internal/device"
	"github.com/hpidcock/ap/internal/escrow"
	"github.com/hpidcock/ap/internal/keychain"
	"github.com/hpidcock/ap/internal/proto"
	"github.com/hpidcock/ap/internal/session"
	"github.com/hpidcock/ap/internal/vault"
)

// Prevailing builtin Octagon policy version<->hash, declared in our stableInfo;
// Cuttlefish validates them. If Apple bumps the version, refresh via fetchPolicyDocuments.
const (
	FrozenPolicyVersion   = 5
	FrozenPolicyHash      = "SHA256:O/ECQlWhvNlLmlDNh2+nal/yekUC87bXpV3k+6kznSo="
	FlexiblePolicyVersion = 20
	FlexiblePolicyHash    = "SHA256:OIzjC3WyLGrM8GAd/EyIfVzTJdYmcGoKPFdQeWeRZTY="

	PeerModelID   = "MacBookPro18,3"
	PeerOSVersion = "macOS 13.4.1 (22F8)"
)

// Error is an Octagon orchestration failure.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

func errorf(format string, a ...any) error { return &Error{Msg: fmt.Sprintf(format, a...)} }

func stableParams(clock uint64, serial string) StableInfoParams {
	return StableInfoParams{
		Clock: clock, FrozenPolicyVersion: FrozenPolicyVersion, FrozenPolicyHash: FrozenPolicyHash,
		FlexiblePolicyVersion: FlexiblePolicyVersion, FlexiblePolicyHash: FlexiblePolicyHash,
		DeviceName: "", SerialNumber: serial, OSVersion: PeerOSVersion,
		UserControllableViews: UCVFollowing, SupportsRepudiation: true,
	}
}

func serialOf(dev *device.Device) string {
	if dev != nil && dev.Serial != "" {
		return dev.Serial
	}
	return "0000000000"
}

// EnsurePeerIdentity generates (once) and persists the Octagon self-peer into the
// session. The stored stable/dynamic info are an initial form; the live join regenerates
// and re-signs both from the fetchChanges trust state, as the real client does.
func EnsurePeerIdentity(s *session.Session, dev *device.Device) (*session.Octagon, error) {
	if s.Octagon != nil && s.Octagon.PeerID != "" {
		return s.Octagon, nil
	}
	keys, err := GeneratePeerKeySet()
	if err != nil {
		return nil, err
	}
	machineID := ""
	if dev != nil {
		machineID = dev.DeviceID
	}
	if machineID == "" {
		machineID = s.DSIDNumeric
	}
	perm, err := BuildPermanentInfo(keys, machineID, PeerModelID, 1, uint64(time.Now().Unix()))
	if err != nil {
		return nil, err
	}
	stable, err := BuildStableInfo(keys, stableParams(1, serialOf(dev)))
	if err != nil {
		return nil, err
	}
	dynamic, err := BuildDynamicInfo(keys, 1, []string{perm.PeerID}, nil, nil)
	if err != nil {
		return nil, err
	}
	s.Octagon = &session.Octagon{
		PeerID:    perm.PeerID,
		Keys:      keys.ToStorage(),
		Permanent: &session.SignedBlob{Data: hex.EncodeToString(perm.Data), Sig: hex.EncodeToString(perm.Sig)},
		Stable:    &session.SignedBlob{Data: hex.EncodeToString(stable.Data), Sig: hex.EncodeToString(stable.Sig)},
		Dynamic:   &session.SignedBlob{Data: hex.EncodeToString(dynamic.Data), Sig: hex.EncodeToString(dynamic.Sig)},
		CreatedAt: time.Now().Unix(),
	}
	return s.Octagon, nil
}

// LoadPeerKeys restores the self-peer keys from the session.
func LoadPeerKeys(o *session.Octagon) (*PeerKeySet, error) {
	if o == nil {
		return nil, errors.New("octagon: no peer identity in session")
	}
	return PeerKeySetFromStorage(o.Keys)
}

// TrustFromChanges derives (sponsor's included peerIDs, next stable clock, next dynamic
// clock) from a fetchChanges result.
func TrustFromChanges(changes proto.FetchChangesResponse, sponsorPeerID string) ([]string, uint64, uint64) {
	var maxStable uint64
	var included []string
	var sponsorDyn uint64
	for _, p := range changes.Peers {
		if p.StableInfo != nil {
			if c := ParseStableInfoData(p.StableInfo.Info).Clock; c > maxStable {
				maxStable = c
			}
		}
		if p.Hash == sponsorPeerID && p.DynamicInfo != nil {
			di := ParseDynamicInfoData(p.DynamicInfo.Info)
			included = di.Included
			sponsorDyn = di.Clock
		}
	}
	return included, maxStable + 1, sponsorDyn + 1
}

// BuildJoinPeer regenerates + re-signs stableInfo and dynamicInfo (sponsor's trusted
// peers + self) and encodes the CuttlefishPeer for joinWithVoucher.
func BuildJoinPeer(o *session.Octagon, keys *PeerKeySet, voucher proto.SignedBlob, included []string, stableClock, dynamicClock uint64, serial string) ([]byte, error) {
	stable, err := BuildStableInfo(keys, stableParams(stableClock, serial))
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var includeds []string
	for _, id := range append(append([]string{}, included...), o.PeerID) {
		if !seen[id] {
			seen[id] = true
			includeds = append(includeds, id)
		}
	}
	dynamic, err := BuildDynamicInfo(keys, dynamicClock, includeds, nil, nil)
	if err != nil {
		return nil, err
	}
	permData, err := hex.DecodeString(o.Permanent.Data)
	if err != nil {
		return nil, err
	}
	permSig, err := hex.DecodeString(o.Permanent.Sig)
	if err != nil {
		return nil, err
	}
	return proto.EncodePeer(o.PeerID,
		proto.SignedBlob{Info: permData, Sig: permSig},
		proto.SignedBlob{Info: stable.Data, Sig: stable.Sig},
		proto.SignedBlob{Info: dynamic.Data, Sig: dynamic.Sig},
		&voucher), nil
}

// Bottle is a viable escrow bottle with the GETRECORDS metadata naming its device.
type Bottle struct {
	ID       string
	OTBottle []byte
	Meta     map[string]any
}

// Client drives the live join + sync from a logged-in session.
type Client struct {
	Session   *session.Session
	Device    *device.Device
	Anisette  anisette.Provider
	Transport *cloudkit.Transport
	AdSID     string // the GUID adsid (escrow key derivation)
	UserID    string
}

// NewClient resolves the per-container cloudKitUserId (cached in the session) and builds
// the CloudKit transport.
func NewClient(s *session.Session, dev *device.Device, anis anisette.Provider) (*Client, error) {
	mme := s.EnsureMME()
	ckToken := mme.Tokens["cloudKitToken"]
	if ckToken == "" {
		return nil, errorf("no cloudKitToken in session - run `ap login` first")
	}
	mmeDSID := mme.DSID
	if mmeDSID == "" {
		mmeDSID = s.DSIDNumeric
	}
	userID := mme.CloudKitUserID
	if userID == "" {
		if mme.MmeAuthToken == "" {
			return nil, errorf("no mmeAuthToken in session - run `ap login`")
		}
		var err error
		userID, err = cloudkit.CKAppInit(cloudkit.CuttlefishContainer, cloudkit.CuttlefishBundle, mmeDSID, mme.MmeAuthToken, anis)
		if err != nil {
			return nil, err
		}
		mme.CloudKitUserID = userID // persisted by the caller's next session.Save
	}
	cfg := cloudkit.DeviceConfig{DeviceUUID: dev.DeviceID, Serial: serialOf(dev), Name: "Mac"}
	return &Client{
		Session: s, Device: dev, Anisette: anis, AdSID: s.DSID, UserID: userID,
		Transport: cloudkit.NewTransport(ckToken, userID, cfg, anis),
	}, nil
}

// FetchChanges returns the current trust state page.
func (c *Client) FetchChanges(syncToken string) (proto.FetchChangesResponse, error) {
	res, err := c.Transport.Invoke("fetchChanges", proto.EncodeFetchChangesRequest(syncToken))
	if err != nil {
		return proto.FetchChangesResponse{}, err
	}
	return proto.ParseFetchChangesResponse(res.SerializedResult()), nil
}

// FetchViableBottles lists the account's escrow bottles (non-destructive).
func (c *Client) FetchViableBottles() ([]proto.ViableBottle, error) {
	res, err := c.Transport.Invoke("fetchViableBottles", proto.EncodeFetchViableBottlesRequest())
	if err != nil {
		return nil, err
	}
	return proto.ParseViableBottles(res.SerializedResult()), nil
}

// ListRecoverableBottles correlates the viable bottles with escrowproxy GETRECORDS
// metadata that names each backed-up device. Metadata is best-effort.
func (c *Client) ListRecoverableBottles(escrowHost, email, pet string, warn func(string)) ([]Bottle, error) {
	viable, err := c.FetchViableBottles()
	if err != nil {
		return nil, err
	}
	meta := map[string]map[string]any{}
	recovery := escrow.NewRecovery(escrowHost, email, pet, c.Anisette)
	if records, err := recovery.ListRecords(); err != nil {
		if warn != nil {
			warn(fmt.Sprintf("GETRECORDS device metadata unavailable: %v", err))
		}
	} else {
		for _, r := range records {
			meta[r.Label] = r.Meta
		}
	}
	var out []Bottle
	for _, b := range viable {
		if len(b.OTBottle) == 0 {
			continue
		}
		m := meta[b.ID]
		if m == nil {
			m = map[string]any{}
		}
		out = append(out, Bottle{ID: b.ID, OTBottle: b.OTBottle, Meta: m})
	}
	return out, nil
}

// SyncKeychain fetches every keychain zone's records and groups them by CKKS type. A
// missing or empty zone is skipped rather than failing the whole sync.
func (c *Client) SyncKeychain(zones []string) map[string][]cloudkit.Record {
	if zones == nil {
		zones = cloudkit.KeychainZones
	}
	grouped := map[string][]cloudkit.Record{}
	for _, zone := range zones {
		zid := cloudkit.RecordZoneIdentifier(zone, c.UserID)
		var continuation []byte
		for {
			raw, err := c.Transport.FetchRecords(cloudkit.BuildRetrieveChangesRequest(zid, continuation, 500))
			if err != nil {
				break
			}
			page := cloudkit.ParseRetrieveChangesResponse(raw)
			for _, r := range page.Records {
				grouped[r.Type] = append(grouped[r.Type], r)
			}
			continuation = page.Continuation
			if page.Status != 1 || len(continuation) == 0 {
				break
			}
		}
	}
	return grouped
}

func (c *Client) recoverSponsor(escrowHost, email, pet string, passcode []byte, chosen *Bottle, confirm bool) (*escrow.RecoveredIdentity, error) {
	if chosen == nil {
		viable, err := c.FetchViableBottles()
		if err != nil {
			return nil, err
		}
		for _, b := range viable {
			if len(b.OTBottle) > 0 {
				chosen = &Bottle{ID: b.ID, OTBottle: b.OTBottle}
				break
			}
		}
	}
	if chosen == nil || len(chosen.OTBottle) == 0 {
		return nil, errorf("no viable escrow bottle found for this account")
	}
	recovery := escrow.NewRecovery(escrowHost, email, pet, c.Anisette)
	entropy, err := recovery.TryRecoverEscrow(chosen.ID, passcode, confirm)
	if err != nil {
		return nil, err
	}
	bottle, err := escrow.ParseOTBottle(chosen.OTBottle)
	if err != nil {
		return nil, err
	}
	identity, err := escrow.RecoverIdentity(bottle, entropy, c.AdSID)
	if err != nil {
		return nil, err
	}
	c.Session.Octagon.Sponsor = &session.Sponsor{
		PeerID:             identity.PeerID,
		EncryptionPrivX963: hex.EncodeToString(identity.Encryption.PrivateX963()),
	}
	return identity, nil
}

// JoinViaEscrow is the full escrow-recovery join: recover the chosen bottle -> vouch ->
// join. Returns the recovered sponsor peerID. confirm MUST be true (set only after the
// user's typed confirmation); each call spends one of the ~10 escrow attempts.
func (c *Client) JoinViaEscrow(escrowHost, email, pet string, passcode []byte, chosen *Bottle, confirm bool) (string, error) {
	identity, err := c.recoverSponsor(escrowHost, email, pet, passcode, chosen, confirm)
	if err != nil {
		return "", err
	}
	o := c.Session.Octagon
	voucher, err := identity.MakeVoucher(o.PeerID, 1)
	if err != nil {
		return "", err
	}
	changes, err := c.FetchChanges("")
	if err != nil {
		return "", err
	}
	included, stableClock, dynClock := TrustFromChanges(changes, identity.PeerID)
	if len(included) == 0 { // sponsor not in the page - trust at least it + self
		included = []string{identity.PeerID}
	}
	keys, err := LoadPeerKeys(o)
	if err != nil {
		return "", err
	}
	peer, err := BuildJoinPeer(o, keys, voucher, included, stableClock, dynClock, serialOf(c.Device))
	if err != nil {
		return "", err
	}
	req := proto.EncodeJoinWithVoucherRequest(peer, nil, nil, changes.SyncToken)
	if _, err := c.Transport.Invoke("joinWithVoucher", req); err != nil {
		return "", err
	}
	o.Joined = true
	return identity.PeerID, nil
}

func (c *Client) fetchRecoverableFor(peerID string, key *PeerKey) (map[string][]byte, []cloudkit.Record, error) {
	res, err := c.Transport.Invoke("fetchRecoverableTLKShares", proto.EncodeFetchRecoverableTLKSharesRequest(peerID))
	if err != nil {
		return nil, nil, err
	}
	parsed := proto.ParseRecoverableTLKSharesResponse(res.SerializedResult())
	var shares, synckeys []cloudkit.Record
	for _, r := range parsed.ShareRecords {
		shares = append(shares, cloudkit.ParseRecord(r))
	}
	for _, r := range parsed.SyncKeyRecords {
		synckeys = append(synckeys, cloudkit.ParseRecord(r))
	}
	enc, err := key.ECDH()
	if err != nil {
		return nil, nil, err
	}
	return keychain.UnwrapTLKShares(shares, peerID, enc), synckeys, nil
}

// FetchRecoverableTLKs obtains every view's TLK via fetchRecoverableTLKShares, from BOTH
// our own peer and the escrow-recovered sponsor (which alone is entitled to the
// user-controllable views like Passwords/Manatee). Both sets are UNIONed.
func (c *Client) FetchRecoverableTLKs() (map[string][]byte, []cloudkit.Record, error) {
	o := c.Session.Octagon
	keys, err := LoadPeerKeys(o)
	if err != nil {
		return nil, nil, err
	}
	tlks, synckeys, err := c.fetchRecoverableFor(o.PeerID, keys.Encryption)
	if err != nil {
		return nil, nil, err
	}
	if o.Sponsor != nil {
		raw, err := hex.DecodeString(o.Sponsor.EncryptionPrivX963)
		if err != nil {
			return nil, nil, err
		}
		spKey, err := LoadPeerKeyX963(raw)
		if err != nil {
			return nil, nil, err
		}
		spTLKs, spSynckeys, err := c.fetchRecoverableFor(o.Sponsor.PeerID, spKey)
		if err != nil {
			return nil, nil, err
		}
		for k, v := range spTLKs {
			tlks[k] = v
		}
		synckeys = append(synckeys, spSynckeys...)
	}
	return tlks, synckeys, nil
}

// SyncAndDecrypt fetches every view's TLK, then the keychain zones, and decrypts them
// into the vault. Returns the credential count.
func (c *Client) SyncAndDecrypt() (int, error) {
	tlks, viewSynckeys, err := c.FetchRecoverableTLKs()
	if err != nil {
		return 0, err
	}
	records := c.SyncKeychain(nil)
	records["synckey"] = append(records["synckey"], viewSynckeys...)
	keys, err := LoadPeerKeys(c.Session.Octagon)
	if err != nil {
		return 0, err
	}
	enc, err := keys.Encryption.ECDH()
	if err != nil {
		return 0, err
	}
	store := keychain.BuildCredentialStore(records, c.Session.Octagon.PeerID, enc, tlks)
	if err := vault.SaveVault(store); err != nil {
		return 0, err
	}
	return store.Len(), nil
}

// Package octagon builds the Octagon self-peer identity (two P-384 key pairs and the
// signed permanent/stable/dynamic info blobs, the way TrustedPeersHelper does) and
// drives the live join + sync. Format pins are documented in RESEARCH.md stage 3.
package octagon

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"time"

	"github.com/hpidcock/ap/internal/peerkey"
	"github.com/hpidcock/ap/internal/proto"
)

// Re-exported key material (see package peerkey).
type (
	PeerKey    = peerkey.PeerKey
	PeerKeySet = peerkey.PeerKeySet
)

var (
	GeneratePeerKey       = peerkey.GeneratePeerKey
	GeneratePeerKeySet    = peerkey.GeneratePeerKeySet
	LoadPeerKeyX963       = peerkey.LoadPeerKeyX963
	LoadPeerKeyScalar     = peerkey.LoadPeerKeyScalar
	PeerKeySetFromStorage = peerkey.PeerKeySetFromStorage
	PrefixedData          = peerkey.PrefixedData
)

// Signature domain-separation prefixes (typesafeSignature).
const (
	PermanentInfoSigType = peerkey.PermanentInfoSigType
	StableInfoSigType    = peerkey.StableInfoSigType
	DynamicInfoSigType   = peerkey.DynamicInfoSigType
	VoucherSigType       = peerkey.VoucherSigType
)

// TPHash is TPHashBuilder: "<ALGO>:" + base64(digest).
func TPHash(data []byte, algo string) string {
	switch algo {
	case "SHA384":
		sum := sha512.Sum384(data)
		return "SHA384:" + base64.StdEncoding.EncodeToString(sum[:])
	default:
		sum := sha256.Sum256(data)
		return "SHA256:" + base64.StdEncoding.EncodeToString(sum[:])
	}
}

// DerivePeerID is tphash(data ++ sig).
func DerivePeerID(permanentInfoData, sig []byte) string {
	return TPHash(append(append([]byte{}, permanentInfoData...), sig...), "SHA256")
}

// MungeModelID is +[TPPeerPermanentInfo mungeModelID:] - pass-through on production builds.
func MungeModelID(modelID string) string { return modelID }

// SerializePermanentInfoData builds the TPPBPeerPermanentInfo protobuf.
func SerializePermanentInfoData(signingSPKI, encryptionSPKI []byte, machineID, modelID string, epoch, creationTime uint64) []byte {
	return new(proto.Writer).Uint64(1, epoch).Bytes(2, signingSPKI).Bytes(3, encryptionSPKI).
		String(4, machineID).String(5, MungeModelID(modelID)).Uint64(6, creationTime).Finish()
}

// PermanentInfo is the signed self-peer identity.
type PermanentInfo struct {
	PeerID       string
	Data         []byte
	Sig          []byte
	MachineID    string
	ModelID      string
	Epoch        uint64
	CreationTime uint64
}

// BuildPermanentInfo builds and signs the permanentInfo and derives its peerID.
func BuildPermanentInfo(keys *PeerKeySet, machineID, modelID string, epoch uint64, creationTime uint64) (*PermanentInfo, error) {
	if creationTime == 0 {
		creationTime = uint64(time.Now().Unix())
	}
	data := SerializePermanentInfoData(keys.Signing.PublicSPKI(), keys.Encryption.PublicSPKI(), machineID, modelID, epoch, creationTime)
	sig, err := keys.Signing.SignSHA384(PrefixedData(data, PermanentInfoSigType))
	if err != nil {
		return nil, err
	}
	return &PermanentInfo{PeerID: DerivePeerID(data, sig), Data: data, Sig: sig, MachineID: machineID,
		ModelID: MungeModelID(modelID), Epoch: epoch, CreationTime: creationTime}, nil
}

// UCVFollowing is the UserControllableViewStatus "FOLLOWING" value.
const UCVFollowing = 1

// StableInfoParams are the TPPBPeerStableInfo fields we set.
type StableInfoParams struct {
	Clock                 uint64
	FrozenPolicyVersion   uint64
	FrozenPolicyHash      string
	FlexiblePolicyVersion uint64
	FlexiblePolicyHash    string
	DeviceName            string
	SerialNumber          string
	OSVersion             string
	UserControllableViews uint64
	SupportsRepudiation   bool
}

// SerializeStableInfoData builds the TPPBPeerStableInfo protobuf.
func SerializeStableInfoData(p StableInfoParams) []byte {
	w := new(proto.Writer).Uint64(1, p.Clock).Uint64(2, p.FrozenPolicyVersion).
		String(3, p.FrozenPolicyHash).String(5, p.OSVersion).String(6, p.DeviceName).
		String(9, p.SerialNumber).Uint64(10, p.FlexiblePolicyVersion).
		String(11, p.FlexiblePolicyHash).Uint64(12, p.UserControllableViews)
	if p.SupportsRepudiation {
		w.Bool(19, true)
	}
	return w.Finish()
}

// SignedInfo is a (data, sig) pair.
type SignedInfo struct {
	Data []byte
	Sig  []byte
}

// BuildStableInfo builds and signs the stableInfo.
func BuildStableInfo(keys *PeerKeySet, p StableInfoParams) (*SignedInfo, error) {
	data := SerializeStableInfoData(p)
	sig, err := keys.Signing.SignSHA384(PrefixedData(data, StableInfoSigType))
	if err != nil {
		return nil, err
	}
	return &SignedInfo{Data: data, Sig: sig}, nil
}

// StableInfoFields are the parsed stableInfo values we care about.
type StableInfoFields struct {
	Clock                 uint64
	FrozenPolicyVersion   uint64
	FrozenPolicyHash      string
	OSVersion             string
	DeviceName            string
	SerialNumber          string
	FlexiblePolicyVersion uint64
	FlexiblePolicyHash    string
	UserControllableViews uint64
	SupportsRepudiation   *bool
}

// ParseStableInfoData decodes a TPPBPeerStableInfo.
func ParseStableInfoData(data []byte) StableInfoFields {
	f := proto.MustDecode(data)
	out := StableInfoFields{
		Clock: f.Uint64(1), FrozenPolicyVersion: f.Uint64(2), FrozenPolicyHash: f.String(3),
		OSVersion: f.String(5), DeviceName: f.String(6), SerialNumber: f.String(9),
		FlexiblePolicyVersion: f.Uint64(10), FlexiblePolicyHash: f.String(11),
		UserControllableViews: f.Uint64(12),
	}
	if f.Has(19) {
		v := f.Uint64(19) != 0
		out.SupportsRepudiation = &v
	}
	return out
}

// SerializeDynamicInfoData builds the TPPBPeerDynamicInfo protobuf (the trust graph).
func SerializeDynamicInfoData(clock uint64, included, excluded, preapprovals []string) []byte {
	w := new(proto.Writer).Uint64(1, clock)
	for _, p := range included {
		w.String(2, p)
	}
	for _, p := range excluded {
		w.String(3, p)
	}
	for _, p := range preapprovals {
		w.String(5, p)
	}
	return w.Finish()
}

// BuildDynamicInfo builds and signs the dynamicInfo.
func BuildDynamicInfo(keys *PeerKeySet, clock uint64, included, excluded, preapprovals []string) (*SignedInfo, error) {
	data := SerializeDynamicInfoData(clock, included, excluded, preapprovals)
	sig, err := keys.Signing.SignSHA384(PrefixedData(data, DynamicInfoSigType))
	if err != nil {
		return nil, err
	}
	return &SignedInfo{Data: data, Sig: sig}, nil
}

// DynamicInfoFields are the parsed dynamicInfo values.
type DynamicInfoFields struct {
	Clock        uint64
	Included     []string
	Excluded     []string
	Preapprovals []string
}

// ParseDynamicInfoData decodes a TPPBPeerDynamicInfo.
func ParseDynamicInfoData(data []byte) DynamicInfoFields {
	f := proto.MustDecode(data)
	out := DynamicInfoFields{Clock: f.Uint64(1)}
	for _, b := range f.Repeated(2) {
		out.Included = append(out.Included, string(b))
	}
	for _, b := range f.Repeated(3) {
		out.Excluded = append(out.Excluded, string(b))
	}
	for _, b := range f.Repeated(5) {
		out.Preapprovals = append(out.Preapprovals, string(b))
	}
	return out
}

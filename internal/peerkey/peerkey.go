// Package peerkey holds the P-384 key material shared by the Octagon self peer and the
// escrow-recovered sponsor identity: X9.63 / SPKI encodings, ECDSA-P384-SHA384 signing
// with Apple's typesafe-signature domain separation, and the session storage form.
package peerkey

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/hpidcock/ap/internal/session"
)

const (
	coordLen = 48
	pointLen = 1 + 2*coordLen // 0x04 || X || Y = 97
)

// PeerKey is one P-384 key pair (a peer has two: signing + encryption).
type PeerKey struct {
	Private *ecdsa.PrivateKey
}

// GeneratePeerKey makes a fresh P-384 key.
func GeneratePeerKey() (*PeerKey, error) {
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &PeerKey{Private: k}, nil
}

// LoadPeerKeyX963 reconstructs a key from `0x04||X||Y||D` (OTPrivateKey.keyData).
func LoadPeerKeyX963(blob []byte) (*PeerKey, error) {
	if len(blob) != pointLen+coordLen {
		return nil, fmt.Errorf("octagon: X9.63 private key must be %d bytes, got %d", pointLen+coordLen, len(blob))
	}
	return LoadPeerKeyScalar(blob[pointLen:])
}

// LoadPeerKeyScalar builds a key from the 48-byte private scalar.
func LoadPeerKeyScalar(d []byte) (*PeerKey, error) {
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P384(), d)
	if err != nil {
		return nil, err
	}
	return &PeerKey{Private: k}, nil
}

// PublicX963 is `0x04 || X || Y` (97 bytes).
func (k *PeerKey) PublicX963() []byte {
	b, err := k.Private.PublicKey.Bytes()
	if err != nil {
		panic(err)
	}
	return b
}

// PublicSPKI is the SubjectPublicKeyInfo DER.
func (k *PeerKey) PublicSPKI() []byte {
	der, err := x509.MarshalPKIXPublicKey(&k.Private.PublicKey)
	if err != nil {
		panic(err)
	}
	return der
}

// PrivateX963 is `0x04 || X || Y || D` (145 bytes).
func (k *PeerKey) PrivateX963() []byte {
	d := make([]byte, coordLen)
	k.Private.D.FillBytes(d)
	return append(k.PublicX963(), d...)
}

// ECDH returns the key as a crypto/ecdh private key for ECIES.
func (k *PeerKey) ECDH() (*ecdh.PrivateKey, error) {
	d := make([]byte, coordLen)
	k.Private.D.FillBytes(d)
	return ecdh.P384().NewPrivateKey(d)
}

// SignSHA384 is a DER-encoded ECDSA-P384-SHA384 signature.
func (k *PeerKey) SignSHA384(data []byte) ([]byte, error) {
	sum := sha512.Sum384(data)
	return ecdsa.SignASN1(rand.Reader, k.Private, sum[:])
}

// VerifySHA384 checks a signature made by SignSHA384.
func (k *PeerKey) VerifySHA384(data, sig []byte) bool {
	sum := sha512.Sum384(data)
	return ecdsa.VerifyASN1(&k.Private.PublicKey, sum[:], sig)
}

// PeerKeySet is the two key pairs of one Octagon self-peer identity.
type PeerKeySet struct {
	Signing    *PeerKey
	Encryption *PeerKey
}

// GeneratePeerKeySet makes both keys.
func GeneratePeerKeySet() (*PeerKeySet, error) {
	s, err := GeneratePeerKey()
	if err != nil {
		return nil, err
	}
	e, err := GeneratePeerKey()
	if err != nil {
		return nil, err
	}
	return &PeerKeySet{Signing: s, Encryption: e}, nil
}

// ToStorage serialises for the encrypted session.
func (ks *PeerKeySet) ToStorage() *session.PeerKeys {
	return &session.PeerKeys{
		Curve:              "P-384",
		SigningPrivX963:    hex.EncodeToString(ks.Signing.PrivateX963()),
		EncryptionPrivX963: hex.EncodeToString(ks.Encryption.PrivateX963()),
	}
}

// PeerKeySetFromStorage is the inverse of ToStorage.
func PeerKeySetFromStorage(d *session.PeerKeys) (*PeerKeySet, error) {
	if d == nil {
		return nil, errors.New("octagon: no stored peer keys")
	}
	sb, err := hex.DecodeString(d.SigningPrivX963)
	if err != nil {
		return nil, err
	}
	eb, err := hex.DecodeString(d.EncryptionPrivX963)
	if err != nil {
		return nil, err
	}
	s, err := LoadPeerKeyX963(sb)
	if err != nil {
		return nil, err
	}
	e, err := LoadPeerKeyX963(eb)
	if err != nil {
		return nil, err
	}
	return &PeerKeySet{Signing: s, Encryption: e}, nil
}

// Signature domain-separation prefixes (typesafeSignature).
const (
	PermanentInfoSigType = "TPPB.PeerPermanentInfo"
	StableInfoSigType    = "TPPB.PeerStableInfo"
	DynamicInfoSigType   = "TPPB.PeerDynamicInfo"
	VoucherSigType       = "TPPB.Voucher"
)

// PrefixedData is UTF8(sigTypeName) ++ data.
func PrefixedData(data []byte, sigType string) []byte {
	return append([]byte(sigType), data...)
}

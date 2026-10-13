package escrow

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha512"
	"fmt"
	"math/big"

	"github.com/hpidcock/ap/internal/peerkey"
	"github.com/hpidcock/ap/internal/proto"
)

// Escrow-recovery join: decrypt the EscrowBottle (after the gated SRP) into the
// recovered old peer keys, then sign a voucher that lets our new peer join.

var p384Order, _ = new(big.Int).SetString(
	"ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16)

// HKDF info labels.
var (
	InfoSymmetric  = []byte("Escrow Symmetric Key")
	InfoSigning    = []byte("Escrow Signing Private Key")
	InfoEncryption = []byte("Escrow Encryption Private Key")
)

// Error is a bottle decryption failure.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

// OTBottle is the parsed OTBottle protobuf.
type OTBottle struct {
	PeerID                string
	BottleID              string
	EscrowedSigningKey    []byte // SPKI DER
	EscrowedEncryptionKey []byte // SPKI DER
	CT                    []byte
	AuthCode              []byte
	IV                    []byte
}

// ParseOTBottle decodes OTBottle{ peerID(1), bottleID(2), signingSPKI(8), encryptionSPKI(9), contents(12){ct(1), tag(2), iv(3)} }.
func ParseOTBottle(raw []byte) (*OTBottle, error) {
	f, err := proto.Decode(raw)
	if err != nil {
		return nil, err
	}
	cf := proto.MustDecode(f.Bytes(12))
	return &OTBottle{
		PeerID: f.String(1), BottleID: f.String(2),
		EscrowedSigningKey: f.Bytes(8), EscrowedEncryptionKey: f.Bytes(9),
		CT: cf.Bytes(1), AuthCode: cf.Bytes(2), IV: cf.Bytes(3),
	}, nil
}

// Encode serialises the bottle (tests).
func (b *OTBottle) Encode() []byte {
	contents := new(proto.Writer).Bytes(1, b.CT).Bytes(2, b.AuthCode).Bytes(3, b.IV).Finish()
	return new(proto.Writer).String(1, b.PeerID).String(2, b.BottleID).
		Bytes(8, b.EscrowedSigningKey).Bytes(9, b.EscrowedEncryptionKey).Message(12, contents).Finish()
}

func hkdfSHA384(entropy []byte, adsid string, info []byte, length int) ([]byte, error) {
	return hkdf.Key(sha512.New384, entropy, []byte(adsid), string(info), length)
}

// DeriveSymmetricKey is the 32-byte AES key that wraps the internal bottle.
func DeriveSymmetricKey(entropy []byte, adsid string) ([]byte, error) {
	return hkdfSHA384(entropy, adsid, InfoSymmetric, 32)
}

// DeriveECPrivateKey is HKDF-SHA384 -> 56 bytes -> FIPS 186-4 B.5.1 (mod (n-1), +1) -> P-384 key.
func DeriveECPrivateKey(entropy []byte, adsid string, info []byte) (*peerkey.PeerKey, error) {
	raw, err := hkdfSHA384(entropy, adsid, info, 56)
	if err != nil {
		return nil, err
	}
	d := new(big.Int).SetBytes(raw)
	d.Mod(d, new(big.Int).Sub(p384Order, big.NewInt(1)))
	d.Add(d, big.NewInt(1))
	buf := make([]byte, 48)
	d.FillBytes(buf)
	return peerkey.LoadPeerKeyScalar(buf)
}

// RecoveredIdentity is the escrowed old peer.
type RecoveredIdentity struct {
	PeerID     string
	Signing    *peerkey.PeerKey
	Encryption *peerkey.PeerKey
}

// MakeVoucher signs Voucher{reason, beneficiary, sponsor=self} with the recovered signing key.
func (r *RecoveredIdentity) MakeVoucher(beneficiaryPeerID string, reason uint64) (proto.SignedBlob, error) {
	info := proto.EncodeVoucher(reason, beneficiaryPeerID, r.PeerID)
	sig, err := r.Signing.SignSHA384(peerkey.PrefixedData(info, peerkey.VoucherSigType))
	if err != nil {
		return proto.SignedBlob{}, err
	}
	return proto.SignedBlob{Info: info, Sig: sig}, nil
}

// RecoverIdentity decrypts an OTBottle with the escrow entropy -> the recovered old
// peer's P-384 keys. Wrong entropy/adsid derives the wrong key and the GCM tag rejects it.
func RecoverIdentity(b *OTBottle, entropy []byte, adsid string) (*RecoveredIdentity, error) {
	key, err := DeriveSymmetricKey(entropy, adsid)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(b.IV) == 0 {
		return nil, &Error{Msg: "bottle has no IV"}
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, len(b.IV))
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, b.IV, append(append([]byte{}, b.CT...), b.AuthCode...), nil)
	if err != nil {
		return nil, &Error{Msg: fmt.Sprintf("bottle AES-GCM decrypt failed: %v", err)}
	}
	// OTInternalBottle{ signingKey(3), encryptionKey(4) } of OTPrivateKey{ keyType(1), keyData(2) }
	f := proto.MustDecode(plaintext)
	signingX963 := proto.MustDecode(f.Bytes(3)).Bytes(2)
	encryptionX963 := proto.MustDecode(f.Bytes(4)).Bytes(2)
	signing, err := peerkey.LoadPeerKeyX963(signingX963)
	if err != nil {
		return nil, &Error{Msg: fmt.Sprintf("bottle signing key: %v", err)}
	}
	encryption, err := peerkey.LoadPeerKeyX963(encryptionX963)
	if err != nil {
		return nil, &Error{Msg: fmt.Sprintf("bottle encryption key: %v", err)}
	}
	return &RecoveredIdentity{PeerID: b.PeerID, Signing: signing, Encryption: encryption}, nil
}

// Package keychain holds the iCloud Keychain decryption primitives (SF-ECIES over
// P-384 with the X9.63 KDF and AES-256-GCM, AES-256-SIV key unwrap) and the pipeline
// that turns CKKS records into credentials. See RESEARCH.md stage 5.
package keychain

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

// X963KDF is the ANSI X9.63 key derivation function.
func X963KDF(secret, sharedInfo []byte, length int, hf func() hash.Hash) []byte {
	if hf == nil {
		hf = sha256.New
	}
	var out []byte
	var counter [4]byte
	for i := uint32(1); len(out) < length; i++ {
		binary.BigEndian.PutUint32(counter[:], i)
		h := hf()
		h.Write(secret)
		h.Write(counter[:])
		h.Write(sharedInfo)
		out = h.Sum(out)
	}
	return out[:length]
}

// ECIESDecrypt performs ECDH(P-384) -> X9.63-KDF(SHA-256, sharedInfo = ephemeral pubkey)
// -> AES-256-GCM with a 16-byte IV.
func ECIESDecrypt(priv *ecdh.PrivateKey, ephemeralPub, ciphertext, authCode []byte) ([]byte, error) {
	eph, err := ecdh.P384().NewPublicKey(ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("ecies: bad ephemeral key: %w", err)
	}
	secret, err := priv.ECDH(eph)
	if err != nil {
		return nil, err
	}
	derived := X963KDF(secret, ephemeralPub, 48, nil)
	block, err := aes.NewCipher(derived[:32])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, derived[32:48], append(append([]byte{}, ciphertext...), authCode...), nil)
}

// ECIESDecryptSF decrypts an Apple IESCiphertext dict (unarchived from a TLKShare
// wrappedkey). SecurityFoundation appends 97+16 bytes of junk to the stored ciphertext.
func ECIESDecryptSF(priv *ecdh.PrivateKey, ies map[string]any) ([]byte, error) {
	eph, _ := ies["SFEphemeralSenderPublicKeyExternaRepresentation"].([]byte)
	ct, _ := ies["SFCiphertext"].([]byte)
	tag, _ := ies["SFIESAuthenticationCode"].([]byte)
	if eph == nil || ct == nil || tag == nil {
		return nil, errors.New("ecies: IESCiphertext missing fields")
	}
	if len(ct) > 97+16 {
		ct = ct[:len(ct)-(97+16)]
	}
	return ECIESDecrypt(priv, eph, ct, tag)
}

// SIVUnwrap decrypts a wrapped key with a 64-byte AES-SIV key and no associated data.
func SIVUnwrap(key64, wrapped []byte) ([]byte, error) {
	return SIVOpen(key64, wrapped, nil)
}

// ErrPadding is returned for malformed ISO 7816-4 padding.
var ErrPadding = errors.New("bad ISO-7816-4 padding")

func stripISO7816(data []byte) ([]byte, error) {
	for i := len(data) - 1; i >= 0; i-- {
		switch data[i] {
		case 0x00:
			continue
		case 0x80:
			return data[:i], nil
		default:
			return nil, ErrPadding
		}
	}
	return data, nil
}

// DecryptItem decrypts an item record's data (= randomIV(16) || SIV(tag||ciphertext)).
// The leading random IV is prepended as the first associated-data element.
func DecryptItem(itemKey64, data []byte, aad [][]byte) ([]byte, error) {
	if len(data) < 16 {
		return nil, errors.New("item data too short")
	}
	headers := append([][]byte{data[:16]}, aad...)
	plaintext, err := SIVOpen(itemKey64, data[16:], headers)
	if err != nil {
		return nil, err
	}
	return stripISO7816(plaintext)
}

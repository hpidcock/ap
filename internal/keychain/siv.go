package keychain

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
)

// AES-SIV (RFC 5297) decryption with AES-CMAC (RFC 4493), as used by CKKS for key
// wrapping and item encryption. Keys are 2*n bytes: the first half keys S2V, the second
// half CTR.

// ErrSIVAuth is returned when the synthetic IV does not match.
var ErrSIVAuth = errors.New("aes-siv: authentication failed")

func dbl(b []byte) []byte {
	out := make([]byte, 16)
	var carry byte
	for i := 15; i >= 0; i-- {
		out[i] = b[i]<<1 | carry
		carry = b[i] >> 7
	}
	if carry != 0 {
		out[15] ^= 0x87
	}
	return out
}

type cmac struct {
	c      cipher.Block
	k1, k2 []byte
}

func newCMAC(key []byte) (*cmac, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	zero := make([]byte, 16)
	l := make([]byte, 16)
	c.Encrypt(l, zero)
	k1 := dbl(l)
	k2 := dbl(k1)
	return &cmac{c: c, k1: k1, k2: k2}, nil
}

func (m *cmac) sum(msg []byte) []byte {
	n := (len(msg) + 15) / 16
	var last [16]byte
	complete := n > 0 && len(msg)%16 == 0
	if n == 0 {
		n = 1
	}
	if complete {
		copy(last[:], msg[(n-1)*16:])
		for i := range last {
			last[i] ^= m.k1[i]
		}
	} else {
		rem := msg[(n-1)*16:]
		copy(last[:], rem)
		last[len(rem)] = 0x80
		for i := range last {
			last[i] ^= m.k2[i]
		}
	}
	x := make([]byte, 16)
	y := make([]byte, 16)
	for i := 0; i < n-1; i++ {
		for j := 0; j < 16; j++ {
			y[j] = x[j] ^ msg[i*16+j]
		}
		m.c.Encrypt(x, y)
	}
	for j := 0; j < 16; j++ {
		y[j] = x[j] ^ last[j]
	}
	m.c.Encrypt(x, y)
	return x
}

func s2v(m *cmac, ad [][]byte, plaintext []byte) []byte {
	zero := make([]byte, 16)
	d := m.sum(zero)
	for _, s := range ad {
		d = dbl(d)
		t := m.sum(s)
		for i := range d {
			d[i] ^= t[i]
		}
	}
	var t []byte
	if len(plaintext) >= 16 {
		t = append([]byte{}, plaintext...)
		off := len(t) - 16
		for i := 0; i < 16; i++ {
			t[off+i] ^= d[i]
		}
	} else {
		d = dbl(d)
		padded := make([]byte, 16)
		copy(padded, plaintext)
		padded[len(plaintext)] = 0x80
		t = make([]byte, 16)
		for i := range t {
			t[i] = d[i] ^ padded[i]
		}
	}
	return m.sum(t)
}

// SIVOpen decrypts `siv(16) || ciphertext` under a 2n-byte key with the given
// associated-data vector.
func SIVOpen(key, data []byte, ad [][]byte) ([]byte, error) {
	if len(key) != 32 && len(key) != 48 && len(key) != 64 {
		return nil, errors.New("aes-siv: key must be 32, 48 or 64 bytes")
	}
	if len(data) < 16 {
		return nil, errors.New("aes-siv: ciphertext too short")
	}
	half := len(key) / 2
	mac, err := newCMAC(key[:half])
	if err != nil {
		return nil, err
	}
	ctr, err := aes.NewCipher(key[half:])
	if err != nil {
		return nil, err
	}
	v := data[:16]
	q := make([]byte, 16)
	copy(q, v)
	q[8] &= 0x7f
	q[12] &= 0x7f
	plaintext := make([]byte, len(data)-16)
	cipher.NewCTR(ctr, q).XORKeyStream(plaintext, data[16:])
	expected := s2v(mac, ad, plaintext)
	if subtle.ConstantTimeCompare(expected, v) != 1 {
		return nil, ErrSIVAuth
	}
	return plaintext, nil
}

// SIVSeal is the inverse of SIVOpen (used by tests).
func SIVSeal(key, plaintext []byte, ad [][]byte) ([]byte, error) {
	half := len(key) / 2
	mac, err := newCMAC(key[:half])
	if err != nil {
		return nil, err
	}
	ctr, err := aes.NewCipher(key[half:])
	if err != nil {
		return nil, err
	}
	v := s2v(mac, ad, plaintext)
	q := make([]byte, 16)
	copy(q, v)
	q[8] &= 0x7f
	q[12] &= 0x7f
	out := make([]byte, 16+len(plaintext))
	copy(out, v)
	cipher.NewCTR(ctr, q).XORKeyStream(out[16:], plaintext)
	return out, nil
}

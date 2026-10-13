// Package srp implements the SRP-6a client variant Apple's GrandSlam (gsa.apple.com)
// and idmsa web sign-in use: the RFC 5054 2048-bit group, SHA-256, k = H(PAD(N)||PAD(g)),
// u = H(PAD(A)||PAD(B)), and the username left out of x. It reproduces the pysrp
// library's byte conventions exactly (trimmed big-endian integers in M1/M2/K, the inner
// identity hash stripped of leading zero bytes in x) since that is what the upstream
// clients were validated against.
package srp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"math/big"
)

// NHex is the RFC 5054 2048-bit prime.
const NHex = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4" +
	"A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF60" +
	"95179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF" +
	"747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B907" +
	"8717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861" +
	"60279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DB" +
	"FBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"

var (
	// N is the group prime, G the generator.
	N, _ = new(big.Int).SetString(NHex, 16)
	G    = big.NewInt(2)
	// NLen is the modulus length in bytes (256).
	NLen = (N.BitLen() + 7) / 8
)

// ErrBadServerValue is returned when the server's B fails the SRP-6a safety checks.
var ErrBadServerValue = errors.New("srp: invalid server public value")

// Pad left-pads x to the modulus length (PAD() in RFC 5054).
func Pad(x *big.Int) []byte {
	out := make([]byte, NLen)
	x.FillBytes(out)
	return out
}

// Trim is the minimal big-endian encoding (pysrp's long_to_bytes; 0 -> "" like pysrp).
func Trim(x *big.Int) []byte {
	if x.Sign() == 0 {
		return []byte{}
	}
	return x.Bytes()
}

func h(parts ...[]byte) []byte {
	d := sha256.New()
	for _, p := range parts {
		d.Write(p)
	}
	return d.Sum(nil)
}

// Client is one SRP exchange.
type Client struct {
	I       []byte // identity used in M1 (H(I)); NOT part of x
	a       *big.Int
	A       *big.Int
	K       []byte
	M1      []byte
	HAMK    []byte
	checked bool
}

// NewClient starts an exchange for identity I with a random 32-byte ephemeral secret.
func NewClient(I string) (*Client, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return NewClientWithSecret(I, buf), nil
}

// NewClientWithSecret is NewClient with a caller-supplied ephemeral secret (tests).
func NewClientWithSecret(I string, secret []byte) *Client {
	a := new(big.Int).SetBytes(secret)
	return &Client{I: []byte(I), a: a, A: new(big.Int).Exp(G, a, N)}
}

// PublicA is A trimmed (what GSA's A2k carries).
func (c *Client) PublicA() []byte { return Trim(c.A) }

// PublicAPadded is A as a fixed 256-byte value (what idmsa's signin/init carries).
func (c *Client) PublicAPadded() []byte { return Pad(c.A) }

// K returns H(PAD(N)||PAD(g)) as an integer.
func kValue() *big.Int {
	return new(big.Int).SetBytes(h(Pad(N), Pad(G)))
}

// HNxorg is H(N) XOR H(PAD(g)) with N trimmed and g padded to len(N) (pysrp rfc5054 mode).
func HNxorg() []byte {
	hN := h(Trim(N))
	gPad := make([]byte, NLen-len(Trim(G)))
	hg := h(append(gPad, Trim(G)...))
	out := make([]byte, len(hN))
	for i := range hN {
		out[i] = hN[i] ^ hg[i]
	}
	return out
}

// ProcessChallenge derives the session key K and proof M1 from the salt, the server's
// B and the pre-derived password material p. x = H(salt || trim(H(":" || p))).
func (c *Client) ProcessChallenge(salt, bBytes, p []byte) ([]byte, error) {
	B := new(big.Int).SetBytes(bBytes)
	if new(big.Int).Mod(B, N).Sign() == 0 {
		return nil, ErrBadServerValue
	}
	u := new(big.Int).SetBytes(h(Pad(c.A), Pad(B)))
	if u.Sign() == 0 {
		return nil, ErrBadServerValue
	}
	inner := new(big.Int).SetBytes(h(append([]byte(":"), p...)))
	x := new(big.Int).SetBytes(h(salt, Trim(inner)))
	v := new(big.Int).Exp(G, x, N)
	k := kValue()
	// S = (B - k*v)^(a + u*x) mod N
	base := new(big.Int).Sub(B, new(big.Int).Mul(k, v))
	base.Mod(base, N)
	exp := new(big.Int).Add(c.a, new(big.Int).Mul(u, x))
	S := new(big.Int).Exp(base, exp, N)
	c.K = h(Trim(S))
	c.M1 = h(HNxorg(), h(c.I), salt, Trim(c.A), Trim(B), c.K)
	c.HAMK = h(Trim(c.A), c.M1, c.K)
	return c.M1, nil
}

// VerifyServer checks the server's M2 proof.
func (c *Client) VerifyServer(m2 []byte) bool {
	if c.HAMK == nil {
		return false
	}
	c.checked = subtle.ConstantTimeCompare(c.HAMK, m2) == 1
	return c.checked
}

// SessionKey returns K.
func (c *Client) SessionKey() []byte { return c.K }

// ExpectedM2 returns the server proof the client expects (tests).
func (c *Client) ExpectedM2() []byte { return c.HAMK }

// DeriveKey is HMAC-SHA256(K, name), GSA's sub-key derivation for the spd envelope.
func DeriveKey(K []byte, name string) []byte {
	m := hmac.New(sha256.New, K)
	m.Write([]byte(name))
	return m.Sum(nil)
}

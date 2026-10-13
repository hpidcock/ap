package srp

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"testing"
)

// A minimal pysrp-convention server to prove the client completes mutual auth.
type server struct {
	I, salt []byte
	v, b, B *big.Int
}

func newServer(I string, p, salt []byte) *server {
	inner := new(big.Int).SetBytes(h(append([]byte(":"), p...)))
	x := new(big.Int).SetBytes(h(salt, Trim(inner)))
	v := new(big.Int).Exp(G, x, N)
	b := big.NewInt(123456789)
	k := kValue()
	B := new(big.Int).Add(new(big.Int).Mul(k, v), new(big.Int).Exp(G, b, N))
	B.Mod(B, N)
	return &server{I: []byte(I), salt: salt, v: v, b: b, B: B}
}

func (s *server) finish(aBytes, m1 []byte) ([]byte, bool) {
	A := new(big.Int).SetBytes(aBytes)
	u := new(big.Int).SetBytes(h(Pad(A), Pad(s.B)))
	S := new(big.Int).Exp(new(big.Int).Mul(A, new(big.Int).Exp(s.v, u, N)), s.b, N)
	K := h(Trim(S))
	expect := h(HNxorg(), h(s.I), s.salt, Trim(A), Trim(s.B), K)
	if !bytes.Equal(expect, m1) {
		return nil, false
	}
	return h(Trim(A), m1, K), true
}

func TestGroup(t *testing.T) {
	if N.BitLen() != 2048 || NLen != 256 {
		t.Fatalf("group: %d bits, %d bytes", N.BitLen(), NLen)
	}
}

func TestMutualAuth(t *testing.T) {
	salt := []byte("0123456789abcdef")
	p := sha256.New().Sum([]byte("derived password material"))
	srv := newServer("user@example.com", p, salt)
	c, err := NewClient("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	m1, err := c.ProcessChallenge(salt, Pad(srv.B), p)
	if err != nil {
		t.Fatal(err)
	}
	m2, ok := srv.finish(c.PublicA(), m1)
	if !ok {
		t.Fatal("server rejected M1")
	}
	if !c.VerifyServer(m2) {
		t.Fatal("client rejected M2")
	}
	if len(c.SessionKey()) != 32 {
		t.Fatal("session key length")
	}
	if len(c.PublicAPadded()) != 256 {
		t.Fatal("padded A length")
	}
}

func TestWrongPasswordFails(t *testing.T) {
	salt := []byte("saltsaltsaltsalt")
	srv := newServer("u", []byte("right"), salt)
	c := NewClientWithSecret("u", []byte{1, 2, 3, 4})
	m1, err := c.ProcessChallenge(salt, Pad(srv.B), []byte("wrong"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.finish(c.PublicA(), m1); ok {
		t.Fatal("wrong password accepted")
	}
}

func TestRejectsZeroB(t *testing.T) {
	c := NewClientWithSecret("u", []byte{5})
	if _, err := c.ProcessChallenge([]byte("s"), Pad(N), []byte("p")); err == nil {
		t.Fatal("B = N accepted")
	}
}

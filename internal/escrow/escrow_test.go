package escrow

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/hpidcock/ap/internal/peerkey"
	"github.com/hpidcock/ap/internal/proto"
)

func TestPackLayoutExact(t *testing.T) {
	m := &Message{Header: []byte("HHHH")}
	m.Section([]byte("AB"))
	m.Section([]byte("CDE"))
	packed := m.Pack()
	want, _ := hex.DecodeString("00000021" + "48484848" + "00000000" + "00000006" + "0000000d" +
		"00000002" + "4142" + "00000003" + "434445")
	if !bytes.Equal(packed, want) {
		t.Fatalf("packed %x\nwant   %x", packed, want)
	}
	hdr, secs, err := UnpackMessage(packed, 4, 2)
	if err != nil || string(hdr) != "HHHH" || string(secs[0]) != "AB" || string(secs[1]) != "CDE" {
		t.Fatalf("unpack: %q %q %v", hdr, secs, err)
	}
}

func TestSectionSized(t *testing.T) {
	m := &Message{Header: make([]byte, 24)}
	if err := m.SectionSized([]byte("id"), 20); err != nil {
		t.Fatal(err)
	}
	m.Section([]byte("proof"))
	_, secs, err := UnpackMessage(m.Pack(), 24, 2)
	if err != nil || string(secs[0]) != "id" || string(secs[1]) != "proof" {
		t.Fatalf("%q %v", secs, err)
	}
	if err := (&Message{}).SectionSized([]byte("toolong"), 4); err == nil {
		t.Fatal("expected size error")
	}
}

// Known-answer test from the upstream suite: fixed a, username, password, salt, b.
func TestSRPKnownAnswer(t *testing.T) {
	a := make([]byte, 32)
	a[31] = 5
	username, password := []byte("1234567890"), []byte("0000")
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i)
	}
	// server side by hand
	x := new(big.Int).SetBytes(h(salt, h(append(append(append([]byte{}, username...), ':'), password...))))
	v := new(big.Int).Exp(G, x, N)
	k := new(big.Int).SetBytes(h(pad(N), pad(G)))
	B := new(big.Int).Add(new(big.Int).Mul(k, v), new(big.Int).Exp(G, big.NewInt(7), N))
	B.Mod(B, N)

	c := NewSRPClient(a)
	K, M1 := c.Process(username, password, salt, trim(B))
	if hex.EncodeToString(K) != "2d19ff43e3713fa1e0e46215140438f4cead8a97d1f0078c0e4d082a6879fad8" {
		t.Fatalf("K = %x", K)
	}
	if hex.EncodeToString(M1) != "f4e679ce9d938ce6a6532f3f94e685c137f96754b7a6d4947777380469ffdd20" {
		t.Fatalf("M1 = %x", M1)
	}
	// padded vs trimmed B give the same answers
	K2, M12 := c.Process(username, password, salt, pad(B))
	if !bytes.Equal(K, K2) || !bytes.Equal(M1, M12) {
		t.Fatal("B padding changed the result")
	}
}

func TestRequestShape(t *testing.T) {
	r := NewRecovery("https://h/", "me@icloud.com", "PET", nil)
	req := r.Request("srp_init", "the-label", "TXN", map[string]any{"blob": "QUJD", "dsid": nil})
	if req["command"] != "SRP_INIT" || req["label"] != "the-label" || req["transactionUUID"] != "TXN" ||
		req["version"] != 1 || req["blob"] != "QUJD" || req["userActionLabel"] != UserAction {
		t.Fatalf("%v", req)
	}
	if _, ok := req["dsid"]; ok {
		t.Fatal("nil extras must be dropped")
	}
	if CommandVariant["get_records"] != "GETRECORDS" || CommandVariant["get_club_cert"] != "GETCLUB" {
		t.Fatal("command variants")
	}
	if _, err := r.TryRecoverEscrow("label", []byte("123456"), false); err == nil {
		t.Fatal("recovery must refuse without confirmation")
	}
}

func TestHeaders(t *testing.T) {
	r := NewRecovery("https://h", "e", "p", nil)
	h, err := r.Headers()
	if err != nil {
		t.Fatal(err)
	}
	if h["Content-Type"] != "application/x-apple-plst" || h["User-Agent"] != "com.apple.sbd/638.100.48 com.apple.iCloudHelper/282" ||
		h["X-Mme-Client-Info"] != "<MacBookPro18,3> <macOS;13.4.1;22F8> <com.apple.AuthKit/1 (com.apple.sbd/638.100.48)>" {
		t.Fatalf("%v", h)
	}
}

func TestListRecordsParsesMetadata(t *testing.T) {
	r := NewRecovery("https://h", "e", "p", nil)
	var gotCmd, gotBody string
	r.Invoke = func(command string, request map[string]any) (map[string]any, error) {
		gotCmd, gotBody = command, request["command"].(string)
		return map[string]any{"metadataList": []any{
			map[string]any{"label": "bottle-1", "metadata": "PD94bWwgdmVyc2lvbj0iMS4wIj8+PHBsaXN0IHZlcnNpb249IjEuMCI+PGRpY3Q+PGtleT5zZXJpYWw8L2tleT48c3RyaW5nPkMwMlhZWjwvc3RyaW5nPjwvZGljdD48L3BsaXN0Pg=="},
			map[string]any{"label": "bottle-2"},
		}}, nil
	}
	out, err := r.ListRecords()
	if err != nil {
		t.Fatal(err)
	}
	if gotCmd != "get_records" || gotBody != "GETRECORDS" {
		t.Fatalf("%s %s", gotCmd, gotBody)
	}
	if len(out) != 2 || out[0].Meta["serial"] != "C02XYZ" || len(out[1].Meta) != 0 {
		t.Fatalf("%+v", out)
	}
}

func buildBottle(t *testing.T, entropy []byte, adsid, peerID string, signing, encryption *peerkey.PeerKey) *OTBottle {
	t.Helper()
	otpriv := func(k *peerkey.PeerKey) []byte {
		return new(proto.Writer).Uint64(1, 1).Bytes(2, k.PrivateX963()).Finish()
	}
	internal := new(proto.Writer).Message(3, otpriv(signing)).Message(4, otpriv(encryption)).Finish()
	sym, err := DeriveSymmetricKey(entropy, adsid)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(sym)
	gcm, _ := cipher.NewGCMWithNonceSize(block, 32)
	iv := make([]byte, 32)
	rand.Read(iv)
	blob := gcm.Seal(nil, iv, internal, nil)
	sk, _ := DeriveECPrivateKey(entropy, adsid, InfoSigning)
	ek, _ := DeriveECPrivateKey(entropy, adsid, InfoEncryption)
	return &OTBottle{PeerID: peerID, BottleID: "bottle-uuid", EscrowedSigningKey: sk.PublicSPKI(),
		EscrowedEncryptionKey: ek.PublicSPKI(), CT: blob[:len(blob)-16], AuthCode: blob[len(blob)-16:], IV: iv}
}

func TestBottleRecovery(t *testing.T) {
	entropy := make([]byte, 72)
	rand.Read(entropy)
	adsid := "001385-10-AAAA"
	signing, _ := peerkey.GeneratePeerKey()
	encryption, _ := peerkey.GeneratePeerKey()
	bottle := buildBottle(t, entropy, adsid, "SHA256:oldpeer", signing, encryption)

	parsed, err := ParseOTBottle(bottle.Encode())
	if err != nil {
		t.Fatal(err)
	}
	rec, err := RecoverIdentity(parsed, entropy, adsid)
	if err != nil {
		t.Fatal(err)
	}
	if rec.PeerID != "SHA256:oldpeer" || !bytes.Equal(rec.Signing.PrivateX963(), signing.PrivateX963()) ||
		!bytes.Equal(rec.Encryption.PrivateX963(), encryption.PrivateX963()) {
		t.Fatal("recovered keys differ")
	}
	wrong := make([]byte, 72)
	rand.Read(wrong)
	if _, err := RecoverIdentity(parsed, wrong, adsid); err == nil {
		t.Fatal("wrong entropy accepted")
	}
	if _, err := RecoverIdentity(parsed, entropy, "other"); err == nil {
		t.Fatal("wrong adsid accepted")
	}

	voucher, err := rec.MakeVoucher("SHA256:newpeer", 1)
	if err != nil {
		t.Fatal(err)
	}
	vf := proto.MustDecode(voucher.Info)
	if vf.Uint64(1) != 1 || vf.String(2) != "SHA256:newpeer" || vf.String(3) != "SHA256:oldpeer" {
		t.Fatalf("voucher %+v", vf)
	}
	if !signing.VerifySHA384(peerkey.PrefixedData(voucher.Info, peerkey.VoucherSigType), voucher.Sig) {
		t.Fatal("voucher signature invalid")
	}
	if signing.VerifySHA384(voucher.Info, voucher.Sig) {
		t.Fatal("voucher signature must be over the prefixed data")
	}
}

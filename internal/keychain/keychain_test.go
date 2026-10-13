package keychain

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"howett.net/plist"

	"github.com/hpidcock/ap/internal/cloudkit"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestX963KDFVector(t *testing.T) {
	out := X963KDF(mustHex("96c05619d56c328ab95fe84b18264b08725b85e33fd34f08"), nil, 16, nil)
	if hex.EncodeToString(out) != "443024c3dae66b95e6f5670601558f71" {
		t.Fatalf("got %x", out)
	}
	long := X963KDF([]byte("secret"), []byte("info"), 48, nil)
	if len(long) != 48 || !bytes.Equal(long[:32], X963KDF([]byte("secret"), []byte("info"), 32, nil)) {
		t.Fatal("length/counter behaviour")
	}
}

// RFC 5297 A.1 deterministic authenticated encryption example.
func TestSIVRFC5297(t *testing.T) {
	key := mustHex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	ad := mustHex("101112131415161718191a1b1c1d1e1f2021222324252627")
	plaintext := mustHex("112233445566778899aabbccddee")
	want := mustHex("85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c")
	got, err := SIVSeal(key, plaintext, [][]byte{ad})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("seal = %x, want %x", got, want)
	}
	back, err := SIVOpen(key, want, [][]byte{ad})
	if err != nil || !bytes.Equal(back, plaintext) {
		t.Fatalf("open = %x, %v", back, err)
	}
	want[20] ^= 1
	if _, err := SIVOpen(key, want, [][]byte{ad}); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}

// RFC 5297 A.2 nonce-based example (3 associated-data elements, plaintext > 16 bytes).
func TestSIVRFC5297Nonce(t *testing.T) {
	key := mustHex("7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f")
	ad1 := mustHex("00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100")
	ad2 := mustHex("102030405060708090a0")
	nonce := mustHex("09f911029d74e35bd84156c5635688c0")
	plaintext := []byte("this is some plaintext to encrypt using SIV-AES")
	want := mustHex("7bdb6e3b432667eb06f4d14bff2fbd0fcb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d")
	got, err := SIVSeal(key, plaintext, [][]byte{ad1, ad2, nonce})
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("seal = %x (%v)", got, err)
	}
}

func TestECIESRoundTrip(t *testing.T) {
	recipient, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	eph, _ := ecdh.P384().GenerateKey(rand.Reader)
	secret, _ := eph.ECDH(recipient.PublicKey())
	ephPub := eph.PublicKey().Bytes()
	derived := X963KDF(secret, ephPub, 48, nil)
	block, _ := aes.NewCipher(derived[:32])
	gcm, _ := cipher.NewGCMWithNonceSize(block, 16)
	sealed := gcm.Seal(nil, derived[32:48], []byte("the tlk"), nil)
	ct, tag := sealed[:len(sealed)-16], sealed[len(sealed)-16:]
	out, err := ECIESDecrypt(recipient, ephPub, ct, tag)
	if err != nil || string(out) != "the tlk" {
		t.Fatalf("%q %v", out, err)
	}
	// the SF dict form appends 97+16 bytes of junk after the ciphertext
	junk := make([]byte, 97+16)
	ies := map[string]any{
		"SFEphemeralSenderPublicKeyExternaRepresentation": ephPub,
		"SFCiphertext":            append(append([]byte{}, ct...), junk...),
		"SFIESAuthenticationCode": tag,
	}
	out, err = ECIESDecryptSF(recipient, ies)
	if err != nil || string(out) != "the tlk" {
		t.Fatalf("SF: %q %v", out, err)
	}
}

func TestDecryptItemPadding(t *testing.T) {
	key := make([]byte, 64)
	rand.Read(key)
	iv := make([]byte, 16)
	rand.Read(iv)
	padded := append([]byte("hello"), 0x80, 0, 0, 0)
	sealed, err := SIVSeal(key, padded, [][]byte{iv, []byte("aad")})
	if err != nil {
		t.Fatal(err)
	}
	out, err := DecryptItem(key, append(iv, sealed...), [][]byte{[]byte("aad")})
	if err != nil || string(out) != "hello" {
		t.Fatalf("%q %v", out, err)
	}
}

func TestAuthenticatedDataV2(t *testing.T) {
	fields := map[string]any{"parentkeyref": "CLASSC", "encver": int64(2), "gen": int64(0),
		"pcsservice": int64(5), "pcspublicidentity": []byte("ident"), "pcspublickey": []byte("pub"),
		"wrappedkey": "ignored", "data": []byte("ignored"), "cdat": cloudkit.Date{Time: 1687305600},
		"score": 3.9, "n": int64(-1)}
	aad := AuthenticatedDataV2("UUID-x", fields, 2, 0, "CLASSC")
	has := func(want []byte) bool {
		for _, a := range aad {
			if bytes.Equal(a, want) {
				return true
			}
		}
		return false
	}
	for _, want := range [][]byte{[]byte("ident"), []byte("pub"), cloudkit.LE8(5), []byte("2023-06-21T00:00:00Z"),
		cloudkit.LE8(3), bytes.Repeat([]byte{0xff}, 8), []byte("UUID-x"), []byte("CLASSC")} {
		if !has(want) {
			t.Errorf("aad missing %q", want)
		}
	}
	if has([]byte("ignored")) {
		t.Error("excluded fields leaked into the aad")
	}
}

func TestExpandKeyedArchive(t *testing.T) {
	objects := []any{"$null",
		map[string]any{"$classname": "NSMutableData", "$classes": []any{"NSMutableData", "NSData", "NSObject"}},
		[]byte{4, 0xab, 0xab},
		map[string]any{"$class": plist.UID(1), "NS.data": plist.UID(2)},
		map[string]any{"SFEphemeralSenderPublicKeyExternaRepresentation": plist.UID(3), "plain": "x"},
	}
	raw, err := plist.Marshal(map[string]any{"$version": 100000, "$archiver": "NSKeyedArchiver",
		"$top": map[string]any{"root": plist.UID(4)}, "$objects": objects}, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	out, err := ExpandKeyedArchive(raw)
	if err != nil {
		t.Fatal(err)
	}
	m := out.(map[string]any)
	if !bytes.Equal(m["SFEphemeralSenderPublicKeyExternaRepresentation"].([]byte), []byte{4, 0xab, 0xab}) || m["plain"] != "x" {
		t.Fatalf("%+v", m)
	}
}

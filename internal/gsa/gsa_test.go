package gsa

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"testing"

	"github.com/hpidcock/ap/internal/plistx"
	"github.com/hpidcock/ap/internal/srp"
)

func TestEncryptPassword(t *testing.T) {
	salt := []byte("0123456789abcdef")
	a, _ := EncryptPassword("hunter2", salt, 1000, "s2k")
	b, _ := EncryptPassword("hunter2", salt, 1000, "s2k_fo")
	if len(a) != 32 || len(b) != 32 || hex.EncodeToString(a) == hex.EncodeToString(b) {
		t.Fatal("s2k and s2k_fo must differ and be 32 bytes")
	}
	a2, _ := EncryptPassword("hunter2", salt, 1000, "s2k")
	if hex.EncodeToString(a) != hex.EncodeToString(a2) {
		t.Fatal("deterministic")
	}
}

func TestDecryptCBC(t *testing.T) {
	K := make([]byte, 32)
	for i := range K {
		K[i] = byte(i)
	}
	key := srp.DeriveKey(K, "extra data key:")
	iv := srp.DeriveKey(K, "extra data iv:")[:16]
	plain, _ := plistx.EncodeXML(map[string]any{"adsid": "X"})
	pad := 16 - len(plain)%16
	for i := 0; i < pad; i++ {
		plain = append(plain, byte(pad))
	}
	block, _ := aes.NewCipher(key)
	ct := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, plain)
	out, err := decryptCBC(K, ct)
	if err != nil {
		t.Fatal(err)
	}
	spd, err := plistx.Decode(out)
	if err != nil || spd["adsid"] != "X" {
		t.Fatalf("%v %v", spd, err)
	}
}

func TestExtractPET(t *testing.T) {
	spd := map[string]any{"adsid": "001-2", "t": map[string]any{"com.apple.gs.idms.pet": map[string]any{"token": "PET", "expiry": uint64(5)}}}
	dsid, pet, exp, err := ExtractPET(spd)
	if err != nil || dsid != "001-2" || pet != "PET" || exp != 5 {
		t.Fatalf("%s %s %d %v", dsid, pet, exp, err)
	}
	if _, _, _, err := ExtractPET(map[string]any{}); err == nil {
		t.Fatal("missing PET must fail")
	}
}

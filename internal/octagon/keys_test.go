package octagon

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"testing"
)

// Apple's own TrustedPeersHelper unit-test vector for TPHashBuilder.
const (
	policy1B64 = "CAESDgoGaVBob25lEgRmdWxsEgwKBGlQYWQSBGZ1bGwSCwoDTWFjEgRmdWxsEgwKBGlNYWMSBGZ1bGwSDQoHQXBwbGVUVhICdHYS" +
		"DgoFV2F0Y2gSBXdhdGNoGhEKCVBDU0VzY3JvdxIEZnVsbBoXCgRXaUZpEgRmdWxsEgJ0dhIFd2F0Y2gaGQoRU2FmYXJpQ3JlZGl0" +
		"Q2FyZHMSBGZ1bGwiDAoEZnVsbBIEZnVsbCIUCgV3YXRjaBIEZnVsbBIFd2F0Y2giDgoCdHYSBGZ1bGwSAnR2"
	policy1Hash = "SHA256:TLXrcQmY4ue3oP5pCX1pwsi9BF8cKfohlJBilCroeBs="
)

func TestTPHashAppleVector(t *testing.T) {
	data, _ := base64.StdEncoding.DecodeString(policy1B64)
	if got := TPHash(data, "SHA256"); got != policy1Hash {
		t.Fatalf("tphash = %s", got)
	}
	if DerivePeerID([]byte("data"), []byte("sig")) != TPHash([]byte("datasig"), "SHA256") {
		t.Fatal("peerID must hash data||sig")
	}
	if TPHash([]byte("x"), "SHA384")[:7] != "SHA384:" {
		t.Fatal("sha384 prefix")
	}
}

func TestPeerKeyEncodings(t *testing.T) {
	k, err := GeneratePeerKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := k.PublicX963()
	if len(pub) != 97 || pub[0] != 4 {
		t.Fatalf("public x963 %d bytes", len(pub))
	}
	priv := k.PrivateX963()
	if len(priv) != 145 || !bytes.Equal(priv[:97], pub) {
		t.Fatalf("private x963 %d bytes", len(priv))
	}
	back, err := LoadPeerKeyX963(priv)
	if err != nil || !bytes.Equal(back.PrivateX963(), priv) {
		t.Fatalf("round trip: %v", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(k.PublicSPKI())
	if err != nil {
		t.Fatal(err)
	}
	_ = parsed
	sig, err := k.SignSHA384([]byte("msg"))
	if err != nil || !k.VerifySHA384([]byte("msg"), sig) || k.VerifySHA384([]byte("other"), sig) {
		t.Fatal("sign/verify")
	}
	ks, _ := GeneratePeerKeySet()
	restored, err := PeerKeySetFromStorage(ks.ToStorage())
	if err != nil || !bytes.Equal(restored.Signing.PrivateX963(), ks.Signing.PrivateX963()) ||
		!bytes.Equal(restored.Encryption.PrivateX963(), ks.Encryption.PrivateX963()) {
		t.Fatal("storage round trip")
	}
}

func TestPermanentInfo(t *testing.T) {
	ks, _ := GeneratePeerKeySet()
	info, err := BuildPermanentInfo(ks, "ABCDEF0123456", "MacBookPro18,3", 1, 1700000000)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.PeerID) != len("SHA256:")+44 || info.PeerID != TPHash(append(append([]byte{}, info.Data...), info.Sig...), "SHA256") {
		t.Fatalf("peerID %s", info.PeerID)
	}
	if info.Data[0] != (1<<3)|0 {
		t.Fatal("epoch must be the first field")
	}
	if !ks.Signing.VerifySHA384(PrefixedData(info.Data, PermanentInfoSigType), info.Sig) ||
		ks.Signing.VerifySHA384(info.Data, info.Sig) {
		t.Fatal("signature must be over the prefixed data only")
	}
}

func TestStableAndDynamicInfo(t *testing.T) {
	ks, _ := GeneratePeerKeySet()
	st, err := BuildStableInfo(ks, StableInfoParams{Clock: 1, FrozenPolicyVersion: 1, FrozenPolicyHash: policy1Hash,
		FlexiblePolicyVersion: 1, FlexiblePolicyHash: policy1Hash, DeviceName: "Sank's Mac", SerialNumber: "C02XYZ123",
		OSVersion: "Mac OS X;13.4.1", UserControllableViews: UCVFollowing, SupportsRepudiation: true})
	if err != nil {
		t.Fatal(err)
	}
	p := ParseStableInfoData(st.Data)
	if p.Clock != 1 || p.DeviceName != "Sank's Mac" || p.SerialNumber != "C02XYZ123" || p.OSVersion != "Mac OS X;13.4.1" ||
		p.UserControllableViews != UCVFollowing || p.SupportsRepudiation == nil || !*p.SupportsRepudiation || p.FrozenPolicyHash != policy1Hash {
		t.Fatalf("%+v", p)
	}
	if !ks.Signing.VerifySHA384(PrefixedData(st.Data, StableInfoSigType), st.Sig) {
		t.Fatal("stable signature")
	}
	st2, _ := BuildStableInfo(ks, StableInfoParams{Clock: 2, FrozenPolicyHash: "x", FlexiblePolicyHash: "x"})
	if ParseStableInfoData(st2.Data).SupportsRepudiation != nil {
		t.Fatal("repudiation should be omitted")
	}

	dyn, err := BuildDynamicInfo(ks, 1, []string{"SHA256:A", "SHA256:B"}, []string{"SHA256:C"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	d := ParseDynamicInfoData(dyn.Data)
	if d.Clock != 1 || len(d.Included) != 2 || d.Included[0] != "SHA256:A" || len(d.Excluded) != 1 || dyn.Data[0] != 0x08 {
		t.Fatalf("%+v", d)
	}
	if !ks.Signing.VerifySHA384(PrefixedData(dyn.Data, DynamicInfoSigType), dyn.Sig) {
		t.Fatal("dynamic signature")
	}
}

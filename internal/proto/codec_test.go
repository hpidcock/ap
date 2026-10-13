package proto

import (
	"bytes"
	"testing"
)

func TestVarint(t *testing.T) {
	cases := map[uint64][]byte{0: {0x00}, 1: {0x01}, 300: {0xac, 0x02}}
	for v, want := range cases {
		if got := EncodeVarint(v); !bytes.Equal(got, want) {
			t.Errorf("EncodeVarint(%d) = %x, want %x", v, got, want)
		}
		back, n, err := ReadVarint(want)
		if err != nil || back != v || n != len(want) {
			t.Errorf("ReadVarint(%x) = %d,%d,%v", want, back, n, err)
		}
	}
}

func TestWriterRoundTrip(t *testing.T) {
	raw := new(Writer).Uint64(1, 7).String(2, "hi").Bytes(3, []byte{1, 2, 3}).Bool(4, true).Finish()
	if raw[0] != (1<<3)|0 {
		t.Fatalf("first tag %#x, want field 1 varint", raw[0])
	}
	f, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if f.Uint64(1) != 7 || f.String(2) != "hi" || !bytes.Equal(f.Bytes(3), []byte{1, 2, 3}) || f.Uint64(4) != 1 {
		t.Fatalf("decoded %+v", f)
	}
	if !f.Has(4) || f.Has(5) {
		t.Fatal("Has mismatch")
	}
}

func TestDecodeTruncated(t *testing.T) {
	if _, err := Decode([]byte{0x12, 0x05, 0x01}); err == nil {
		t.Fatal("expected truncation error")
	}
}

func TestEmptyBytesWritten(t *testing.T) {
	raw := new(Writer).Bytes(2, []byte{}).Finish()
	if !bytes.Equal(raw, []byte{0x12, 0x00}) {
		t.Fatalf("empty bytes field = %x", raw)
	}
	if raw := new(Writer).Bytes(2, nil).Finish(); len(raw) != 0 {
		t.Fatalf("nil bytes should be skipped, got %x", raw)
	}
}

func TestPeerAndVoucher(t *testing.T) {
	v := SignedBlob{Info: EncodeVoucher(1, "SHA256:new", "SHA256:old"), Sig: []byte("sig")}
	raw := EncodePeer("SHA256:me", SignedBlob{Info: []byte("p"), Sig: []byte("ps")},
		SignedBlob{Info: []byte("s"), Sig: []byte("ss")}, SignedBlob{Info: []byte("d"), Sig: []byte("ds")}, &v)
	p := ParsePeer(raw)
	if p.Hash != "SHA256:me" || string(p.PermanentInfo.Info) != "p" || string(p.StableInfo.Sig) != "ss" ||
		string(p.DynamicInfo.Info) != "d" || p.Voucher == nil {
		t.Fatalf("parsed %+v", p)
	}
	vf := MustDecode(p.Voucher.Info)
	if vf.Uint64(1) != 1 || vf.String(2) != "SHA256:new" || vf.String(3) != "SHA256:old" {
		t.Fatalf("voucher %+v", vf)
	}
}

func TestTLKShareRoundTrip(t *testing.T) {
	s := TLKShare{Service: "Passwords", Curve: 4, Epoch: 1, KeyID: "k", Poisoned: 0, Receiver: "r",
		ReceiverPublicEncryptionKey: "pk", Sender: "s", Signature: "sig", Version: 2, WrappedKey: "w"}
	if got := ParseTLKShare(s.Encode()); got != s {
		t.Fatalf("round trip %+v != %+v", got, s)
	}
}

func TestFetchChangesResponse(t *testing.T) {
	peer := EncodePeer("SHA256:x", SignedBlob{}, SignedBlob{}, SignedBlob{}, nil)
	change := new(Writer).Message(3, peer).Finish()
	changes := new(Writer).String(1, "tok").Message(2, change).Finish()
	raw := new(Writer).Message(1, changes).Finish()
	r := ParseFetchChangesResponse(raw)
	if r.SyncToken != "tok" || len(r.Peers) != 1 || r.Peers[0].Hash != "SHA256:x" {
		t.Fatalf("%+v", r)
	}
	if r := ParseFetchChangesResponse(nil); r.SyncToken != "" || len(r.Peers) != 0 {
		t.Fatalf("empty: %+v", r)
	}
}

func TestRecoverableTLKShares(t *testing.T) {
	rec := func(name string) []byte { return new(Writer).Bytes(2, []byte(name)).Finish() } // CuttlefishRecord{inner(2)}
	viewKeys := new(Writer).Message(1, rec("tlk")).Message(2, rec("a")).Message(3, rec("b")).Finish()
	grp := new(Writer).Message(2, viewKeys).Message(3, rec("share")).Finish()
	raw := new(Writer).Message(1, grp).Finish()
	out := ParseRecoverableTLKSharesResponse(raw)
	if len(out.ShareRecords) != 1 || string(out.ShareRecords[0]) != "share" || len(out.SyncKeyRecords) != 3 {
		t.Fatalf("%+v", out)
	}
}

func TestViableBottles(t *testing.T) {
	bottle := new(Writer).Bytes(2, []byte("otbottle")).Finish()
	ed := new(Writer).String(1, "bottle-1").Message(2, bottle).Finish()
	raw := new(Writer).Message(1, ed).Finish()
	bs := ParseViableBottles(raw)
	if len(bs) != 1 || bs[0].ID != "bottle-1" || string(bs[0].OTBottle) != "otbottle" {
		t.Fatalf("%+v", bs)
	}
}

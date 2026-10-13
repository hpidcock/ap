package cloudkit

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"

	"github.com/hpidcock/ap/internal/proto"
)

func TestDelimit(t *testing.T) {
	msgs, err := Undelimit(append(Delimit([]byte("abc")), Delimit([]byte("de"))...))
	if err != nil || len(msgs) != 2 || string(msgs[0]) != "abc" || string(msgs[1]) != "de" {
		t.Fatalf("%q %v", msgs, err)
	}
	gz, _ := MaybeGunzip([]byte("plain"))
	if string(gz) != "plain" {
		t.Fatal("non-gzip body must pass through")
	}
}

func TestParseValue(t *testing.T) {
	var d [8]byte
	binary.LittleEndian.PutUint64(d[:], math.Float64bits(2.5))
	raw := append([]byte{(5 << 3) | 1}, d[:]...)
	if v := parseValue(raw); v != 2.5 {
		t.Fatalf("double %v", v)
	}
	binary.LittleEndian.PutUint64(d[:], math.Float64bits(1687305600))
	inner := append([]byte{(1 << 3) | 1}, d[:]...)
	rawDate := append([]byte{(6 << 3) | 2, byte(len(inner))}, inner...)
	if v := parseValue(rawDate); v != (Date{Time: 1687305600}) {
		t.Fatalf("date %v", v)
	}
	// referenceValue -> record name
	ident := new(proto.Writer).String(1, "PARENT").Finish()
	rid := new(proto.Writer).Message(1, ident).Finish()
	ref := new(proto.Writer).Message(2, rid).Finish()
	if v := parseValue(new(proto.Writer).Message(9, ref).Finish()); v != "PARENT" {
		t.Fatalf("reference %v", v)
	}
	if v := parseValue(new(proto.Writer).Uint64(4, 7).Finish()); v != int64(7) {
		t.Fatalf("signed %v", v)
	}
}

func TestParseRecord(t *testing.T) {
	ident := func(name string) []byte { return new(proto.Writer).String(1, name).Finish() }
	field := func(name string, val []byte) []byte {
		return new(proto.Writer).Message(1, ident(name)).Message(2, val).Finish()
	}
	rid := new(proto.Writer).Message(1, ident("REC-1")).Finish()
	raw := new(proto.Writer).Message(2, rid).Message(3, ident("item")).
		Message(7, field("wrappedkey", new(proto.Writer).String(7, "w").Finish())).
		Message(7, field("data", new(proto.Writer).Bytes(2, []byte{9}).Finish())).Finish()
	rec := ParseRecord(raw)
	if rec.Name != "REC-1" || rec.Type != "item" || rec.Str("wrappedkey") != "w" || !bytes.Equal(rec.Bytes("data"), []byte{9}) {
		t.Fatalf("%+v", rec)
	}
	change := new(proto.Writer).Message(5, raw).Finish()
	page := ParseRetrieveChangesResponse(new(proto.Writer).Message(1, change).Bytes(2, []byte("tok")).Uint64(4, 1).Finish())
	if len(page.Records) != 1 || string(page.Continuation) != "tok" || page.Status != 1 {
		t.Fatalf("%+v", page)
	}
}

func TestHeaderAndOperation(t *testing.T) {
	hdr := BuildHeader(DeviceConfig{DeviceUUID: "UUID", Serial: "SER"}, CuttlefishContainer, CuttlefishBundle)
	f := proto.MustDecode(hdr)
	if f.String(2) != CuttlefishContainer || f.String(3) != CuttlefishBundle || f.String(33) != "SER" || f.String(21) != "Mac" || f.Uint64(35) != 1 {
		t.Fatalf("%+v", f)
	}
	op := BuildRequestOperation(hdr, 1101, 1101, []byte("req"))
	of := proto.MustDecode(op)
	if !of.Has(1) || !of.Has(2) || string(of.Bytes(1101)) != "req" {
		t.Fatal("operation framing")
	}
	if proto.MustDecode(of.Bytes(2)).Uint64(2) != 1101 {
		t.Fatal("operation type")
	}
}

func TestResponseOperationError(t *testing.T) {
	errMsg := new(proto.Writer).String(4, "boom").Finish()
	result := new(proto.Writer).Uint64(1, 2).Message(2, errMsg).Finish()
	res, err := ParseResponseOperation(new(proto.Writer).Message(3, result).Finish())
	if err != nil || res.OK() || res.ErrorDescription != "boom" {
		t.Fatalf("%+v %v", res, err)
	}
	ok, _ := ParseResponseOperation(new(proto.Writer).Message(1101, new(proto.Writer).Bytes(1, []byte("r")).Finish()).Finish())
	if !ok.OK() || string(ok.SerializedResult()) != "r" {
		t.Fatal("success parsing")
	}
}

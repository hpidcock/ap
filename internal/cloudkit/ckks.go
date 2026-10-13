package cloudkit

import (
	"encoding/binary"
	"math"

	"github.com/hpidcock/ap/internal/proto"
)

// CKKS record fetch: the iCloud Keychain zone records (tlkshare / synckey / item /
// currentitem) via a RecordRetrieveChanges op per zone.

// Date is a CloudKit Date value - kept distinct from a plain double so the item AAD
// encodes it as RFC3339 rather than as a number.
type Date struct {
	Time float64 // unix seconds
}

// KeychainZones are the private-DB CKKS zones. "Passwords" + "Manatee" hold web credentials.
var KeychainZones = []string{
	"Passwords", "Manatee", "Engram", "SecureObjectSync", "ProtectedCloudStorage",
	"CreditCards", "ApplePay", "WiFi", "Home", "Groups", "Contacts", "Mail",
	"LimitedPeersAllowed", "SE-PTC", "Photos",
}

const (
	idTypeRecordZone = 6
	idTypeUser       = 7

	// OpTypeRecordRetrieveChanges is the RecordRetrieveChanges operation type/field.
	OpTypeRecordRetrieveChanges = 213
	FieldRetrieveChanges        = 213
)

// RecordZoneIdentifier builds RecordZoneIdentifier{ zone(1), owner(2) }.
func RecordZoneIdentifier(zone, userID string) []byte {
	return new(proto.Writer).
		Message(1, Identifier(zone, idTypeRecordZone)).
		Message(2, Identifier(userID, idTypeUser)).Finish()
}

// BuildRetrieveChangesRequest builds the per-zone changes request.
func BuildRetrieveChangesRequest(zoneIdentifier, continuation []byte, maxChanges uint64) []byte {
	w := new(proto.Writer)
	if continuation != nil {
		w.Bytes(1, continuation)
	}
	return w.Message(2, zoneIdentifier).Uint64(4, maxChanges).Finish()
}

// Record is a parsed CloudKit record.
type Record struct {
	Name   string         // identifier value name (usually a UUID)
	Type   string         // "item" / "synckey" / "tlkshare" / "currentitem" / ...
	Fields map[string]any // string, []byte, int64, float64, Date
}

// Bytes returns a data field.
func (r Record) Bytes(name string) []byte {
	v, _ := r.Fields[name].([]byte)
	return v
}

// Str returns a string field.
func (r Record) Str(name string) string {
	v, _ := r.Fields[name].(string)
	return v
}

// parseValue decodes Record.Field.Value, preserving types for the item AAD.
func parseValue(raw []byte) any {
	v := proto.MustDecode(raw)
	switch {
	case v.Has(2):
		b := v.Bytes(2)
		if b == nil {
			b = []byte{}
		}
		return b // bytesValue
	case v.Has(7):
		return v.String(7) // stringValue
	case v.Has(4):
		return int64(v.Uint64(4)) // signedValue
	case v.Has(5):
		return math.Float64frombits(v.Uint64(5)) // doubleValue
	case v.Has(6): // dateValue: Date{ time(1): double }
		d := proto.MustDecode(v.Bytes(6))
		if d.Has(1) {
			return Date{Time: math.Float64frombits(d.Uint64(1))}
		}
	case v.Has(9): // referenceValue -> the target record's name (parentkeyref)
		ref := proto.MustDecode(v.Bytes(9))
		if ref.Has(2) {
			rid := proto.MustDecode(ref.Bytes(2))
			if rid.Has(1) {
				return proto.MustDecode(rid.Bytes(1)).String(1)
			}
		}
	}
	return nil
}

// ParseRecord decodes a Record protobuf.
func ParseRecord(raw []byte) Record {
	f := proto.MustDecode(raw)
	rec := Record{Fields: map[string]any{}}
	if f.Has(2) {
		rid := proto.MustDecode(f.Bytes(2))
		if rid.Has(1) {
			rec.Name = proto.MustDecode(rid.Bytes(1)).String(1)
		}
	}
	if f.Has(3) {
		rec.Type = proto.MustDecode(f.Bytes(3)).String(1)
	}
	for _, fld := range f.Repeated(7) {
		ff := proto.MustDecode(fld)
		if !ff.Has(1) || !ff.Has(2) {
			continue
		}
		name := proto.MustDecode(ff.Bytes(1)).String(1)
		if val := parseValue(ff.Bytes(2)); val != nil {
			rec.Fields[name] = val
		}
	}
	return rec
}

// ChangesPage is one RecordRetrieveChanges response. Status 1 means another page is
// available; 3 is the final state token for the zone.
type ChangesPage struct {
	Records      []Record
	Continuation []byte
	Status       uint64
}

// ParseRetrieveChangesResponse decodes a retrieveChangesResponse.
func ParseRetrieveChangesResponse(raw []byte) ChangesPage {
	f := proto.MustDecode(raw)
	page := ChangesPage{Continuation: f.Bytes(2), Status: f.Uint64(4)}
	for _, change := range f.Repeated(1) {
		cf := proto.MustDecode(change)
		if cf.Has(5) {
			page.Records = append(page.Records, ParseRecord(cf.Bytes(5)))
		}
	}
	return page
}

// LE8 is the 64-bit two's-complement little-endian encoding used in the item AAD.
func LE8(n int64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], uint64(n))
	return b[:]
}

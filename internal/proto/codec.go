// Package proto is a minimal protobuf wire codec - enough to build and parse the
// Cuttlefish and CloudKit messages - hand-rolled to keep byte-exact control over field
// ordering (Apple signs some of these blobs).
package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Wire types.
const (
	WTVarint = 0
	WTI64    = 1
	WTLen    = 2
	WTI32    = 5
)

// ErrTruncated is returned for malformed wire data.
var ErrTruncated = errors.New("proto: truncated message")

// EncodeVarint returns the uleb128 encoding of v.
func EncodeVarint(v uint64) []byte {
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			out = append(out, b|0x80)
		} else {
			return append(out, b)
		}
	}
}

// ReadVarint decodes a varint at the start of data.
func ReadVarint(data []byte) (uint64, int, error) {
	var val uint64
	var shift uint
	for i := 0; i < len(data); i++ {
		b := data[i]
		val |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return val, i + 1, nil
		}
		shift += 7
		if shift > 63 {
			return 0, 0, errors.New("proto: varint overflow")
		}
	}
	return 0, 0, ErrTruncated
}

func tag(field int, wire int) []byte {
	return EncodeVarint(uint64(field)<<3 | uint64(wire))
}

// Writer accumulates fields in call order. Emit fields in ascending field-number order
// when the output is going to be signed.
type Writer struct {
	buf []byte
}

// Uint64 appends a varint field.
func (w *Writer) Uint64(field int, v uint64) *Writer {
	w.buf = append(w.buf, tag(field, WTVarint)...)
	w.buf = append(w.buf, EncodeVarint(v)...)
	return w
}

// Bool appends a varint 0/1 field.
func (w *Writer) Bool(field int, v bool) *Writer {
	if v {
		return w.Uint64(field, 1)
	}
	return w.Uint64(field, 0)
}

// Bytes appends a length-delimited field. A nil slice is skipped (proto "unset"); an
// empty non-nil slice is written as a zero-length field.
func (w *Writer) Bytes(field int, v []byte) *Writer {
	if v == nil {
		return w
	}
	w.buf = append(w.buf, tag(field, WTLen)...)
	w.buf = append(w.buf, EncodeVarint(uint64(len(v)))...)
	w.buf = append(w.buf, v...)
	return w
}

// String appends a length-delimited UTF-8 field (always, even when empty).
func (w *Writer) String(field int, v string) *Writer {
	return w.Bytes(field, []byte(v))
}

// OptString appends the field only when v is non-empty.
func (w *Writer) OptString(field int, v string) *Writer {
	if v == "" {
		return w
	}
	return w.String(field, v)
}

// Message appends an embedded message.
func (w *Writer) Message(field int, v []byte) *Writer {
	if v == nil {
		return w
	}
	return w.Bytes(field, v)
}

// Finish returns the encoded bytes.
func (w *Writer) Finish() []byte {
	if w.buf == nil {
		return []byte{}
	}
	return w.buf
}

// Value is one decoded field value.
type Value struct {
	Wire  int
	Num   uint64 // varint / i32 / i64
	Bytes []byte // length-delimited
}

// Fields maps field number to the values seen, preserving repeats.
type Fields map[int][]Value

// Decode parses raw wire data; unknown fields are kept.
func Decode(data []byte) (Fields, error) {
	out := Fields{}
	pos := 0
	for pos < len(data) {
		t, n, err := ReadVarint(data[pos:])
		if err != nil {
			return nil, err
		}
		pos += n
		field, wire := int(t>>3), int(t&7)
		switch wire {
		case WTVarint:
			v, n, err := ReadVarint(data[pos:])
			if err != nil {
				return nil, err
			}
			pos += n
			out[field] = append(out[field], Value{Wire: wire, Num: v})
		case WTLen:
			ln, n, err := ReadVarint(data[pos:])
			if err != nil {
				return nil, err
			}
			pos += n
			if uint64(len(data)-pos) < ln {
				return nil, ErrTruncated
			}
			out[field] = append(out[field], Value{Wire: wire, Bytes: data[pos : pos+int(ln)]})
			pos += int(ln)
		case WTI64:
			if len(data)-pos < 8 {
				return nil, ErrTruncated
			}
			out[field] = append(out[field], Value{Wire: wire, Num: binary.LittleEndian.Uint64(data[pos:])})
			pos += 8
		case WTI32:
			if len(data)-pos < 4 {
				return nil, ErrTruncated
			}
			out[field] = append(out[field], Value{Wire: wire, Num: uint64(binary.LittleEndian.Uint32(data[pos:]))})
			pos += 4
		default:
			return nil, fmt.Errorf("proto: unsupported wire type %d (field %d)", wire, field)
		}
	}
	return out, nil
}

// MustDecode decodes or returns an empty Fields.
func MustDecode(data []byte) Fields {
	f, err := Decode(data)
	if err != nil {
		return Fields{}
	}
	return f
}

// Has reports whether the field is present.
func (f Fields) Has(field int) bool { return len(f[field]) > 0 }

// Bytes returns the first length-delimited value of the field, or nil.
func (f Fields) Bytes(field int) []byte {
	if vs := f[field]; len(vs) > 0 {
		return vs[0].Bytes
	}
	return nil
}

// String returns the first value as a string ("" when absent).
func (f Fields) String(field int) string {
	return string(f.Bytes(field))
}

// Uint64 returns the first numeric value (0 when absent).
func (f Fields) Uint64(field int) uint64 {
	if vs := f[field]; len(vs) > 0 {
		return vs[0].Num
	}
	return 0
}

// Repeated returns every length-delimited value of the field.
func (f Fields) Repeated(field int) [][]byte {
	var out [][]byte
	for _, v := range f[field] {
		out = append(out, v.Bytes)
	}
	return out
}

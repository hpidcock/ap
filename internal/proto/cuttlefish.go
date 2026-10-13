package proto

// Cuttlefish and function-invoke wire messages for the escrow join path. Field
// numbers follow apple-oss-distributions/Security (TrustedPeersHelper protobufs) and
// rustpush; see RESEARCH.md stages 2-4.

// SignedBlob is a Cuttlefish SignedInfo{ info(1), sig(2) }.
type SignedBlob struct {
	Info []byte
	Sig  []byte
}

// Encode serialises the SignedInfo message.
func (s SignedBlob) Encode() []byte {
	return new(Writer).Bytes(1, orEmpty(s.Info)).Bytes(2, orEmpty(s.Sig)).Finish()
}

func orEmpty(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

// ParseSignedBlob decodes a SignedInfo.
func ParseSignedBlob(raw []byte) SignedBlob {
	f := MustDecode(raw)
	return SignedBlob{Info: orEmpty(f.Bytes(1)), Sig: orEmpty(f.Bytes(2))}
}

// Peer is a parsed CuttlefishPeer.
type Peer struct {
	Hash          string
	PermanentInfo *SignedBlob
	StableInfo    *SignedBlob
	DynamicInfo   *SignedBlob
	Voucher       *SignedBlob
}

// EncodePeer builds a CuttlefishPeer{ hash(1), permanent(2), stable(3), dynamic(4), voucher(5) }.
func EncodePeer(peerID string, permanent, stable, dynamic SignedBlob, voucher *SignedBlob) []byte {
	w := new(Writer).String(1, peerID).
		Message(2, permanent.Encode()).
		Message(3, stable.Encode()).
		Message(4, dynamic.Encode())
	if voucher != nil {
		w.Message(5, voucher.Encode())
	}
	return w.Finish()
}

// ParsePeer decodes a CuttlefishPeer.
func ParsePeer(raw []byte) Peer {
	f := MustDecode(raw)
	p := Peer{Hash: f.String(1)}
	blob := func(num int) *SignedBlob {
		if !f.Has(num) {
			return nil
		}
		sb := ParseSignedBlob(f.Bytes(num))
		return &sb
	}
	p.PermanentInfo = blob(2)
	p.StableInfo = blob(3)
	p.DynamicInfo = blob(4)
	p.Voucher = blob(5)
	return p
}

// EncodeVoucher builds Voucher{ reason(1), beneficiary(2), sponsor(3) }.
func EncodeVoucher(reason uint64, beneficiary, sponsor string) []byte {
	return new(Writer).Uint64(1, reason).String(2, beneficiary).String(3, sponsor).Finish()
}

// TLKShare mirrors Cuttlefish's TLKShare message.
type TLKShare struct {
	Service                     string
	Curve                       uint64
	Epoch                       uint64
	KeyID                       string
	Poisoned                    uint64
	Receiver                    string
	ReceiverPublicEncryptionKey string
	Sender                      string
	Signature                   string
	Version                     uint64
	WrappedKey                  string
}

// Encode serialises the TLKShare.
func (t TLKShare) Encode() []byte {
	return new(Writer).String(1, t.Service).Uint64(2, t.Curve).Uint64(3, t.Epoch).
		String(4, t.KeyID).Uint64(5, t.Poisoned).String(6, t.Receiver).
		String(7, t.ReceiverPublicEncryptionKey).String(8, t.Sender).
		String(9, t.Signature).Uint64(10, t.Version).String(11, t.WrappedKey).Finish()
}

// ParseTLKShare decodes a TLKShare.
func ParseTLKShare(raw []byte) TLKShare {
	f := MustDecode(raw)
	return TLKShare{
		Service: f.String(1), Curve: f.Uint64(2), Epoch: f.Uint64(3), KeyID: f.String(4),
		Poisoned: f.Uint64(5), Receiver: f.String(6), ReceiverPublicEncryptionKey: f.String(7),
		Sender: f.String(8), Signature: f.String(9), Version: f.Uint64(10), WrappedKey: f.String(11),
	}
}

// EncodeFetchChangesRequest builds FetchChangesRequest{ changeToken(1) }.
func EncodeFetchChangesRequest(syncToken string) []byte {
	w := new(Writer)
	if syncToken != "" {
		w.String(1, syncToken)
	}
	return w.Finish()
}

// FetchChangesResponse is the trust state page returned by fetchChanges.
type FetchChangesResponse struct {
	SyncToken string
	Peers     []Peer
}

// ParseFetchChangesResponse decodes a fetchChanges result.
func ParseFetchChangesResponse(raw []byte) FetchChangesResponse {
	f := MustDecode(raw)
	if !f.Has(1) {
		return FetchChangesResponse{}
	}
	cf := MustDecode(f.Bytes(1))
	out := FetchChangesResponse{SyncToken: cf.String(1)}
	for _, change := range cf.Repeated(2) {
		chg := MustDecode(change)
		if chg.Has(3) {
			out.Peers = append(out.Peers, ParsePeer(chg.Bytes(3)))
		}
	}
	return out
}

// EncodeJoinWithVoucherRequest builds the joinWithVoucher parameters. `peer` is an
// encoded CuttlefishPeer whose voucher SignedInfo was populated by the sponsor.
func EncodeJoinWithVoucherRequest(peer []byte, shares []TLKShare, bottle []byte, restorePoint string) []byte {
	w := new(Writer)
	if restorePoint != "" {
		w.String(1, restorePoint)
	}
	w.Message(2, peer)
	if bottle != nil {
		w.Message(3, bottle)
	}
	for _, s := range shares {
		w.Message(4, s.Encode())
	}
	return w.Finish()
}

// EncodeFetchRecoverableTLKSharesRequest asks for every view TLKShare the peer can recover.
func EncodeFetchRecoverableTLKSharesRequest(peerID string) []byte {
	return new(Writer).String(1, peerID).Finish()
}

// RecoverableTLKShares holds the inner CloudKit Record protobufs (parse with cloudkit.ParseRecord).
type RecoverableTLKShares struct {
	ShareRecords   [][]byte
	SyncKeyRecords [][]byte
}

// ParseRecoverableTLKSharesResponse decodes a fetchRecoverableTLKShares result.
func ParseRecoverableTLKSharesResponse(raw []byte) RecoverableTLKShares {
	f := MustDecode(raw)
	inner := func(cuttlefishRecord []byte) []byte { // CuttlefishRecord{ inner(2): Record }
		if cuttlefishRecord == nil {
			return nil
		}
		return MustDecode(cuttlefishRecord).Bytes(2)
	}
	var out RecoverableTLKShares
	for _, grp := range f.Repeated(1) {
		g := MustDecode(grp)
		if sh := inner(g.Bytes(3)); sh != nil {
			out.ShareRecords = append(out.ShareRecords, sh)
		}
		if g.Has(2) {
			vf := MustDecode(g.Bytes(2))
			for _, fn := range []int{1, 2, 3} { // tlk, classA, classB synckey records
				if rec := inner(vf.Bytes(fn)); rec != nil {
					out.SyncKeyRecords = append(out.SyncKeyRecords, rec)
				}
			}
		}
	}
	return out
}

// EncodeFunctionInvokeRequest builds FunctionInvokeRequest{ service(1), name(2), parameters(3) }.
func EncodeFunctionInvokeRequest(service, name string, parameters []byte) []byte {
	return new(Writer).String(1, service).String(2, name).Bytes(3, orEmpty(parameters)).Finish()
}

// EncodeFetchViableBottlesRequest builds the fetchViableBottles parameters.
func EncodeFetchViableBottlesRequest() []byte {
	return new(Writer).Uint64(1, 1).Bytes(2, []byte{}).Finish()
}

// ViableBottle is one escrow bottle from fetchViableBottles.
type ViableBottle struct {
	ID       string
	OTBottle []byte
}

// ParseViableBottles decodes a fetchViableBottles result.
func ParseViableBottles(raw []byte) []ViableBottle {
	var out []ViableBottle
	for _, ed := range MustDecode(raw).Repeated(1) {
		edf := MustDecode(ed)
		b := ViableBottle{ID: edf.String(1)}
		if edf.Has(2) {
			b.OTBottle = MustDecode(edf.Bytes(2)).Bytes(2)
		}
		out = append(out, b)
	}
	return out
}

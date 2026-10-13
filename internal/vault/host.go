// Package vault is the decrypted credential store, its domain matching, and the
// native-messaging host protocol spoken to the browser extension (read-only).
//
// Protocol (JSON, 4-byte LE length prefix):
//
//	-> {"cmd":"ping"}                                <- {"ok":true,"count":N}
//	-> {"cmd":"match","domain":"login.example.com"}  <- {"ok":true,"credentials":[...],"aliases":[...]}
//	-> {"cmd":"totp","domain":...,"username":...}    <- {"ok":true,"totp":{"code":...}}
//
// A credential's one-time-code secret never crosses this protocol: `match` carries a
// code generated at request time, and `totp` re-generates it when it has rolled over.
package vault

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"howett.net/plist"

	"github.com/hpidcock/ap/internal/cloudkit"
	"github.com/hpidcock/ap/internal/hme"
	"github.com/hpidcock/ap/internal/totp"
)

// Credential is one stored login.
type Credential struct {
	Domain   string  `json:"domain"`
	Username string  `json:"username"`
	Password string  `json:"password"`
	Title    string  `json:"title"`
	MDat     float64 `json:"mdat"`
	Notes    string  `json:"notes"`
	LastUsed float64 `json:"last_used"`
	TOTP     string  `json:"totp"` // otpauth:// URI, never sent to the browser
}

// Recency is the ordering key: last used, else modification time.
func (c Credential) Recency() float64 {
	if c.LastUsed != 0 {
		return c.LastUsed
	}
	return c.MDat
}

// WireDict is the extension's view: the totp URI is replaced by a code generated now.
func (c Credential) WireDict() map[string]any {
	var code any
	if g := totp.Generate(c.TOTP); g != nil {
		code = g
	}
	return map[string]any{
		"domain": c.Domain, "username": c.Username, "password": c.Password,
		"title": c.Title, "mdat": c.MDat, "notes": c.Notes, "last_used": c.LastUsed,
		"totp": code,
	}
}

const appleEpoch = 978307200 // 2001-01-01 UTC in unix seconds

// toUnix converts a keychain date (mdat/cdat) to unix seconds; 0 if unknown.
func toUnix(value any) float64 {
	switch v := value.(type) {
	case time.Time:
		return float64(v.UnixNano()) / 1e9
	case cloudkit.Date:
		return v.Time
	case float64:
		return numberToUnix(v)
	case int64:
		return numberToUnix(float64(v))
	case uint64:
		return numberToUnix(float64(v))
	case int:
		return numberToUnix(float64(v))
	}
	return 0
}

func numberToUnix(v float64) float64 {
	if v <= 0 {
		return 0
	}
	if v < 1e9 { // Apple absolute time (secs since 2001)
		return v + appleEpoch
	}
	return v
}

// NormalizeHost reduces a URL or host to a bare lowercase hostname.
func NormalizeHost(value string) string {
	v := strings.ToLower(strings.TrimSpace(value))
	if i := strings.Index(v, "://"); i >= 0 {
		v = v[i+3:]
	}
	if i := strings.IndexAny(v, "/?"); i >= 0 {
		v = v[:i]
	}
	if i := strings.LastIndex(v, "@"); i >= 0 {
		v = v[i+1:]
	}
	if i := strings.Index(v, ":"); i >= 0 {
		v = v[:i]
	}
	return strings.TrimPrefix(v, "www.")
}

// DomainsMatch is true if a stored item's domain should autofill on page: exact host,
// or either being a sub-domain of the other on a dotted boundary.
func DomainsMatch(page, stored string) bool {
	p, s := NormalizeHost(page), NormalizeHost(stored)
	if p == "" || s == "" {
		return false
	}
	if p == s {
		return true
	}
	return strings.HasSuffix(p, "."+s) || strings.HasSuffix(s, "."+p)
}

// MatchAliases returns the Hide My Email aliases whose recorded domain matches the page.
func MatchAliases(page string, aliases []hme.Alias) []hme.Alias {
	var out []hme.Alias
	for _, a := range aliases {
		if a.Domain != "" && DomainsMatch(page, a.Domain) {
			out = append(out, a)
		}
	}
	return out
}

// isCredential is false for the non-login records iCloud Keychain also syncs (PCS
// service blobs, per-site "Website Metadata" records, reverse-DNS labelled internals).
func isCredential(domain, title string) bool {
	for _, tag := range []string{domain, title} {
		t := strings.ToLower(strings.TrimSpace(tag))
		if strings.HasPrefix(t, "pcs ") || strings.HasPrefix(t, "pcs-") ||
			strings.HasPrefix(t, "website metadata") || strings.Contains(t, "com.apple.") {
			return false
		}
	}
	return true
}

var genericNameTokens = map[string]bool{
	"account": true, "accounts": true, "admin": true, "app": true, "dashboard": true,
	"login": true, "password": true, "passwords": true, "signin": true, "sign": true,
	"web": true, "www": true,
}

var tokenRE = regexp.MustCompile(`[a-z0-9]+`)

// nameMatchesHost is the fallback for entries that only carry a saved label: match
// whole hostname labels against the label's words (length >= 4, not generic).
func nameMatchesHost(page, name string) bool {
	labels := map[string]bool{}
	for _, l := range strings.Split(NormalizeHost(page), ".") {
		if l != "" {
			labels[l] = true
		}
	}
	if len(labels) == 0 {
		return false
	}
	for _, tok := range tokenRE.FindAllString(strings.ToLower(name), -1) {
		if len(tok) >= 4 && !genericNameTokens[tok] && labels[tok] {
			return true
		}
	}
	return false
}

// Access groups (`agrp`) identify the subsystem that wrote an item, i.e. its record type.
const (
	agrpSidecarPrefix = "com.apple.password-manager"
	agrpCard          = "com.apple.safari.credit-cards"
	agrpPasskey       = "com.apple.webkit.webauthn"
	sidecarLabel      = "password manager metadata:"
)

var agrpLogin = map[string]bool{"com.apple.cfnetwork": true, "apple": true}

// Allowlist of sidecar keys kept. `s_hi` is excluded deliberately - it holds previous
// passwords in cleartext, which have no autofill use and do not belong in the vault.
var sidecarKeep = map[string]bool{"notes": true, "title": true, "ctxt": true, "totp": true}

var plumbingKeysets = [][]string{{"tlkUUID", "srcIdentity"}, {"viewName", "encryptedData"}}
var cardKeys = []string{"CardNumber", "FPANHash", "PrimaryAccountIdentifier", "CardSecurityCode"}

func loadPlist(blob []byte) map[string]any {
	if !strings.HasPrefix(string(blob), "bplist00") {
		return nil
	}
	var v any
	if _, err := plist.Unmarshal(blob, &v); err != nil {
		return nil
	}
	m, _ := v.(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}

// Kind classifies an item's payload.
type Kind string

// Payload kinds.
const (
	KindPassword  Kind = "password"
	KindSidecar   Kind = "sidecar"
	KindCard      Kind = "card"
	KindPlumbing  Kind = "plumbing"
	KindBinary    Kind = "binary"
	KindPasskey   Kind = "passkey"
	KindSubsystem Kind = "subsystem"
)

// ClassifyPayload classifies an item's v_Data -> (kind, text password, plist payload).
func ClassifyPayload(value any) (Kind, string, map[string]any) {
	switch v := value.(type) {
	case string:
		return KindPassword, v, nil
	case []byte:
		if len(v) == 0 {
			return KindPassword, "", nil
		}
		if parsed := loadPlist(v); parsed != nil {
			for _, ks := range plumbingKeysets {
				all := true
				for _, k := range ks {
					if _, ok := parsed[k]; !ok {
						all = false
						break
					}
				}
				if all {
					return KindPlumbing, "", parsed
				}
			}
			for _, k := range cardKeys {
				if _, ok := parsed[k]; ok {
					return KindCard, "", parsed
				}
			}
			return KindSidecar, "", parsed
		}
		if strings.HasPrefix(strings.TrimLeft(string(v), " \t\r\n"), "<?xml") {
			return KindPlumbing, "", nil
		}
		text := string(v)
		if !isValidUTF8(text) {
			return KindBinary, "", nil
		}
		for _, r := range text {
			if (r < 0x20 && r != '\t' && r != '\n' && r != '\r') || r == 0x7f {
				return KindBinary, "", nil
			}
		}
		return KindPassword, text, nil
	}
	return KindPassword, "", nil
}

func isValidUTF8(s string) bool {
	for _, r := range s {
		if r == '�' {
			// could be a genuine U+FFFD; check bytes
			if !strings.Contains(s, "\xef\xbf\xbd") {
				return false
			}
		}
	}
	return strings.ToValidUTF8(s, "") == s
}

// ClassifyItem classifies a decrypted keychain item by its `agrp` access group, falling
// back to the payload for unrecognised groups.
func ClassifyItem(item map[string]any) (Kind, string, map[string]any) {
	agrp := strOf(item["agrp"])
	raw := item["v_Data"]
	if raw == nil {
		raw = item["password"]
	}
	switch {
	case strings.HasPrefix(agrp, agrpSidecarPrefix):
		_, _, payload := ClassifyPayload(raw)
		if payload == nil {
			payload = map[string]any{}
		}
		return KindSidecar, "", payload
	case agrp == agrpCard:
		_, _, payload := ClassifyPayload(raw)
		if payload == nil {
			payload = map[string]any{}
		}
		return KindCard, "", payload
	case agrp == agrpPasskey:
		return KindPasskey, "", nil
	case agrpLogin[agrp]:
		kind, text, payload := ClassifyPayload(raw)
		if kind == KindPassword || kind == KindSidecar {
			return kind, text, payload
		}
		return KindBinary, "", nil
	case strings.HasPrefix(agrp, "com.apple."):
		return KindSubsystem, "", nil
	}
	return ClassifyPayload(raw)
}

func strOf(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case []byte:
		return string(x)
	}
	return fmt.Sprint(v)
}

func sidecarLastUsed(ctxt any) float64 {
	m, ok := ctxt.(map[string]any)
	if !ok {
		return 0
	}
	var best float64
	for _, per := range m {
		pm, ok := per.(map[string]any)
		if !ok {
			continue
		}
		v := pm["lUsed"]
		if v == nil {
			v = pm["slUsed"]
		}
		if t := toUnix(v); t > best {
			best = t
		}
	}
	return best
}

// Store is the in-memory read-only credential store.
type Store struct {
	creds []Credential
}

// NewStore wraps a credential list.
func NewStore(creds []Credential) *Store { return &Store{creds: append([]Credential{}, creds...)} }

// Len is the credential count.
func (s *Store) Len() int { return len(s.creds) }

// All returns a copy of every credential.
func (s *Store) All() []Credential { return append([]Credential{}, s.creds...) }

// Match returns the credentials for a page: exact-host matches first, then
// parent/subdomain, then label-only fallbacks; within a tier most-recently-used first.
func (s *Store) Match(page string) []Credential {
	type ranked struct {
		rank int
		c    Credential
	}
	var out []ranked
	for _, c := range s.creds {
		if !isCredential(c.Domain, c.Title) {
			continue
		}
		rank := -1
		switch {
		case DomainsMatch(page, c.Domain):
			if NormalizeHost(page) == NormalizeHost(c.Domain) {
				rank = 0
			} else {
				rank = 1
			}
		default:
			name := c.Title
			if name == "" {
				name = c.Domain
			}
			if !strings.Contains(NormalizeHost(c.Domain), ".") && nameMatchesHost(page, name) {
				rank = 2
			}
		}
		if rank >= 0 {
			out = append(out, ranked{rank, c})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.rank != b.rank {
			return a.rank < b.rank
		}
		if a.c.Recency() != b.c.Recency() {
			return a.c.Recency() > b.c.Recency()
		}
		if a.c.Title != b.c.Title {
			return a.c.Title < b.c.Title
		}
		return a.c.Username < b.c.Username
	})
	res := make([]Credential, len(out))
	for i, r := range out {
		res[i] = r.c
	}
	return res
}

// FromItems builds a store from decrypted keychain item dicts. Apple `inet` items use
// `srvr` (domain), `acct` (username), `v_Data` (password), `labl` (title). A login and
// its metadata sidecar are separate items joined on (srvr, acct).
func FromItems(items []map[string]any) *Store {
	type login struct {
		key                               string
		domain, username, password, title string
		mdat                              float64
	}
	var logins []login
	sidecars := map[string]map[string]any{}
	for _, it := range items {
		var domain string
		for _, k := range []string{"srvr", "server", "domain", "url", "svce"} {
			if domain = strOf(it[k]); domain != "" {
				break
			}
		}
		var username string
		for _, k := range []string{"acct", "username", "user"} {
			if username = strOf(it[k]); username != "" {
				break
			}
		}
		label := strOf(it["labl"])
		kind, text, payload := ClassifyItem(it)
		if strings.HasPrefix(strings.ToLower(label), sidecarLabel) {
			kind = KindSidecar
			if payload == nil {
				payload = map[string]any{}
			}
		}
		key := strings.ToLower(domain) + "\x00" + strings.ToLower(username)
		if kind == KindSidecar {
			if domain != "" || username != "" {
				sc := sidecars[key]
				if sc == nil {
					sc = map[string]any{}
					sidecars[key] = sc
				}
				for k, v := range payload {
					if sidecarKeep[k] {
						sc[k] = v
					}
				}
			}
			continue
		}
		if kind != KindPassword {
			continue
		}
		title := label
		if title == "" {
			title = domain
		}
		if !isCredential(domain, title) {
			continue
		}
		if (domain == "" && username == "") || (username == "" && text == "") {
			continue
		}
		mdat := it["mdat"]
		if mdat == nil {
			mdat = it["cdat"]
		}
		logins = append(logins, login{key, domain, username, text, title, toUnix(mdat)})
	}
	creds := make([]Credential, 0, len(logins))
	for _, l := range logins {
		side := sidecars[l.key]
		title := l.title
		if t := strOf(side["title"]); t != "" {
			title = t
		}
		creds = append(creds, Credential{
			Domain: l.domain, Username: l.username, Password: l.password, Title: title,
			MDat: l.mdat, Notes: strOf(side["notes"]), LastUsed: sidecarLastUsed(side["ctxt"]),
			TOTP: totp.URIFromSidecar(side["totp"]),
		})
	}
	return NewStore(creds)
}

// ReadMessage reads one native-messaging frame; (nil, io.EOF) at end of stream.
func ReadMessage(r io.Reader) (map[string]any, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, io.EOF
	}
	n := binary.LittleEndian.Uint32(lenBuf[:])
	if n > 64<<20 {
		return nil, fmt.Errorf("native message too large (%d bytes)", n)
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, io.EOF
	}
	var msg map[string]any
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	return msg, nil
}

// WriteMessage writes one native-messaging frame.
func WriteMessage(w io.Writer, msg map[string]any) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(data)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// Handle answers one request.
func Handle(req map[string]any, store *Store, aliases []hme.Alias) map[string]any {
	cmd, _ := req["cmd"].(string)
	switch cmd {
	case "ping":
		return map[string]any{"ok": true, "count": store.Len()}
	case "match":
		domain, _ := req["domain"].(string)
		if domain == "" {
			return map[string]any{"ok": false, "error": "missing domain"}
		}
		creds := []map[string]any{}
		for _, c := range store.Match(domain) {
			creds = append(creds, c.WireDict())
		}
		matched := []map[string]any{}
		for _, a := range MatchAliases(domain, aliases) {
			matched = append(matched, a.PublicDict())
		}
		return map[string]any{"ok": true, "credentials": creds, "aliases": matched}
	case "totp":
		domain, _ := req["domain"].(string)
		username, _ := req["username"].(string)
		for _, c := range store.Match(domain) {
			if c.Username == username && c.TOTP != "" {
				return map[string]any{"ok": true, "totp": totp.Generate(c.TOTP)}
			}
		}
		return map[string]any{"ok": false, "error": "no code for that login"}
	}
	return map[string]any{"ok": false, "error": fmt.Sprintf("unknown cmd %q", cmd)}
}

// Serve runs the blocking native-messaging loop until the extension disconnects.
func Serve(store *Store, aliases []hme.Alias, in io.Reader, out io.Writer) error {
	br := bufio.NewReader(in)
	bw := bufio.NewWriter(out)
	for {
		req, err := ReadMessage(br)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := WriteMessage(bw, Handle(req, store, aliases)); err != nil {
			return err
		}
		if err := bw.Flush(); err != nil {
			return err
		}
	}
}

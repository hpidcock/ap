// Package anisette defines where the "machine validation data" (X-Apple-I-MD /
// X-Apple-I-MD-M) GrandSlam requires comes from. Package remote fetches it from an
// anisette-v3 server (the default); package local generates it in-process with Apple's
// Android CoreADI library.
package anisette

// Provider produces a fresh set of anisette headers for one request.
type Provider interface {
	Headers() (map[string]string, error)
}

// Resyncer is implemented by providers that can answer GrandSlam's "anisette resync"
// demand (Status.hsc == 434): Apple hands back X-Apple-I-MD-DATA, the provider feeds it
// to ADI and returns fresh machine data to retry the request with.
type Resyncer interface {
	Resync(simBase64 string) (map[string]string, error)
}

// ClientInfoProvider is implemented by providers whose machine data is only valid for a
// particular X-Mme-Client-Info / User-Agent pair (Apple checks the platform).
type ClientInfoProvider interface {
	ClientInfo() (clientInfo, userAgent string, err error)
}

// Error is an anisette failure.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

// Keys are the header names forwarded to Apple's services.
var Keys = []string{
	"X-Apple-I-MD",
	"X-Apple-I-MD-M",
	"X-Apple-I-MD-RINFO",
	"X-Apple-I-MD-LU",
	"X-Apple-I-SRL-NO",
	"X-Mme-Device-Id",
	"X-Apple-I-Client-Time",
	"X-Apple-I-TimeZone",
	"X-Apple-Locale",
}

// Filter keeps only the forwarded keys and checks the mandatory machine data is present.
func Filter(data map[string]string) (map[string]string, error) {
	out := map[string]string{}
	for _, k := range Keys {
		if v, ok := data[k]; ok {
			out[k] = v
		}
	}
	if out["X-Apple-I-MD"] == "" || out["X-Apple-I-MD-M"] == "" {
		return nil, &Error{Msg: "anisette data is missing X-Apple-I-MD / X-Apple-I-MD-M"}
	}
	return out, nil
}

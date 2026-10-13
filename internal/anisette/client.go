// Package anisette defines where the "machine validation data" (X-Apple-I-MD /
// X-Apple-I-MD-M) GrandSlam requires comes from. The implementation is package local,
// which generates it in-process with Apple's CoreADI library.
package anisette

// Provider produces a fresh set of anisette headers for one request.
type Provider interface {
	Headers() (map[string]string, error)
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

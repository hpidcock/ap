package logx

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestRedactBody(t *testing.T) {
	cases := map[string][]string{
		`<key>password</key><string>hunter2</string><key>u</key><string>me@example.com</string>`: {"hunter2"},
		`<key>M1</key>
	<data>AAEC</data>`: {"AAEC"},
		`{"accountName":"me@example.com","m1":"abc","securityCode":{"code":"123456"},"password":"p"}`: {`"abc"`, `"123456"`, `"p"`},
		`password=hunter2&u=me`:             {"hunter2"},
		`Authorization: Basic dXNlcjpwYXNz`: {"dXNlcjpwYXNz"},
	}
	for in, secrets := range cases {
		out := RedactBody(in)
		for _, s := range secrets {
			if strings.Contains(out, s) {
				t.Errorf("secret %q survived in %q", s, out)
			}
		}
		if !strings.Contains(out, "redacted") {
			t.Errorf("nothing redacted in %q", out)
		}
	}
	if got := RedactBody(`<key>u</key><string>me@example.com</string>`); !strings.Contains(got, "me@example.com") {
		t.Errorf("over-redacted: %q", got)
	}
}

func TestFormatHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Basic abc")
	h.Set("X-Apple-I-MD", "machine-data")
	h.Set("Security-Code", "123456")
	h.Set("Content-Type", "text/x-xml-plist")
	out := FormatHeaders(h)
	for _, s := range []string{"Basic abc", "machine-data", "123456"} {
		if strings.Contains(out, s) {
			t.Errorf("secret %q in %q", s, out)
		}
	}
	if !strings.Contains(out, "Content-Type: text/x-xml-plist") {
		t.Errorf("plain header lost: %q", out)
	}
}

func TestBody(t *testing.T) {
	if got := Body("application/octet-stream", []byte{0, 1, 2, 0xff}, 100); got != "<4 bytes of application/octet-stream>" {
		t.Errorf("binary body: %q", got)
	}
	long := strings.Repeat("a", 50)
	if got := Body("text/plain", []byte(long), 10); !strings.HasPrefix(got, "aaaaaaaaaa...") || !strings.Contains(got, "50 bytes total") {
		t.Errorf("truncation: %q", got)
	}
}

func TestChain(t *testing.T) {
	root := errors.New("root cause")
	err := fmt.Errorf("outer: %w", fmt.Errorf("middle: %w", root))
	got := Chain(err)
	for _, s := range []string{"outer: middle: root cause", "middle: root cause", "root cause (*errors.errorString)"} {
		if !strings.Contains(got, s) {
			t.Errorf("chain %q lacks %q", got, s)
		}
	}
	if Chain(nil) != "<nil>" {
		t.Error("nil chain")
	}
}

func TestParseLevel(t *testing.T) {
	for in, want := range map[string]Level{"": Off, "0": Off, "1": Debug, "true": Debug, "debug": Debug, "2": Trace, "trace": Trace} {
		if got := ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

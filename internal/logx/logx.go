// Package logx is ap's diagnostic log. It is silent by default; `ap --debug` or
// AP_DEBUG=1 prints timestamped lines to stderr, AP_DEBUG=2 (or --debug=trace) also
// prints request and response bodies, and AP_LOG_FILE=<path> (or --log-file) appends the
// same lines to a private file, which is how the background sync and the native-messaging
// host can be diagnosed after the fact.
//
// Everything that could authenticate as the user - Basic auth, tokens, cookies, 2FA codes,
// anisette machine data, passwords and PETs in bodies - is redacted before it is written.
package logx

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Level is the verbosity.
type Level int

const (
	Off   Level = iota
	Debug       // operations, statuses, redacted headers, bodies of failed requests
	Trace       // everything, including redacted bodies of successful requests
)

var (
	mu      sync.Mutex
	level   Level
	stderr  bool
	file    *os.File
	started = time.Now()
)

// ParseLevel maps AP_DEBUG / --debug values to a level.
func ParseLevel(v string) Level {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "0", "false", "off", "no":
		return Off
	case "2", "trace", "all":
		return Trace
	default:
		return Debug
	}
}

// Init configures the log. lvl selects what is printed to stderr (Off prints nothing
// there); logFile, when non-empty, receives everything at Trace level regardless.
func Init(lvl Level, logFile string) error {
	mu.Lock()
	defer mu.Unlock()
	level, stderr = lvl, lvl > Off
	if file != nil {
		file.Close()
		file = nil
	}
	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("open log file: %w", err)
		}
		file = f
		if level < Trace {
			level = Trace
		}
	}
	return nil
}

// InitFromEnv configures the log from AP_DEBUG and AP_LOG_FILE alone.
func InitFromEnv() error {
	return Init(ParseLevel(os.Getenv("AP_DEBUG")), os.Getenv("AP_LOG_FILE"))
}

// Enabled reports whether anything is logged at all.
func Enabled() bool { mu.Lock(); defer mu.Unlock(); return level > Off }

// Tracing reports whether bodies of successful requests are logged.
func Tracing() bool { mu.Lock(); defer mu.Unlock(); return level >= Trace }

func write(lvl Level, component, format string, a ...any) {
	mu.Lock()
	defer mu.Unlock()
	if level < lvl {
		return
	}
	msg := fmt.Sprintf(format, a...)
	line := fmt.Sprintf("%s [%s] %s\n", time.Now().Format("15:04:05.000"), component, strings.TrimRight(msg, "\n"))
	if stderr {
		fmt.Fprint(os.Stderr, line)
	}
	if file != nil {
		fmt.Fprint(file, line)
	}
}

// Debugf logs an operational line for a component ("gsa", "icloud", "http", ...).
func Debugf(component, format string, a ...any) { write(Debug, component, format, a...) }

// Tracef logs a verbose line (bodies, full header sets).
func Tracef(component, format string, a ...any) { write(Trace, component, format, a...) }

// Errorf logs an error with its full cause chain; it is written at Debug level because
// the CLI prints the user-facing message itself.
func Errorf(component string, err error, format string, a ...any) {
	if err == nil {
		return
	}
	write(Debug, component, "%s: %s", fmt.Sprintf(format, a...), Chain(err))
}

// Chain renders an error and every wrapped cause, innermost last, with the concrete
// type of each so a bare "unknown error" can still be traced to its package.
func Chain(err error) string {
	if err == nil {
		return "<nil>"
	}
	var parts []string
	seen := map[string]bool{}
	for e := err; e != nil; e = errors.Unwrap(e) {
		s := fmt.Sprintf("%v (%T)", e, e)
		if seen[s] {
			break
		}
		seen[s] = true
		parts = append(parts, s)
	}
	return strings.Join(parts, " <- ")
}

// --- redaction -------------------------------------------------------------------------

var secretHeaders = map[string]bool{
	"authorization": true, "cookie": true, "set-cookie": true, "x-apple-identity-token": true,
	"security-code": true, "x-apple-i-md": true, "x-apple-i-md-m": true, "x-apple-i-md-lu": true,
	"x-apple-session-token": true, "x-apple-id-session-id": true, "scnt": true,
	"x-apple-twosv-trust-token": true, "x-apple-auth-attributes": true, "x-apple-oauth-token": true,
	"x-apple-session": true, "x-cloudkit-authtoken": true, "x-cloudkit-usertoken": true,
	"x-mme-authtoken": true, "x-apple-adsid": true, "x-apple-mme-token": true,
}

// RedactValue hides a secret, keeping only its length.
func RedactValue(v string) string { return fmt.Sprintf("<redacted %d bytes>", len(v)) }

// RedactHeader returns the loggable value of a header.
func RedactHeader(name, value string) string {
	if secretHeaders[strings.ToLower(name)] {
		return RedactValue(value)
	}
	return value
}

// FormatHeaders renders a header set, redacted and sorted, as "k: v" lines.
func FormatHeaders(h http.Header) string {
	names := make([]string, 0, len(h))
	for k := range h {
		names = append(names, k)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, k := range names {
		for _, v := range h[k] {
			fmt.Fprintf(&b, "    %s: %s\n", k, RedactHeader(k, v))
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

var (
	secretKeys = `(?i:password|passcode|pet|token|mmeAuthToken|cloudKitToken|trustToken|securityCode|security-code|code|M1|M2|A2k|A|spd|cookie|session|secret|entropy|key)`
	plistRE    = regexp.MustCompile(`(?s)(<key>` + secretKeys + `</key>\s*<(?:string|data)>)[^<]*(</(?:string|data)>)`)
	jsonRE     = regexp.MustCompile(`("` + secretKeys + `"\s*:\s*")(?:[^"\\]|\\.)*(")`)
	formRE     = regexp.MustCompile(`(?i)((?:^|&)(?:password|token|code|pet)=)[^&]*`)
	basicRE    = regexp.MustCompile(`(?i)(basic\s+)[A-Za-z0-9+/=]+`)
)

// RedactBody masks secret values in a textual (plist / JSON / form) body.
func RedactBody(body string) string {
	body = plistRE.ReplaceAllString(body, "${1}<redacted>${2}")
	body = jsonRE.ReplaceAllString(body, "${1}<redacted>${2}")
	body = formRE.ReplaceAllString(body, "${1}<redacted>")
	body = basicRE.ReplaceAllString(body, "${1}<redacted>")
	return body
}

// Textual reports whether a content type is worth printing.
func Textual(contentType string) bool {
	ct := strings.ToLower(contentType)
	for _, t := range []string{"text/", "json", "xml", "plist", "x-www-form-urlencoded", "javascript"} {
		if strings.Contains(ct, t) {
			return true
		}
	}
	return false
}

// Body renders up to max bytes of a body for the log, redacted; binary bodies are
// summarised by size.
func Body(contentType string, raw []byte, max int) string {
	if len(raw) == 0 {
		return "<empty>"
	}
	if !Textual(contentType) && !looksTextual(raw) {
		return fmt.Sprintf("<%d bytes of %s>", len(raw), nonEmpty(contentType, "binary"))
	}
	s := string(raw)
	if len(s) > max {
		s = s[:max] + fmt.Sprintf("... (%d bytes total)", len(raw))
	}
	return RedactBody(s)
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func looksTextual(b []byte) bool {
	n := len(b)
	if n > 512 {
		n = 512
	}
	for _, c := range b[:n] {
		if c < 0x09 || (c > 0x0d && c < 0x20) || c > 0x7e {
			return false
		}
	}
	return true
}

// Keys returns a map's keys, sorted, for compact "what did Apple send" lines.
func Keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Elapsed is the time since the process started, for coarse phase timing.
func Elapsed() time.Duration { return time.Since(started).Round(time.Millisecond) }

// Close flushes and closes the log file.
func Close() {
	mu.Lock()
	defer mu.Unlock()
	if file != nil {
		file.Close()
		file = nil
	}
}

// Writer returns an io.Writer that logs each write as a Debug line, for packages that
// take a *log.Logger.
func Writer(component string) io.Writer { return writer{component} }

type writer struct{ component string }

func (w writer) Write(p []byte) (int, error) {
	Debugf(w.component, "%s", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

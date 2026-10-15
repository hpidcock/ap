package httpx

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hpidcock/ap/internal/logx"
)

// maxLoggedBody bounds how much of a body is buffered and printed.
const maxLoggedBody = 8 * 1024

// maxBufferedBody bounds how large a response ap is willing to buffer just to log it;
// anything bigger (the APK download) streams through untouched.
const maxBufferedBody = 1 << 20

// loggingTransport logs every request and response through logx: one line per exchange
// at Debug level, redacted headers and the bodies of failed requests at Debug level, and
// all bodies at Trace level.
type loggingTransport struct{ next http.RoundTripper }

func (t *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !logx.Enabled() {
		return t.next.RoundTrip(req)
	}
	var reqBody []byte
	if req.Body != nil && req.Body != http.NoBody {
		b, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, err
		}
		reqBody = b
		req.Body = io.NopCloser(bytes.NewReader(b))
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
	}
	logx.Debugf("http", "> %s %s (%d bytes)", req.Method, req.URL, len(reqBody))
	logx.Tracef("http", "> headers\n%s", logx.FormatHeaders(req.Header))
	if len(reqBody) > 0 {
		logx.Tracef("http", "> body: %s", logx.Body(req.Header.Get("Content-Type"), reqBody, maxLoggedBody))
	}
	start := time.Now()
	resp, err := t.next.RoundTrip(req)
	if err != nil {
		logx.Debugf("http", "< %s %s failed after %s: %v", req.Method, req.URL, time.Since(start).Round(time.Millisecond), err)
		return nil, err
	}
	failed := resp.StatusCode/100 != 2
	logx.Debugf("http", "< %s %s -> %d %s (%s, %s)", req.Method, req.URL.Host+req.URL.Path, resp.StatusCode,
		nonEmpty(resp.Header.Get("Content-Type"), "no content-type"), sizeOf(resp.ContentLength),
		time.Since(start).Round(time.Millisecond))
	if failed || logx.Tracing() {
		logx.Tracef("http", "< headers\n%s", logx.FormatHeaders(resp.Header))
		if failed {
			logx.Debugf("http", "< headers\n%s", logx.FormatHeaders(resp.Header))
		}
		if resp.Body != nil && (resp.ContentLength <= maxBufferedBody) {
			b, rerr := io.ReadAll(io.LimitReader(resp.Body, maxBufferedBody+1))
			resp.Body.Close()
			if rerr != nil {
				return nil, rerr
			}
			resp.Body = io.NopCloser(bytes.NewReader(b))
			line := "< body: " + logx.Body(resp.Header.Get("Content-Type"), b, maxLoggedBody)
			if failed {
				logx.Debugf("http", "%s", line)
			} else {
				logx.Tracef("http", "%s", line)
			}
		}
	}
	return resp, nil
}

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func sizeOf(n int64) string {
	if n < 0 {
		return "chunked"
	}
	return itoa(n) + " bytes"
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

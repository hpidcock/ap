// Package httpx builds the HTTP clients used against Apple's services.
//
// gsa.apple.com (GrandSlam) presents a certificate chained to Apple's own "Apple Root
// CA", which public CA bundles do not carry, so that root is embedded here and trusted
// in addition to the system roots. Every other Apple endpoint ap talks to uses a
// publicly trusted chain and is verified normally.
package httpx

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"net/http"
	"net/http/cookiejar"
	"os"
	"sync"
	"time"
)

//go:embed apple-root-ca.pem
var appleRootCA []byte

var (
	poolOnce sync.Once
	pool     *x509.CertPool
)

// RootPool is the system pool plus Apple Root CA.
func RootPool() *x509.CertPool {
	poolOnce.Do(func() {
		p, err := x509.SystemCertPool()
		if err != nil || p == nil {
			p = x509.NewCertPool()
		}
		p.AppendCertsFromPEM(appleRootCA)
		pool = p
	})
	return pool
}

// Insecure reports whether TLS verification is disabled (AP_INSECURE_TLS=1), which is
// only meant for debugging through an intercepting proxy.
func Insecure() bool {
	return os.Getenv("AP_INSECURE_TLS") == "1"
}

// Transport returns a fresh transport honouring Insecure, wrapped so that every
// exchange is logged through logx when debugging is on.
func Transport() http.RoundTripper { return &loggingTransport{next: baseTransport()} }

func baseTransport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = http.ProxyFromEnvironment
	t.TLSClientConfig = &tls.Config{RootCAs: RootPool(), MinVersion: tls.VersionTLS12}
	if Insecure() {
		t.TLSClientConfig.InsecureSkipVerify = true //nolint:gosec // opt-in debugging aid
	}
	return t
}

// Client returns a client with the given timeout.
func Client(timeout time.Duration) *http.Client {
	return &http.Client{Transport: Transport(), Timeout: timeout}
}

// ClientNoKeepAlive returns a client that opens a fresh connection for every request
// and tells the server so. gsa.apple.com's edge answers the second request on a reused
// keep-alive connection with HTTP 503 (seen by AltStore, SideStore and iloader since
// September 2026), and a sign-in is always several requests in a row.
func ClientNoKeepAlive(timeout time.Duration) *http.Client {
	t := baseTransport()
	t.DisableKeepAlives = true
	return &http.Client{Transport: &loggingTransport{next: t}, Timeout: timeout}
}

// ClientWithJar returns a client that keeps cookies.
func ClientWithJar(timeout time.Duration, jar http.CookieJar) *http.Client {
	if jar == nil {
		jar, _ = cookiejar.New(nil)
	}
	return &http.Client{Transport: Transport(), Timeout: timeout, Jar: jar}
}

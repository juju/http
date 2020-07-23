// Copyright 2020 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package http

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"

	"github.com/juju/errors"
	"github.com/juju/loggo"
)

// NOTE: Once we refactor the juju tests enough that they do not use
// a RoundTripper on the DefaultTransport, NewClient can always return
// a Client with a locally constructed Transport via NewHttpTLSTransport
// and init() will no longer be needed.
//
// https://bugs.launchpad.net/juju/+bug/1888888
func init() {
	defaultTransport := http.DefaultTransport.(*http.Transport)
	// Call the HTTPDialShim for the DefaultTransport to
	// facilitate testing use of OutgoingAccessAllowed.
	installHTTPDialShim(defaultTransport)
	// Call our own proxy function with the DefaultTransport.
	installProxyShim(defaultTransport)
	//registerFileProtocol(defaultTransport)
}

// HTTPClient represents an http.Client.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Logger represents methods required for package logging.
type Logger interface {
	IsTraceEnabled() bool
	Tracef(message string, args ...interface{})
}

// Client represents an http client.
type Client struct {
	HTTPClient

	logger Logger
}

// Config holds configuration for creating a new http client.
type Config struct {
	// CACertificates contains an optional list of Certificate
	// Authority certificates to be used to validate certificates
	// of cloud infrastructure components.
	// The contents are Base64 encoded x.509 certs.
	CACertificates []string

	// Jar specifies the cookie jar.
	//
	// The Jar is used to insert relevant cookies into every
	// outbound Request and is updated with the cookie values
	// of every inbound Response. The Jar is consulted for every
	// redirect that the Client follows.
	//
	// If Jar is nil, cookies are only sent if they are explicitly
	// set on the Request.
	Jar http.CookieJar

	// SkipHostnameVerification indicates whether to use self-signed credentials
	// and not try to verify the hostname on the TLS/SSL certificates.
	SkipHostnameVerification bool

	// Logger is used to provide logging with the provided Client.
	// When logging level is set to Trace, the httptrace package is
	// used to log details about any Get done.  If empty, a local
	// logger is created.
	Logger Logger
}

// NewClient returns a new juju http client defined
// by the given config.
func NewClient(cfg Config) *Client {
	certCnt := len(cfg.CACertificates)
	var hc = http.DefaultClient
	switch {
	case certCnt > 0:
		hc = clientWithCerts(cfg)
	case cfg.SkipHostnameVerification:
		hc = client(cfg)
	default:
		// In this case, use a default http.Client.
		// Ideally we should always use the NewHttpTLSTransport,
		// however test suites such as JujuConnSuite and some facade
		// tests rely on settings to the http.DefaultTransport for
		// tests to run with different protocol scheme such as "test"
		// and some replace the RoundTripper to answer test scenarios.
		//
		// https://bugs.launchpad.net/juju/+bug/1888888
	}
	hc.Jar = cfg.Jar
	c := &Client{
		HTTPClient: hc,
	}
	if cfg.Logger == nil {
		c.logger = loggo.GetLogger("http")
	} else {
		c.logger = cfg.Logger
	}
	return c
}

func client(cfg Config) *http.Client {
	return &http.Client{
		Transport: NewHttpTLSTransport(&tls.Config{
			InsecureSkipVerify: cfg.SkipHostnameVerification,
		}),
	}
}

func clientWithCerts(cfg Config) *http.Client {
	if len(cfg.CACertificates) == 0 {
		return nil
	}
	pool := x509.NewCertPool()
	for _, cert := range cfg.CACertificates {
		pool.AppendCertsFromPEM([]byte(cert))
	}
	tlsConfig := SecureTLSConfig()
	tlsConfig.RootCAs = pool
	tlsConfig.InsecureSkipVerify = cfg.SkipHostnameVerification
	return &http.Client{
		Transport: NewHttpTLSTransport(tlsConfig),
	}
}

// Client returns the underlying http.Client.  Used in testing
// only.
func (c *Client) Client() *http.Client {
	return c.HTTPClient.(*http.Client)
}

// Get issues a GET to the specified URL.  It mimics the net/http Get,
// but allows for enhanced debugging.
//
// When err is nil, resp always contains a non-nil resp.Body.
// Caller should close resp.Body when done reading from it.
func (c *Client) Get(ctx context.Context, path string) (resp *http.Response, err error) {
	req, err := http.NewRequestWithContext(ctx, "GET", path, nil)
	if err != nil {
		return nil, errors.Trace(err)
	}

	if err := c.traceRequest(req, path); err != nil {
		// No need to fail, but let user know we're
		// not tracing the client GET.
		err = errors.Annotatef(err, "setup of http client tracing failed")
		c.logger.Tracef("%s", err)
	}
	return c.Do(req)
}

// traceRequest enabled debugging on the http request if
// log level for ths package is set to Trace.  Otherwise it
// returns with no change to the request.
func (c *Client) traceRequest(req *http.Request, url string) error {
	if !c.logger.IsTraceEnabled() {
		return nil
	}
	dump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		return errors.Trace(err)
	}
	c.logger.Tracef("request for %q: %q", url, dump)
	trace := &httptrace.ClientTrace{
		DNSStart: func(info httptrace.DNSStartInfo) {
			c.logger.Tracef("%s DNS Start: %q", url, info.Host)
		},
		DNSDone: func(dnsInfo httptrace.DNSDoneInfo) {
			c.logger.Tracef("%s DNS Info: %+v\n", url, dnsInfo)
		},
		ConnectDone: func(network, addr string, err error) {
			c.logger.Tracef("%s Connection Done: network %q, addr %q, err %q", url, network, addr, err)
		},
		GetConn: func(hostPort string) {
			c.logger.Tracef("%s Get Conn: %q", url, hostPort)
		},
		GotConn: func(connInfo httptrace.GotConnInfo) {
			c.logger.Tracef("%s Got Conn: %+v", url, connInfo)
		},
		TLSHandshakeStart: func() {
			c.logger.Tracef("%s TLS Handshake Start", url)
		},
		TLSHandshakeDone: func(st tls.ConnectionState, err error) {
			c.logger.Tracef("%s TLS Handshake Done: complete %t, verified chains %d, server name %q",
				url,
				st.HandshakeComplete,
				len(st.VerifiedChains),
				st.ServerName)
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	return nil
}

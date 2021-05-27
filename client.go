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
	"time"

	"github.com/juju/errors"
	"github.com/juju/loggo"
)

// NOTE: Once we refactor the juju tests enough that they do not use
// a RoundTripper on the DefaultTransport, NewClient can always return
// a Client with a locally constructed Transport via NewHttpTLSTransport
// and init() will no longer be needed.
//
// https://bugs.launchpad.net/juju/+bug/1888888
//
// TODO (stickupkid) This is terrible, I'm not kidding! This isn't yours to
// touch!
func init() {
	defaultTransport := http.DefaultTransport.(*http.Transport)
	// Call the HTTPDialShim for the DefaultTransport to
	// facilitate testing use of OutgoingAccessAllowed.
	defaultTransport = DialContextMiddleware(NewLocalDialBreaker(true))(defaultTransport)
	// Call our own proxy function with the DefaultTransport.
	http.DefaultTransport = ProxyMiddleware(defaultTransport)
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

// Option to be passed into the transport construction to customize the
// default transport.
type Option func(*options)

type options struct {
	caCertificates           []string
	cookieJar                http.CookieJar
	disableKeepAlives        bool
	skipHostnameVerification bool
	tlsHandshakeTimeout      time.Duration
	middlewares              []TransportMiddleware
	httpClient               *http.Client
	logger                   Logger
}

// WithCACertificates contains Authority certificates to be used to validate
// certificates of cloud infrastructure components.
// The contents are Base64 encoded x.509 certs.
func WithCACertificates(value ...string) Option {
	return func(opt *options) {
		opt.caCertificates = value
	}
}

// WithCookieJar is used to insert relevant cookies into every
// outbound Request and is updated with the cookie values
// of every inbound Response. The Jar is consulted for every
// redirect that the Client follows.
//
// If Jar is nil, cookies are only sent if they are explicitly
// set on the Request.
func WithCookieJar(value http.CookieJar) Option {
	return func(opt *options) {
		opt.cookieJar = value
	}
}

// WithDisableKeepAlives will disable HTTP keep alives, not TCP keep alives.
// Disabling HTTP keep alives will only use the connection to the server for a
// single HTTP request creating a lot of garbage for the collector.
func WithDisableKeepAlives(value bool) Option {
	return func(opt *options) {
		opt.disableKeepAlives = value
	}
}

// WithSkipHostnameVerification will skip hostname verification on the TLS/SSL
// certificates.
func WithSkipHostnameVerification(value bool) Option {
	return func(opt *options) {
		opt.skipHostnameVerification = value
	}
}

// WithTLSHandshakeTimeout will modify how long a TLS handshake should take.
// Setting the value to zero will mean that no timeout will occur.
func WithTLSHandshakeTimeout(value time.Duration) Option {
	return func(opt *options) {
		opt.tlsHandshakeTimeout = value
	}
}

// WithTransportMiddlewares allows the wrapping or modification of the existing
// transport for a given client.
// In an ideal world, all transports should be cloned to prevent the
// modification of an existing client transport.
func WithTransportMiddlewares(middlewares ...TransportMiddleware) Option {
	return func(opt *options) {
		opt.middlewares = middlewares
	}
}

// WithHTTPClient allows to define the http.Client to use.
func WithHTTPClient(value *http.Client) Option {
	return func(opt *options) {
		opt.httpClient = value
	}
}

// WithLogger defines a logger to use with the client.
func WithLogger(value Logger) Option {
	return func(opt *options) {
		opt.logger = value
	}
}

// Create a options instance with default values.
func newOptions() *options {
	// In this case, use a default http.Client.
	// Ideally we should always use the NewHTTPTLSTransport,
	// however test suites such as JujuConnSuite and some facade
	// tests rely on settings to the http.DefaultTransport for
	// tests to run with different protocol scheme such as "test"
	// and some replace the RoundTripper to answer test scenarios.
	//
	// https://bugs.launchpad.net/juju/+bug/1888888
	defaultCopy := *http.DefaultClient

	return &options{
		disableKeepAlives:        false,
		skipHostnameVerification: false,
		middlewares: []TransportMiddleware{
			DialContextMiddleware(NewLocalDialBreaker(true)),
			FileProtocolMiddleware,
			ProxyMiddleware,
		},
		httpClient: &defaultCopy,
		logger:     loggo.GetLogger("http"),
	}
}

// Client represents an http client.
type Client struct {
	HTTPClient

	logger Logger
}

// NewClient returns a new juju http client defined
// by the given config.
func NewClient(options ...Option) *Client {
	opts := newOptions()
	for _, option := range options {
		option(opts)
	}

	client := opts.httpClient
	transport := DefaultHTTPTransportWithMiddlewares(opts.middlewares)
	switch {
	case len(opts.caCertificates) > 0:
		transport = transportWithCerts(transport, opts.caCertificates, opts.skipHostnameVerification)
	case opts.skipHostnameVerification:
		transport = transportWithSkipVerify(transport, opts.skipHostnameVerification)
	}
	client.Transport = transport

	if opts.cookieJar != nil {
		client.Jar = opts.cookieJar
	}
	return &Client{
		HTTPClient: client,
		logger:     opts.logger,
	}
}

func transportWithSkipVerify(defaultTransport *http.Transport, skipHostnameVerify bool) *http.Transport {
	transport := defaultTransport
	// We know that the DefaultHTTPTransport doesn't create a tls.Config here
	// so we can safely do that here.
	transport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: skipHostnameVerify,
	}
	// We're creating a new tls.Config, HTTP/2 requests will not work, force the
	// client to create a HTTP/2 requests.
	transport.ForceAttemptHTTP2 = true
	return transport
}

func transportWithCerts(defaultTransport *http.Transport, caCerts []string, skipHostnameVerify bool) *http.Transport {
	pool := x509.NewCertPool()
	for _, cert := range caCerts {
		pool.AppendCertsFromPEM([]byte(cert))
	}

	tlsConfig := SecureTLSConfig()
	tlsConfig.RootCAs = pool
	tlsConfig.InsecureSkipVerify = skipHostnameVerify

	transport := defaultTransport
	transport.TLSClientConfig = tlsConfig

	// We're creating a new tls.Config, HTTP/2 requests will not work, force the
	// client to create a HTTP/2 requests.
	transport.ForceAttemptHTTP2 = true
	return transport
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
	*req = *req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	return nil
}

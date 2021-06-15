// Copyright 2021 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.
package http

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/juju/errors"
)

// FileProtocolMiddleware registers support for file:// URLs on the given transport.
func FileProtocolMiddleware(transport *http.Transport) *http.Transport {
	transport.RegisterProtocol("file", http.NewFileTransport(http.Dir("/")))
	return transport
}

// DialBreaker replicates a highly specialized CircuitBreaker pattern, which
// takes into account the current address.
type DialBreaker interface {
	// Allowed checks to see if a given address is allowed.
	Allowed(string) bool
	// Trip will cause the DialBreaker to change the breaker state
	Trip()
}

func isLocalAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return host == "localhost" || net.ParseIP(host).IsLoopback()
}

// DialContextMiddleware patches the default HTTP transport so
// that it fails when an attempt is made to dial a non-local
// host.
func DialContextMiddleware(breaker DialBreaker) TransportMiddleware {
	return func(transport *http.Transport) *http.Transport {
		dialer := &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if !breaker.Allowed(addr) {
				return nil, errors.Errorf("access to address %q not allowed", addr)
			}

			return dialer.DialContext(ctx, network, addr)
		}
		return transport
	}
}

// LocalDialBreaker defines a DialBreaker that when tripped only allows local
// dials, anything else is prevented.
type LocalDialBreaker struct {
	allowOutgoingAccess bool
}

// NewLocalDialBreaker creates a new LocalDialBreaker with a default value.
func NewLocalDialBreaker(allowOutgoingAccess bool) *LocalDialBreaker {
	return &LocalDialBreaker{
		allowOutgoingAccess: allowOutgoingAccess,
	}
}

// Allowed checks to see if a dial is allowed to happen, or returns an error
// stating why.
func (b *LocalDialBreaker) Allowed(addr string) bool {
	if b.allowOutgoingAccess {
		return true
	}
	// If we're not allowing outgoing access, then only local addresses are
	// allowed to be dialed. Check for local only addresses.
	return isLocalAddr(addr)
}

// Trip inverts the local state of the DialBreaker.
func (b *LocalDialBreaker) Trip() {
	b.allowOutgoingAccess = !b.allowOutgoingAccess
}

// ProxyMiddleware adds a Proxy to the given transport. This implementation
// uses the http.ProxyFromEnvironment.
func ProxyMiddleware(transport *http.Transport) *http.Transport {
	transport.Proxy = http.ProxyFromEnvironment
	return transport
}

// ForceAttemptHTTP2Middleware forces a HTTP/2 connection if a non-zero
// Dial, DialTLS, or DialContext func or TLSClientConfig is provided to the
// Transport. Using any of these will render HTTP/2 disabled, so force the
// client to use it for requests.
func ForceAttemptHTTP2Middleware(transport *http.Transport) *http.Transport {
	transport.ForceAttemptHTTP2 = true
	return transport
}

// RequestRecorder is implemented by types that can record information about
// successful and unsuccessful http requests.
type RequestRecorder interface {
	// Record an outgoing request which produced an http.Response.
	Record(method string, url *url.URL, res *http.Response, rtt time.Duration)

	// Record an outgoing request which returned back an error.
	RecordError(method string, url *url.URL, err error)
}

type roundTripRecorder struct {
	requestRecorder     RequestRecorder
	wrappedRoundTripper http.RoundTripper
}

// RoundTrip implements http.RoundTripper. If delegates the request to the
// wrapped RoundTripper and invokes the appropriate RequestRecorder methods
// depending on the outcome.
func (lr roundTripRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	res, err := lr.wrappedRoundTripper.RoundTrip(req)
	rtt := time.Since(start)

	if err != nil {
		lr.requestRecorder.RecordError(req.Method, req.URL, err)
	} else {
		lr.requestRecorder.Record(req.Method, req.URL, res, rtt)
	}

	return res, err
}

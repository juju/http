// Copyright 2020 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package http

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/http/httpproxy"
)

// registerFileProtocol registers support for file:// URLs on the given transport.
func registerFileProtocol(transport *http.Transport) {
	transport.RegisterProtocol("file", http.NewFileTransport(http.Dir("/")))
}

var ctxtDialer = &net.Dialer{
	Timeout:   30 * time.Second,
	KeepAlive: 30 * time.Second,
}

// OutgoingAccessAllowed determines whether connections other than
// localhost can be dialled.  Used for testing via the juju conn suite
// and the base suite.
//
var OutgoingAccessAllowed = true

func isLocalAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return host == "localhost" || net.ParseIP(host).IsLoopback()
}

// installHTTPDialShim patches the default HTTP transport so
// that it fails when an attempt is made to dial a non-local
// host.
func installHTTPDialShim(t *http.Transport) {
	t.DialContext = func(ctxt context.Context, network, addr string) (net.Conn, error) {
		if !OutgoingAccessAllowed && !isLocalAddr(addr) {
			return nil, fmt.Errorf("access to address %q not allowed", addr)
		}
		return ctxtDialer.DialContext(ctxt, network, addr)
	}
}

// installProxyShim set a new proxy func so that we do not
// cache proxy settings.
func installProxyShim(t *http.Transport) {
	t.Proxy = getProxy
}

func getProxy(req *http.Request) (*url.URL, error) {
	// Get proxy config new for each client.  Go will cache the proxy
	// settings for a process, this is a problem for long running programs.
	// And caused changes in proxy settings via model-config not to
	// be used.
	return httpproxy.FromEnvironment().ProxyFunc()(req.URL)
}

// BasicAuthHeader creates a header that contains just the "Authorization"
// entry.  The implementation was originally taked from net/http but this is
// needed externally from the http request object in order to use this with
// our websockets. See 2 (end of page 4) http://www.ietf.org/rfc/rfc2617.txt
// "To receive authorization, the client sends the userid and password,
// separated by a single colon (":") character, within a base64 encoded string
// in the credentials."
func BasicAuthHeader(username, password string) http.Header {
	auth := username + ":" + password
	encoded := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
	return http.Header{
		"Authorization": {encoded},
	}
}

// ParseBasicAuth attempts to find an Authorization header in the supplied
// http.Header and if found parses it as a Basic header. See 2 (end of page 4)
// http://www.ietf.org/rfc/rfc2617.txt "To receive authorization, the client
// sends the userid and password, separated by a single colon (":") character,
// within a base64 encoded string in the credentials."
func ParseBasicAuthHeader(h http.Header) (userid, password string, err error) {
	parts := strings.Fields(h.Get("Authorization"))
	if len(parts) != 2 || parts[0] != "Basic" {
		return "", "", fmt.Errorf("invalid or missing HTTP auth header")
	}
	// Challenge is a base64-encoded "tag:pass" string.
	// See RFC 2617, Section 2.
	challenge, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", fmt.Errorf("invalid HTTP auth encoding")
	}
	tokens := strings.SplitN(string(challenge), ":", 2)
	if len(tokens) != 2 {
		return "", "", fmt.Errorf("invalid HTTP auth contents")
	}
	return tokens[0], tokens[1], nil
}

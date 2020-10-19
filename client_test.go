// Copyright 2020 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package http

import (
	"bytes"
	"context"
	"encoding/pem"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"

	"github.com/juju/testing"
	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"
)

type clientSuite struct {
}

var _ = gc.Suite(&clientSuite{})

func (s *clientSuite) TestNewClient(c *gc.C) {
	client := NewClient(Config{})
	c.Assert(client, gc.NotNil)
}

var isLocalAddrTests = []struct {
	addr    string
	isLocal bool
}{
	{"localhost:456", true},
	{"127.0.0.1:1234", true},
	{"[::1]:4567", true},
	{"localhost:smtp", true},
	{"123.45.67.5", false},
	{"0.1.2.3", false},
	{"10.0.43.6:12345", false},
	{":456", false},
	{"12xz4.5.6", false},
}

func (s *clientSuite) TestIsLocalAddr(c *gc.C) {
	for i, test := range isLocalAddrTests {
		c.Logf("test %d: %v", i, test.addr)
		c.Assert(isLocalAddr(test.addr), gc.Equals, test.isLocal)
	}
}

type httpNoOutgoingAccessSuite struct {
	testing.IsolationSuite
}

var _ = gc.Suite(&httpNoOutgoingAccessSuite{})

func (s *httpNoOutgoingAccessSuite) TestInsecureClientNoAccess(c *gc.C) {
	s.PatchValue(&OutgoingAccessAllowed, false)
	cfg := Config{
		SkipHostnameVerification: true,
	}
	client := NewClient(cfg)
	_, err := client.Get(context.TODO(), "http://0.1.2.3:1234")
	c.Assert(err, gc.ErrorMatches, `.*access to address "0.1.2.3:1234" not allowed`)
}

func (s *httpNoOutgoingAccessSuite) TestSecureClientNoAccess(c *gc.C) {
	s.PatchValue(&OutgoingAccessAllowed, false)
	client := NewClient(Config{})
	_, err := client.Get(context.TODO(), "http://0.1.2.3:1234")
	c.Assert(err, gc.ErrorMatches, `.*access to address "0.1.2.3:1234" not allowed`)
}

type httpSuite struct {
	testing.IsolationSuite
	server *httptest.Server
}

var _ = gc.Suite(&httpSuite{})

func (s *httpSuite) SetUpTest(c *gc.C) {
	s.IsolationSuite.SetUpTest(c)
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
}

func (s *httpSuite) TestInsecureClientAllowAccess(c *gc.C) {
	cfg := Config{SkipHostnameVerification: true}
	client := NewClient(cfg)
	_, err := client.Get(context.TODO(), s.server.URL)
	c.Assert(err, jc.ErrorIsNil)
}

func (s *httpSuite) TestSecureClientAllowAccess(c *gc.C) {
	client := NewClient(Config{})
	_, err := client.Get(context.TODO(), s.server.URL)
	c.Assert(err, jc.ErrorIsNil)
}

// NewClient with a default config used to overwrite http.DefaultClient.Jar
// field; add a regression test for that.
func (s *httpSuite) TestDefaultClientJarNotOverwritten(c *gc.C) {
	oldJar := http.DefaultClient.Jar

	jar, err := cookiejar.New(nil)
	c.Assert(err, jc.ErrorIsNil)
	client := NewClient(Config{Jar: jar})

	hc := client.HTTPClient.(*http.Client)
	c.Assert(hc.Jar, gc.Equals, jar)
	c.Assert(http.DefaultClient.Jar, gc.Not(gc.Equals), jar)
	c.Assert(http.DefaultClient.Jar, gc.Equals, oldJar)

	http.DefaultClient.Jar = oldJar
}

type httpTLSServerSuite struct {
	testing.IsolationSuite
	server *httptest.Server
}

var _ = gc.Suite(&httpTLSServerSuite{})

func (s *httpTLSServerSuite) SetUpTest(c *gc.C) {
	s.IsolationSuite.SetUpTest(c)
	// NewTLSServer returns a server which serves TLS, but
	// its certificates are not validated by the default
	// OS certificates, so any HTTPS request will fail
	// unless a non-validating client is used.
	s.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
}

func (s *httpTLSServerSuite) TearDownTest(c *gc.C) {
	if s.server != nil {
		s.server.Close()
	}
	s.IsolationSuite.TearDownTest(c)
}

func (s *httpTLSServerSuite) TestValidatingClientGetter(c *gc.C) {
	client := NewClient(Config{})
	_, err := client.Get(context.TODO(), s.server.URL)
	c.Assert(err, gc.ErrorMatches, "(.|\n)*x509: certificate signed by unknown authority")

	client1 := NewClient(Config{})
	c.Assert(client1, gc.Not(gc.Equals), client)
}

func (s *httpTLSServerSuite) TestNonValidatingClientGetter(c *gc.C) {
	cfg := Config{SkipHostnameVerification: true}
	client := NewClient(cfg)
	resp, err := client.Get(context.TODO(), s.server.URL)
	c.Assert(err, gc.IsNil)
	_ = resp.Body.Close()
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)

	client1 := NewClient(cfg)
	c.Assert(client1, gc.Not(gc.Equals), client)
}

func (s *httpTLSServerSuite) TestGetHTTPClientWithCertsVerify(c *gc.C) {
	s.testGetHTTPClientWithCerts(c, true)
}

func (s *httpTLSServerSuite) TestGetHTTPClientWithCertsNoVerify(c *gc.C) {
	s.testGetHTTPClientWithCerts(c, false)
}

func (s *httpTLSServerSuite) testGetHTTPClientWithCerts(c *gc.C, skip bool) {
	caPEM := new(bytes.Buffer)
	err := pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: s.server.Certificate().Raw,
	})
	c.Assert(err, gc.IsNil)
	cfg := Config{
		CACertificates:           []string{caPEM.String()},
		SkipHostnameVerification: true,
	}
	client := NewClient(cfg)
	resp, err := client.Get(context.TODO(), s.server.URL)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.Body.Close(), gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
}

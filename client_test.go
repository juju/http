// Copyright 2020 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package http

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	url "net/url"
	"time"

	gomock "github.com/golang/mock/gomock"
	"github.com/juju/testing"
	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"
)

type clientSuite struct {
}

var _ = gc.Suite(&clientSuite{})

func (s *clientSuite) TestNewClient(c *gc.C) {
	client := NewClient()
	c.Assert(client, gc.NotNil)
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
	client := NewClient(WithSkipHostnameVerification(true))
	_, err := client.Get(context.TODO(), s.server.URL)
	c.Assert(err, jc.ErrorIsNil)
}

func (s *httpSuite) TestSecureClientAllowAccess(c *gc.C) {
	client := NewClient()
	_, err := client.Get(context.TODO(), s.server.URL)
	c.Assert(err, jc.ErrorIsNil)
}

// NewClient with a default config used to overwrite http.DefaultClient.Jar
// field; add a regression test for that.
func (s *httpSuite) TestDefaultClientJarNotOverwritten(c *gc.C) {
	oldJar := http.DefaultClient.Jar

	jar, err := cookiejar.New(nil)
	c.Assert(err, jc.ErrorIsNil)

	client := NewClient(WithCookieJar(jar))

	hc := client.HTTPClient.(*http.Client)
	c.Assert(hc.Jar, gc.Equals, jar)
	c.Assert(http.DefaultClient.Jar, gc.Not(gc.Equals), jar)
	c.Assert(http.DefaultClient.Jar, gc.Equals, oldJar)

	http.DefaultClient.Jar = oldJar
}

func (s *httpSuite) TestRequestRecorder(c *gc.C) {
	ctrl := gomock.NewController(c)
	defer ctrl.Finish()

	dummyServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		_, _ = fmt.Fprintln(res, "they are listening...")
	}))
	defer dummyServer.Close()

	validTarget := fmt.Sprintf("%s/tin/foil", dummyServer.URL)
	validTargetURL, err := url.Parse(validTarget)
	c.Assert(err, jc.ErrorIsNil)

	invalidTarget := "btc://secret/wallet"
	invalidTargetURL, err := url.Parse(invalidTarget)
	c.Assert(err, jc.ErrorIsNil)

	recorder := NewMockRequestRecorder(ctrl)
	recorder.EXPECT().Record("GET", validTargetURL, gomock.AssignableToTypeOf(&http.Response{}), gomock.AssignableToTypeOf(time.Duration(42)))
	recorder.EXPECT().RecordError("PUT", invalidTargetURL, gomock.AssignableToTypeOf(errors.New("")))

	client := NewClient(WithRequestRecorder(recorder))
	res, err := client.Get(context.TODO(), validTarget)
	c.Assert(err, jc.ErrorIsNil)
	defer res.Body.Close()

	req, err := http.NewRequestWithContext(context.TODO(), "PUT", invalidTarget, nil)
	c.Assert(err, jc.ErrorIsNil)
	_, err = client.Do(req)
	c.Assert(err, gc.Not(jc.ErrorIsNil))
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
	client := NewClient()
	_, err := client.Get(context.TODO(), s.server.URL)
	c.Assert(err, gc.ErrorMatches, "(.|\n)*x509: certificate signed by unknown authority")
}

func (s *httpTLSServerSuite) TestNonValidatingClientGetter(c *gc.C) {
	client := NewClient(WithSkipHostnameVerification(true))
	resp, err := client.Get(context.TODO(), s.server.URL)
	c.Assert(err, gc.IsNil)
	_ = resp.Body.Close()
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
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

	client := NewClient(
		WithCACertificates(caPEM.String()),
		WithSkipHostnameVerification(true),
	)
	resp, err := client.Get(context.TODO(), s.server.URL)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.Body.Close(), gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
}

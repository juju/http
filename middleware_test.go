// Copyright 2021 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.
package http

import (
	"context"

	"github.com/juju/testing"
	gc "gopkg.in/check.v1"
)

type DialContextMiddlewareSuite struct {
	testing.IsolationSuite
}

var _ = gc.Suite(&DialContextMiddlewareSuite{})

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

func (s *DialContextMiddlewareSuite) TestIsLocalAddr(c *gc.C) {
	for i, test := range isLocalAddrTests {
		c.Logf("test %d: %v", i, test.addr)
		c.Assert(isLocalAddr(test.addr), gc.Equals, test.isLocal)
	}
}

func (s *DialContextMiddlewareSuite) TestInsecureClientNoAccess(c *gc.C) {
	client := NewClient(
		WithTransportMiddlewares(
			DialContextMiddleware(NewLocalDialBreaker(false)),
		),
		WithSkipHostnameVerification(true),
	)
	_, err := client.Get(context.TODO(), "http://0.1.2.3:1234")
	c.Assert(err, gc.ErrorMatches, `.*access to address "0.1.2.3:1234" not allowed`)
}

func (s *DialContextMiddlewareSuite) TestSecureClientNoAccess(c *gc.C) {
	client := NewClient(
		WithTransportMiddlewares(
			DialContextMiddleware(NewLocalDialBreaker(false)),
		),
	)
	_, err := client.Get(context.TODO(), "http://0.1.2.3:1234")
	c.Assert(err, gc.ErrorMatches, `.*access to address "0.1.2.3:1234" not allowed`)
}

type LocalDialBreakerSuite struct {
	testing.IsolationSuite
}

var _ = gc.Suite(&LocalDialBreakerSuite{})

func (s *LocalDialBreakerSuite) TestAllowed(c *gc.C) {
	breaker := NewLocalDialBreaker(true)

	for i, test := range isLocalAddrTests {
		c.Logf("test %d: %v", i, test.addr)
		allowed := breaker.Allowed(test.addr)
		c.Assert(allowed, gc.Equals, true)
	}
}

func (s *LocalDialBreakerSuite) TestLocalAllowed(c *gc.C) {
	breaker := NewLocalDialBreaker(false)

	for i, test := range isLocalAddrTests {
		c.Logf("test %d: %v", i, test.addr)
		allowed := breaker.Allowed(test.addr)
		c.Assert(allowed, gc.Equals, test.isLocal)
	}
}

func (s *LocalDialBreakerSuite) TestLocalAllowedAfterTrip(c *gc.C) {
	breaker := NewLocalDialBreaker(true)

	for i, test := range isLocalAddrTests {
		c.Logf("test %d: %v", i, test.addr)
		allowed := breaker.Allowed(test.addr)
		c.Assert(allowed, gc.Equals, true)

		breaker.Trip()

		allowed = breaker.Allowed(test.addr)
		c.Assert(allowed, gc.Equals, test.isLocal)

		// Reset the breaker.
		breaker.Trip()
	}
}

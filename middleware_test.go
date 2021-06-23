// Copyright 2021 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.
package http

import (
	"context"
	"net/http"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/juju/clock"
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

type RetrySuite struct {
	testing.IsolationSuite
}

var _ = gc.Suite(&RetrySuite{})

func (s *RetrySuite) TestRetryNotRequired(c *gc.C) {
	ctrl := gomock.NewController(c)
	defer ctrl.Finish()

	req, err := http.NewRequest("GET", "http://meshuggah.rocks", nil)
	c.Assert(err, gc.IsNil)

	transport := NewMockRoundTripper(ctrl)
	transport.EXPECT().RoundTrip(req).Return(&http.Response{
		StatusCode: http.StatusOK,
	}, nil)

	middleware := makeRetryMiddleware(transport, RetryPolicy{
		Attempts: 3,
		Delay:    time.Second,
		MaxDelay: time.Minute,
	}, clock.WallClock, logger(ctrl))

	resp, err := middleware.RoundTrip(req)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
}

func (s *RetrySuite) TestRetryRequired(c *gc.C) {
	ctrl := gomock.NewController(c)
	defer ctrl.Finish()

	req, err := http.NewRequest("GET", "http://meshuggah.rocks", nil)
	c.Assert(err, gc.IsNil)

	transport := NewMockRoundTripper(ctrl)
	transport.EXPECT().RoundTrip(req).Return(&http.Response{
		StatusCode: http.StatusBadGateway,
	}, nil).Times(2)
	transport.EXPECT().RoundTrip(req).Return(&http.Response{
		StatusCode: http.StatusOK,
	}, nil)

	ch := make(chan time.Time)

	clock := NewMockClock(ctrl)
	clock.EXPECT().Now().Return(time.Now()).AnyTimes()
	clock.EXPECT().After(gomock.Any()).Return(ch).AnyTimes()

	retries := 3
	go func() {
		for i := 0; i < retries; i++ {
			ch <- time.Now()
		}
	}()

	middleware := makeRetryMiddleware(transport, RetryPolicy{
		Attempts: retries,
		Delay:    time.Second,
		MaxDelay: time.Minute,
	}, clock, logger(ctrl))

	resp, err := middleware.RoundTrip(req)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
}

func (s *RetrySuite) TestRetryRequiredUsingBackoff(c *gc.C) {
	ctrl := gomock.NewController(c)
	defer ctrl.Finish()

	req, err := http.NewRequest("GET", "http://meshuggah.rocks", nil)
	c.Assert(err, gc.IsNil)

	header := make(http.Header)
	header.Add("Retry-After", "42")

	transport := NewMockRoundTripper(ctrl)
	transport.EXPECT().RoundTrip(req).Return(&http.Response{
		StatusCode: http.StatusTooManyRequests,
		Header:     header,
	}, nil).Times(2)
	transport.EXPECT().RoundTrip(req).Return(&http.Response{
		StatusCode: http.StatusOK,
	}, nil)

	ch := make(chan time.Time)

	clock := NewMockClock(ctrl)
	clock.EXPECT().Now().Return(time.Now()).AnyTimes()
	clock.EXPECT().After(time.Second * 42).Return(ch).Times(2)

	retries := 3
	go func() {
		for i := 0; i < retries; i++ {
			ch <- time.Now()
		}
	}()

	middleware := makeRetryMiddleware(transport, RetryPolicy{
		Attempts: retries,
		Delay:    time.Second,
		MaxDelay: time.Minute,
	}, clock, logger(ctrl))

	resp, err := middleware.RoundTrip(req)
	c.Assert(err, gc.IsNil)
	c.Assert(resp.StatusCode, gc.Equals, http.StatusOK)
}

func (s *RetrySuite) TestRetryRequiredUsingBackoffFailure(c *gc.C) {
	ctrl := gomock.NewController(c)
	defer ctrl.Finish()

	req, err := http.NewRequest("GET", "http://meshuggah.rocks", nil)
	c.Assert(err, gc.IsNil)

	header := make(http.Header)
	header.Add("Retry-After", "2520")

	transport := NewMockRoundTripper(ctrl)
	transport.EXPECT().RoundTrip(req).Return(&http.Response{
		StatusCode: http.StatusTooManyRequests,
		Header:     header,
	}, nil)

	ch := make(chan time.Time)

	clock := NewMockClock(ctrl)
	clock.EXPECT().Now().Return(time.Now()).AnyTimes()
	clock.EXPECT().After(time.Minute * 42).Return(ch)

	retries := 3
	go func() {
		ch <- time.Now()
	}()

	middleware := makeRetryMiddleware(transport, RetryPolicy{
		Attempts: retries,
		Delay:    time.Minute,
		MaxDelay: time.Second,
	}, clock, logger(ctrl))

	_, err = middleware.RoundTrip(req)
	c.Assert(err, gc.ErrorMatches, `API request retry is not accepting further requests until .*`)
}

func (s *RetrySuite) TestRetryRequiredUsingBackoffError(c *gc.C) {
	ctrl := gomock.NewController(c)
	defer ctrl.Finish()

	req, err := http.NewRequest("GET", "http://meshuggah.rocks", nil)
	c.Assert(err, gc.IsNil)

	header := make(http.Header)
	header.Add("Retry-After", "!@1234391asd--\\123")

	transport := NewMockRoundTripper(ctrl)
	transport.EXPECT().RoundTrip(req).Return(&http.Response{
		StatusCode: http.StatusTooManyRequests,
		Header:     header,
	}, nil)

	ch := make(chan time.Time)

	clock := NewMockClock(ctrl)
	clock.EXPECT().Now().Return(time.Now()).AnyTimes()
	clock.EXPECT().After(time.Minute * 1).Return(ch)

	retries := 3
	go func() {
		ch <- time.Now()
	}()

	middleware := makeRetryMiddleware(transport, RetryPolicy{
		Attempts: retries,
		Delay:    time.Minute,
		MaxDelay: time.Second,
	}, clock, logger(ctrl))

	_, err = middleware.RoundTrip(req)
	c.Assert(err, gc.ErrorMatches, `API request retry is not accepting further requests until .*`)
}

func (s *RetrySuite) TestRetryRequiredAndExceeded(c *gc.C) {
	ctrl := gomock.NewController(c)
	defer ctrl.Finish()

	req, err := http.NewRequest("GET", "http://meshuggah.rocks", nil)
	c.Assert(err, gc.IsNil)

	transport := NewMockRoundTripper(ctrl)
	transport.EXPECT().RoundTrip(req).Return(&http.Response{
		StatusCode: http.StatusBadGateway,
	}, nil).Times(3)

	ch := make(chan time.Time)

	clock := NewMockClock(ctrl)
	clock.EXPECT().Now().Return(time.Now()).AnyTimes()
	clock.EXPECT().After(gomock.Any()).Return(ch).AnyTimes()

	retries := 3
	go func() {
		for i := 0; i < retries; i++ {
			ch <- time.Now()
		}
	}()

	middleware := makeRetryMiddleware(transport, RetryPolicy{
		Attempts: retries,
		Delay:    time.Second,
		MaxDelay: time.Minute,
	}, clock, logger(ctrl))

	_, err = middleware.RoundTrip(req)
	c.Assert(err, gc.ErrorMatches, `attempt count exceeded: retryable error`)
}

func (s *RetrySuite) TestRetryRequiredContextKilled(c *gc.C) {
	ctrl := gomock.NewController(c)
	defer ctrl.Finish()

	ctx, cancel := context.WithCancel(context.Background())

	req, err := http.NewRequestWithContext(ctx, "GET", "http://meshuggah.rocks", nil)
	c.Assert(err, gc.IsNil)

	transport := NewMockRoundTripper(ctrl)

	clock := NewMockClock(ctrl)
	clock.EXPECT().Now().Return(time.Now())

	middleware := makeRetryMiddleware(transport, RetryPolicy{
		Attempts: 3,
		Delay:    time.Second,
	}, clock, logger(ctrl))

	// Nothing should run, the context has been cancelled.
	cancel()

	_, err = middleware.RoundTrip(req)
	c.Assert(err, gc.ErrorMatches, `context canceled`)
}

func logger(ctrl *gomock.Controller) Logger {
	logger := NewMockLogger(ctrl)
	logger.EXPECT().IsTraceEnabled().Return(false).AnyTimes()
	logger.EXPECT().Tracef(gomock.Any(), gomock.Any()).AnyTimes()
	logger.EXPECT().Errorf(gomock.Any(), gomock.Any()).AnyTimes()
	return logger
}

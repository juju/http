// Copyright 2020 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package http_test

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/juju/testing"
	gc "gopkg.in/check.v1"

	jujuhttp "github.com/juju/http/v2"
)

type httpSuite struct {
	testing.IsolationSuite
}

var _ = gc.Suite(&httpSuite{})

func (s *httpSuite) TestBasicAuthHeader(c *gc.C) {
	header := jujuhttp.BasicAuthHeader("eric", "sekrit")
	c.Assert(len(header), gc.Equals, 1)
	auth := header.Get("Authorization")
	fields := strings.Fields(auth)
	c.Assert(len(fields), gc.Equals, 2)
	basic, encoded := fields[0], fields[1]
	c.Assert(basic, gc.Equals, "Basic")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	c.Assert(err, gc.IsNil)
	c.Assert(string(decoded), gc.Equals, "eric:sekrit")
}

func (s *httpSuite) TestParseBasicAuthHeader(c *gc.C) {
	tests := []struct {
		about          string
		h              http.Header
		expectUserid   string
		expectPassword string
		expectError    string
	}{{
		about:       "no Authorization header",
		h:           http.Header{},
		expectError: "invalid or missing HTTP auth header",
	}, {
		about: "empty Authorization header",
		h: http.Header{
			"Authorization": {""},
		},
		expectError: "invalid or missing HTTP auth header",
	}, {
		about: "Not basic encoding",
		h: http.Header{
			"Authorization": {"NotBasic stuff"},
		},
		expectError: "invalid or missing HTTP auth header",
	}, {
		about: "invalid base64",
		h: http.Header{
			"Authorization": {"Basic not-base64"},
		},
		expectError: "invalid HTTP auth encoding",
	}, {
		about: "no ':'",
		h: http.Header{
			"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("aladdin"))},
		},
		expectError: "invalid HTTP auth contents",
	}, {
		about: "valid credentials",
		h: http.Header{
			"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("aladdin:open sesame"))},
		},
		expectUserid:   "aladdin",
		expectPassword: "open sesame",
	}}
	for i, test := range tests {
		c.Logf("test %d: %s", i, test.about)
		u, p, err := jujuhttp.ParseBasicAuthHeader(test.h)
		c.Assert(u, gc.Equals, test.expectUserid)
		c.Assert(p, gc.Equals, test.expectPassword)
		if test.expectError != "" {
			c.Assert(err.Error(), gc.Equals, test.expectError)
		} else {
			c.Assert(err, gc.IsNil)
		}
	}
}

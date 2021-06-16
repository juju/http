// Copyright 2020 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package http

import (
	"testing"

	gc "gopkg.in/check.v1"
)

//go:generate go run github.com/golang/mock/mockgen -package http -destination client_mock_test.go . HTTPClient,RequestRecorder

func Test(t *testing.T) {
	gc.TestingT(t)
}

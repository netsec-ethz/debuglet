// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"errors"
	"net/http"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestUnclassifiedHTTPMessagesAreNotPublic(t *testing.T) {
	const detail = "private fixture diagnostic and stack"
	cause := errors.New("private fixture database detail")
	for _, code := range []int{http.StatusBadRequest, http.StatusInternalServerError} {
		failure := echo.NewHTTPError(code, detail).SetInternal(cause)
		gotStatus, body, internal := errorEnvelope(failure)
		if gotStatus != code || body.Code != codeForStatus(code) || body.Message != http.StatusText(code) || !errors.Is(internal, cause) {
			t.Fatalf("unclassified error boundary changed: %d %+v %v", gotStatus, body, internal)
		}
	}
	status, body, internal := errorEnvelope(apiErrorFrom(http.StatusBadRequest, CodeInvalidPolicy, "timeout_ms must be positive", cause))
	if status != http.StatusBadRequest || body.Code != CodeInvalidPolicy || body.Message != "timeout_ms must be positive" || !errors.Is(internal, cause) {
		t.Fatalf("explicit public diagnostic lost: %d %+v %v", status, body, internal)
	}
}

func TestBodyDecoderMessagesAreNotPublic(t *testing.T) {
	decoder := echo.NewHTTPError(http.StatusBadRequest, "invalid field value fixture-account-key").SetInternal(errors.New("fixture decoder failure"))
	status, body, internal := errorEnvelope(bindError(decoder))
	if status != http.StatusBadRequest || body.Code != CodeInvalidRequest || body.Message != "invalid request body" || internal != nil {
		t.Fatalf("decoder error boundary changed: %d %+v %v", status, body, internal)
	}
}

func TestPrivateHTTPCauseCannotReplacePublicEnvelope(t *testing.T) {
	cause := echo.NewHTTPError(http.StatusServiceUnavailable, "private dependency detail")
	status, body, internal := errorEnvelope(apiErrorFrom(http.StatusBadRequest, CodeInvalidPolicy, "invalid policy", cause))
	if status != http.StatusBadRequest || body.Code != CodeInvalidPolicy || body.Message != "invalid policy" || !errors.Is(internal, cause) {
		t.Fatalf("private cause replaced public contract: %d %+v %v", status, body, internal)
	}
}

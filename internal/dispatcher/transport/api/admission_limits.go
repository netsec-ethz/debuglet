// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/uploadsize"
)

const CodeAccountQuota = "account_quota_exceeded"

func (h *Handler) allowAdmissionRequest(c echo.Context, established *caller) error {
	var owner *uuid.UUID
	if id, ok := established.owner(); ok {
		owner = &id
	}
	if err := h.dispatcher.AllowAdmissionRequest(c.Request().Context(), owner); err != nil {
		return admissionError(c, err)
	}
	return nil
}

func admissionError(c echo.Context, err error) error {
	var quota *dispatcher.AccountQuotaError
	if errors.As(err, &quota) {
		if quota.RetryAfter > 0 {
			seconds := (quota.RetryAfter + time.Second - 1) / time.Second
			c.Response().Header().Set("Retry-After", strconv.FormatInt(int64(seconds), 10))
		}
		return apiErrorFrom(http.StatusTooManyRequests, CodeAccountQuota, quota.Error(), err)
	}
	if errors.Is(err, uploadsize.ErrLimit) {
		return apiErrorFrom(http.StatusRequestEntityTooLarge, CodePayloadTooLarge, "upload exceeds the decoded module, stored run or batch limit", err)
	}
	return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to check admission capacity", err)
}

// validateUploadBatch runs for both intent and submission, before pricing,
// hashing, decoded allocation or SQL writes. Padding is excluded from the
// decoded upper bound. Malformed WASM remains the submission decoder's concern.
func validateUploadBatch(requests []DebugletRequest) error {
	if len(requests) > uploadsize.MaxBatchRuns {
		return apiError(http.StatusRequestEntityTooLarge, CodePayloadTooLarge, "batch exceeds 128 runs")
	}
	for _, request := range requests {
		size := int64(base64.StdEncoding.DecodedLen(len(request.Wasm)))
		if strings.HasSuffix(request.Wasm, "==") {
			size -= 2
		} else if strings.HasSuffix(request.Wasm, "=") {
			size--
		}
		if size < 0 {
			size = 0
		}
		if _, err := uploadsize.StoredBytesForModule(size, request.Args, request.Policy.Addresses); err != nil {
			return apiError(http.StatusRequestEntityTooLarge, CodePayloadTooLarge, "upload exceeds the decoded module or stored run limit")
		}
	}
	return nil
}

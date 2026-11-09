// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/studio"
)

var generatedCodeDiagnostic = regexp.MustCompile(`(?m)^(?:\./)?main\.go:[0-9]+:[0-9]+:`)

// Reuse the hosted compiler and its account/global admission limits. This check
// is called only for custom code, after authentication and graph validation.
// The resulting bundle is not persisted, returned to the model or executed.
func (h *Handler) assistantCompileCheck(account uuid.UUID) studio.AssistantCompileCheck {
	return func(ctx context.Context, kind string, document json.RawMessage) (string, error) {
		unavailable := func() error {
			return echo.NewHTTPError(http.StatusServiceUnavailable, ErrorResponse{Code: CodeUnavailable, Reason: "compiler_unavailable",
				Message: "the build service could not check the AI's custom code; retry when it is available; your draft is unchanged"})
		}
		busy := func() error {
			return echo.NewHTTPError(http.StatusTooManyRequests, ErrorResponse{Code: CodeRateLimited, Reason: "compiler_busy",
				Message: "the build service is busy; retry shortly to check the AI's custom code; your draft is unchanged"})
		}
		if h.studio == nil {
			return "", unavailable()
		}
		if !h.studio.acquire(account) {
			return "", busy()
		}
		defer h.studio.release(account)
		path, limit := "/studio/build", int64(studioResponseLimit)
		if kind == "experiment" {
			path, limit = "/studio/experiments/build", studioExperimentResponseLimit
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://studio"+path, bytes.NewReader(document))
		if err != nil {
			return "", unavailable()
		}
		// Only source crosses this boundary, never browser or provider credentials.
		req.Header.Set("Content-Type", echo.MIMEApplicationJSON)
		req.Header.Set("Accept", echo.MIMEApplicationJSON)
		req.Header.Set("User-Agent", "")
		response, err := h.studio.client.Do(req)
		if err != nil {
			return "", unavailable()
		}
		defer response.Body.Close()
		if response.StatusCode == http.StatusTooManyRequests {
			return "", busy()
		}
		if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusUnprocessableEntity {
			return "", unavailable()
		}
		if response.StatusCode == http.StatusUnprocessableEntity {
			limit = 64 << 10
		}
		contentType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if err != nil || contentType != echo.MIMEApplicationJSON || response.ContentLength > limit {
			return "", unavailable()
		}
		data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
		if err != nil || int64(len(data)) > limit || !json.Valid(data) {
			return "", unavailable()
		}
		if response.StatusCode == http.StatusUnprocessableEntity {
			var failure struct {
				Error string `json:"error"`
			}
			// The worker also uses 422 for toolchain/setup failures. Only an
			// actual diagnostic in generated main.go can be repaired by the model.
			if json.Unmarshal(data, &failure) != nil || !strings.Contains(failure.Error, "compile workflow:") || !generatedCodeDiagnostic.MatchString(failure.Error) {
				return "", unavailable()
			}
			return failure.Error, nil
		}
		// A successful worker response must identify the document it compiled.
		var result struct {
			Version          int    `json:"version"`
			WorkflowSHA256   string `json:"workflow_sha256"`
			ExperimentSHA256 string `json:"experiment_sha256"`
		}
		if json.Unmarshal(data, &result) != nil || result.Version != 1 {
			return "", unavailable()
		}
		digest := result.WorkflowSHA256
		if kind == "experiment" {
			digest = result.ExperimentSHA256
		}
		if digest != studio.DocumentDigest(document) {
			return "", unavailable()
		}
		return "", nil
	}
}

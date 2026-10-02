// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
)

var credentialScopes = []string{"account:read", "executors:read", "executors:write", "measurements:read", "measurements:write"}

// API credentials narrow existing account access; they grant no dispatcher
// administration or identity-management authority.
var credentialRouteScopes = map[string]string{
	"GET /me": "account:read",
	"GET /auth/credential": "account:read",
	"GET /executors": "executors:read",
	"GET /executors/by-ip": "executors:read",
	"GET /executors/:id/tesla": "executors:read",
	"GET /operator/executors": "executors:read",
	"POST /operator/executors": "executors:write",
	"POST /operator/executors/:id/enrollment-token": "executors:write",
	"GET /list-debuglets": "measurements:read",
	"GET /debuglet/:id/logs": "measurements:read",
	"GET /debuglet/:id/state": "measurements:read",
	"GET /debuglet/:id/recovery": "measurements:read",
	"GET /debuglet/:id/cancellation": "measurements:read",
	"GET /debuglet/:id/result": "measurements:read",
	"GET /debuglet/:id/detail": "measurements:read",
	"GET /measurements": "measurements:read",
	"GET /measurements/:id": "measurements:read",
	"GET /measurement-templates": "measurements:read",
	"GET /measurement-profiles": "measurements:read",
	"GET /measurement-profiles/:id": "measurements:read",
	"GET /payment/:transaction_id/status": "measurements:read",
	"PUT /debuglet": "measurements:write",
	"DELETE /debuglet": "measurements:write",
	"DELETE /debuglet/:id/payload": "measurements:write",
	"PUT /payment/intent": "measurements:write",
	"POST /measurement-profiles": "measurements:write",
	"PUT /measurement-profiles/:id": "measurements:write",
	"DELETE /measurement-profiles/:id": "measurements:write",
}

func credentialAllows(scopes []string, method, path string) bool {
	if method == http.MethodPost && path == "/auth/logout" {
		return true
	}
	required, ok := credentialRouteScopes[method+" "+path]
	return ok && slices.Contains(scopes, required)
}

func normalizeCredentialScopes(scopes []string) (string, error) {
	if len(scopes) == 0 || len(scopes) > len(credentialScopes) {
		return "", apiError(http.StatusBadRequest, CodeInvalidRequest, "choose one or more supported credential scopes")
	}
	result := slices.Clone(scopes)
	for _, scope := range result {
		if !slices.Contains(credentialScopes, scope) {
			return "", apiError(http.StatusBadRequest, CodeInvalidRequest, "unsupported credential scope")
		}
	}
	slices.Sort(result)
	return strings.Join(slices.Compact(result), " "), nil
}

func requireRecentBrowserSession(c echo.Context) (*caller, error) {
	account, err := requireAccount(c)
	if err != nil {
		return nil, err
	}
	if account.API || !account.Cookie || account.CreatedAt.IsZero() || time.Since(account.CreatedAt) > 10*time.Minute {
		return nil, apiError(http.StatusForbidden, CodeForbidden, "sign in again in this browser before managing credentials or identities")
	}
	return account, nil
}

func newAuthLimiter() *addressLimiter { return newAddressLimiter(0.5, 10) }

func (h *Handler) limitAuthentication(c echo.Context) error {
	if err := h.authLimiter.allow(c); err != nil {
		return apiError(http.StatusTooManyRequests, CodeRateLimited, "too many authentication requests; retry later")
	}
	return nil
}

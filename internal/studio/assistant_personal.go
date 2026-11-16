// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"context"
	"net/http"
	"net/url"
)

// NewPersonalAssistant always sends account-owned credentials to OpenAI, never
// to an operator's custom endpoint. Its lifetime is one request.
func NewPersonalAssistant(model, key, reasoning string) (*Assistant, error) {
	return NewAssistant(AssistantConfig{Endpoint: "https://api.openai.com/v1/responses", Model: model, APIKey: key, ReasoningEffort: reasoning})
}

func (a *Assistant) Close() { a.client.CloseIdleConnections() }

// CheckAccess checks model access without generating tokens. It does not prove
// that a later generation will succeed or that the account has remaining funds.
func (a *Assistant) CheckAccess(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.openai.com/v1/models/"+url.PathEscape(a.model), nil)
	if err != nil {
		return assistantError("provider_unavailable", 0)
	}
	req.Header.Set("Authorization", "Bearer "+a.key)
	resp, err := a.client.Do(req)
	if err != nil {
		return assistantError("provider_unavailable", 0)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	code := "provider_unavailable"
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		code = "provider_auth"
	case http.StatusTooManyRequests:
		code = "provider_rate_limit"
	}
	return assistantError(code, resp.StatusCode)
}

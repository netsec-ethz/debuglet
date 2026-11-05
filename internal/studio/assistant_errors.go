// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import "context"

// AssistantError carries only allowlisted diagnostics. Provider bodies, prompts,
// graph contents and credentials must never become public error messages.
type AssistantError struct {
	Code           string
	Message        string
	ProviderStatus int
	cause          error
}

func (e *AssistantError) Error() string { return e.Message }
func (e *AssistantError) Unwrap() error { return e.cause }

func assistantError(code string, status int) *AssistantError {
	e := &AssistantError{Code: code, ProviderStatus: status, cause: ErrAssistantInvalidReply}
	switch code {
	case "provider_auth":
		e.Message = "The assistant provider rejected its credentials. Ask the dispatcher operator to check the assistant configuration; your draft is unchanged."
		e.cause = ErrAssistantUnavailable
	case "provider_rate_limit":
		e.Message = "The assistant provider has reached its request or quota limit. Retry later; your draft is unchanged."
		e.cause = ErrAssistantUnavailable
	case "provider_unavailable":
		e.Message = "The assistant provider is unavailable. Retry shortly; your draft is unchanged."
		e.cause = ErrAssistantUnavailable
	case "output_truncated":
		e.Message = "The assistant's proposed edit was too long to finish. Ask for a smaller change or one measurement at a time; your draft is unchanged."
	case "invalid_graph":
		e.Message = "The assistant could not produce a valid graph after one correction. Try a smaller change or edit the blocks directly; your draft is unchanged."
	case "deadline_exceeded":
		e.Message = "The assistant reached its time limit. Try a smaller change; your draft is unchanged."
		e.cause = ErrAssistantTimeout
	case "canceled":
		e.Message = "The assistant request was canceled before an edit was ready; your draft is unchanged."
		e.cause = ErrAssistantTimeout
	default:
		e.Code = "invalid_response"
		e.Message = "The assistant returned an unreadable proposal. Retry the request; your draft is unchanged."
	}
	return e
}

func assistantContextError(ctx context.Context) *AssistantError {
	if ctx.Err() == context.Canceled {
		return assistantError("canceled", 0)
	}
	return assistantError("deadline_exceeded", 0)
}

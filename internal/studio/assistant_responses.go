// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"context"
	"encoding/json"
)

// completeResponses adapts the provider protocol only. The existing proposal
// validator, compiler check and single correction still decide what is accepted.
func (a *Assistant) completeResponses(ctx context.Context, messages []assistantModelMessage, function map[string]any, observe func(AssistantProgress) error) (assistantModelMessage, error) {
	var empty assistantModelMessage
	input := make([]any, 0, len(messages))
	for _, message := range messages {
		switch {
		case len(message.ResponseItems) > 0:
			// Keep reasoning and function-call items together and in their original
			// order. In stateless mode their encrypted content enables the repair.
			for _, item := range message.ResponseItems {
				input = append(input, item)
			}
		case message.Role == "tool":
			input = append(input, map[string]any{"type": "function_call_output", "call_id": message.ToolCallID, "output": message.Content})
		default:
			input = append(input, map[string]any{"role": message.Role, "content": message.Content})
		}
	}
	tool := map[string]any{"type": "function"}
	for key, value := range function {
		tool[key] = value
	}
	payload := map[string]any{
		"model": a.model, "input": input, "tools": []any{tool},
		"tool_choice":         map[string]any{"type": "function", "name": "propose_document"},
		"parallel_tool_calls": false, "max_output_tokens": 16384,
		"store": false, "stream": true, "include": []string{"reasoning.encrypted_content"},
	}
	reasoning := map[string]any{"summary": "auto"}
	if a.reasoningEffort != "" {
		reasoning["effort"] = a.reasoningEffort
	}
	payload["reasoning"] = reasoning
	response, err := a.requestAssistant(ctx, payload)
	if err != nil {
		return empty, err
	}
	defer response.Body.Close()
	data, err := assistantReadResponseStream(ctx, response.Body, observe)
	if err != nil {
		return empty, err
	}
	return assistantDecodeResponse(data)
}

func assistantDecodeResponse(data []byte) (assistantModelMessage, error) {
	var empty assistantModelMessage
	var response struct {
		Status            string `json:"status"`
		IncompleteDetails struct {
			Reason string `json:"reason"`
		} `json:"incomplete_details"`
		Output []json.RawMessage `json:"output"`
	}
	if json.Unmarshal(data, &response) != nil {
		return empty, assistantError("invalid_response", 0)
	}
	if response.Status == "incomplete" && response.IncompleteDetails.Reason == "max_output_tokens" {
		return empty, assistantError("output_truncated", 0)
	}
	if response.Status == "failed" {
		return empty, assistantError("provider_unavailable", 0)
	}
	if response.Status != "completed" {
		return empty, assistantError("invalid_response", 0)
	}
	answer := assistantModelMessage{Role: "assistant", ResponseItems: response.Output}
	for _, raw := range response.Output {
		var item struct {
			Type      string          `json:"type"`
			Status    string          `json:"status"`
			CallID    string          `json:"call_id"`
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
			Content   []struct {
				Type string `json:"type"`
			} `json:"content"`
		}
		if json.Unmarshal(raw, &item) != nil {
			return empty, assistantError("invalid_response", 0)
		}
		switch item.Type {
		case "reasoning":
			// Opaque provider state is never converted into user-visible text.
		case "message":
			for _, content := range item.Content {
				if content.Type == "refusal" {
					return empty, assistantError("invalid_response", 0)
				}
			}
		case "function_call":
			if item.Status != "" && item.Status != "completed" {
				return empty, assistantError("invalid_response", 0)
			}
			call := assistantCall{ID: item.CallID, Type: "function"}
			call.Function.Name, call.Function.Arguments = item.Name, item.Arguments
			answer.ToolCalls = append(answer.ToolCalls, call)
		default:
			return empty, assistantError("invalid_response", 0)
		}
	}
	return answer, nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"
)

const (
	assistantStreamLimit = 8 << 20
	assistantEventLimit  = assistantResponseLimit + 4096
	assistantEventCount  = 32768
)

// assistantReadResponseStream forwards only real provider milestones. The final
// response remains the sole source for proposal validation and repair history.
func assistantReadResponseStream(ctx context.Context, body io.Reader, observe func(AssistantProgress) error) ([]byte, error) {
	reader := &io.LimitedReader{R: body, N: assistantStreamLimit + 1}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), assistantEventLimit+1)
	var data strings.Builder
	accepted, summaryBytes, outputBytes, events := false, 0, 0, 0
	notify := func(progress AssistantProgress) error {
		if ctx.Err() != nil {
			return assistantContextError(ctx)
		}
		if observe != nil {
			return observe(progress)
		}
		return nil
	}
	for scanner.Scan() {
		if ctx.Err() != nil {
			return nil, assistantContextError(ctx)
		}
		if reader.N <= 0 {
			return nil, assistantError("invalid_response", 0)
		}
		line := scanner.Text()
		if line != "" {
			if value, ok := strings.CutPrefix(line, "data:"); ok {
				value = strings.TrimPrefix(value, " ")
				if data.Len()+len(value)+1 > assistantEventLimit {
					return nil, assistantError("invalid_response", 0)
				}
				data.WriteString(value)
				data.WriteByte('\n')
			}
			continue
		}
		if data.Len() == 0 {
			continue
		}
		events++
		if events > assistantEventCount {
			return nil, assistantError("invalid_response", 0)
		}
		var event struct {
			Type     string          `json:"type"`
			Delta    string          `json:"delta"`
			Response json.RawMessage `json:"response"`
		}
		if json.Unmarshal([]byte(data.String()), &event) != nil || event.Type == "" {
			return nil, assistantError("invalid_response", 0)
		}
		data.Reset()
		var progress AssistantProgress
		switch event.Type {
		case "response.created", "response.in_progress":
			if !accepted {
				accepted = true
				progress.Phase = "accepted"
			}
		case "response.reasoning_summary_text.delta":
			remaining := assistantTextLimit - summaryBytes
			if remaining > 0 && event.Delta != "" {
				text := event.Delta
				if len(text) > remaining {
					text = text[:remaining]
					for !utf8.ValidString(text) {
						text = text[:len(text)-1]
					}
				}
				summaryBytes += len(text)
				if text != "" {
					progress = AssistantProgress{Phase: "reasoning", SummaryDelta: text}
				}
			}
		case "response.function_call_arguments.delta":
			outputBytes += len(event.Delta)
			if outputBytes > assistantResponseLimit {
				return nil, assistantError("invalid_response", 0)
			}
			if event.Delta != "" {
				progress = AssistantProgress{Phase: "output", OutputBytes: outputBytes}
			}
		case "response.completed", "response.incomplete", "response.failed":
			if len(event.Response) == 0 || len(event.Response) > assistantResponseLimit {
				return nil, assistantError("invalid_response", 0)
			}
			var terminal struct {
				Status string `json:"status"`
			}
			if json.Unmarshal(event.Response, &terminal) != nil || event.Type != "response."+terminal.Status {
				return nil, assistantError("invalid_response", 0)
			}
			return event.Response, nil
		case "error":
			return nil, assistantError("provider_unavailable", 0)
		}
		if progress.Phase != "" {
			if err := notify(progress); err != nil {
				return nil, err
			}
		}
	}
	if ctx.Err() != nil {
		return nil, assistantContextError(ctx)
	}
	// EOF, malformed framing and provider disconnection never apply a partial edit.
	return nil, assistantError("invalid_response", 0)
}

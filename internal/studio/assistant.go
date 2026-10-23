// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/netsec-ethz/debuglet/pkg/workflow"
)

const (
	AssistantRequestLimit  = (4 << 20) + (64 << 10)
	AssistantTimeout       = 90 * time.Second
	assistantDocumentLimit = 256 << 10
	assistantResponseLimit = 512 << 10
	assistantTextLimit     = 8192
)

var (
	ErrAssistantUnavailable  = errors.New("experiment assistant provider is unavailable; retry later")
	ErrAssistantTimeout      = errors.New("experiment assistant timed out or was canceled")
	ErrAssistantInvalidReply = errors.New("experiment assistant could not produce a valid edit; your experiment has not changed")
)

type AssistantConfig struct {
	Endpoint          string
	Model             string
	APIKey            string
	AllowInsecureHTTP bool
	ReasoningEffort   string
}

type AssistantMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type AssistantRequest struct {
	Kind     string             `json:"kind"`
	Document json.RawMessage    `json:"document"`
	Message  string             `json:"message"`
	History  []AssistantMessage `json:"history,omitempty"`
}

type AssistantResponse struct {
	Message  string          `json:"message"`
	Document json.RawMessage `json:"document,omitempty"`
}

// Assistant only proposes editable source. It has no compiler, database,
// submission capability or access to another account's saved documents.
type Assistant struct {
	endpoint        string
	model           string
	key             string
	reasoningEffort string
	client          *http.Client
}

func NewAssistant(cfg AssistantConfig) (*Assistant, error) {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Scheme != "https" && !(u.Scheme == "http" && (cfg.AllowInsecureHTTP || net.ParseIP(u.Hostname()).IsLoopback()))) {
		return nil, errors.New("assistant endpoint requires HTTPS, literal loopback HTTP or allow_insecure_http; URL credentials, query and fragment are forbidden")
	}
	if cfg.Model == "" || len(cfg.Model) > 128 || strings.TrimSpace(cfg.Model) != cfg.Model || strings.ContainsFunc(cfg.Model, unicode.IsControl) {
		return nil, errors.New("assistant model must contain 1–128 characters without surrounding whitespace or control characters")
	}
	switch cfg.ReasoningEffort {
	case "", "low", "high", "max":
	default:
		return nil, errors.New("assistant reasoning_effort must be empty, low, high or max")
	}
	key := strings.TrimSpace(cfg.APIKey)
	if key == "" || len(key) > 8192 || strings.ContainsFunc(key, unicode.IsSpace) || strings.ContainsFunc(key, unicode.IsControl) {
		return nil, errors.New("assistant API key is missing or malformed")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxResponseHeaderBytes = 16 << 10
	transport.ResponseHeaderTimeout = AssistantTimeout
	return &Assistant{endpoint: u.String(), model: cfg.Model, key: key, reasoningEffort: cfg.ReasoningEffort, client: &http.Client{
		Transport: transport, Timeout: AssistantTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func (a *Assistant) Model() string { return a.model }

// DecodeAssistantRequest permits an incomplete graph so the assistant can repair
// it. Proposed edits are validated separately before they leave the server.
func DecodeAssistantRequest(r io.Reader) (AssistantRequest, error) {
	var request AssistantRequest
	data, err := io.ReadAll(io.LimitReader(r, AssistantRequestLimit+1))
	if err != nil {
		return request, fmt.Errorf("read assistant request: %w", err)
	}
	if len(data) > AssistantRequestLimit {
		return request, &http.MaxBytesError{Limit: AssistantRequestLimit}
	}
	if err := assistantDecode(data, &request); err != nil {
		return request, errors.New("assistant request must contain one JSON object with kind, document and message")
	}
	if strings.TrimSpace(request.Message) == "" || len(request.Message) > assistantTextLimit {
		return request, errors.New("assistant message must contain 1–8192 bytes")
	}
	if len(request.History) > 12 {
		return request, errors.New("assistant history may contain at most 12 messages")
	}
	total := 0
	for _, message := range request.History {
		total += len(message.Content)
		if (message.Role != "user" && message.Role != "assistant") || len(message.Content) > assistantTextLimit || total > 16384 {
			return request, errors.New("assistant history must contain user/assistant text, at most 8192 bytes per message and 16384 bytes in total")
		}
	}
	if len(request.Document) > assistantDocumentLimit {
		return request, errors.New("this experiment is too large for the assistant (256 KiB); continue editing it visually")
	}
	var document any
	switch request.Kind {
	case "workflow":
		document, err = DecodeWorkflow(bytes.NewReader(request.Document))
	case "experiment":
		document, err = DecodeExperiment(bytes.NewReader(request.Document))
	default:
		return request, errors.New("assistant kind must be workflow or experiment")
	}
	if err != nil || len(bytes.TrimSpace(request.Document)) == 0 || bytes.Equal(bytes.TrimSpace(request.Document), []byte("null")) {
		return request, errors.New("assistant document must use the existing editable graph format")
	}
	request.Document, err = json.Marshal(document)
	return request, err
}

type assistantCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"function"`
}

type assistantModelMessage struct {
	Role             string          `json:"role"`
	Content          string          `json:"content,omitempty"`
	ReasoningContent string          `json:"reasoning_content,omitempty"`
	ToolCalls        []assistantCall `json:"tool_calls,omitempty"`
	ToolCallID       string          `json:"tool_call_id,omitempty"`
}

// Reply makes at most two provider requests: one proposal and one correction
// using the existing graph validator's diagnostics. It never executes tool calls.
func (a *Assistant) Reply(ctx context.Context, request AssistantRequest) (AssistantResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, AssistantTimeout)
	defer cancel()
	catalog, _ := json.Marshal(workflow.Catalog())
	messages := []assistantModelMessage{{Role: "system", Content: assistantInstructions + "\nAvailable blocks: " + string(catalog)}}
	for _, item := range request.History {
		messages = append(messages, assistantModelMessage{Role: item.Role, Content: item.Content})
	}
	input, _ := json.Marshal(map[string]any{"kind": request.Kind, "document": request.Document, "request": request.Message})
	messages = append(messages, assistantModelMessage{Role: "user", Content: string(input)})
	for attempt := 0; attempt < 2; attempt++ {
		answer, err := a.complete(ctx, messages)
		if err != nil {
			return AssistantResponse{}, err
		}
		if len(answer.ToolCalls) == 0 {
			if strings.TrimSpace(answer.Content) == "" || len(answer.Content) > assistantTextLimit {
				return AssistantResponse{}, ErrAssistantInvalidReply
			}
			return AssistantResponse{Message: answer.Content}, nil
		}
		if len(answer.ToolCalls) != 1 || answer.ToolCalls[0].Function.Name != "propose_document" || answer.ToolCalls[0].Type != "function" ||
			answer.ToolCalls[0].ID == "" || len(answer.ToolCalls[0].ID) > 128 {
			return AssistantResponse{}, ErrAssistantInvalidReply
		}
		call := &answer.ToolCalls[0]
		arguments := call.Function.Arguments
		if len(arguments) > 0 && arguments[0] == '"' {
			var text string
			if json.Unmarshal(arguments, &text) != nil {
				return AssistantResponse{}, ErrAssistantInvalidReply
			}
			arguments = []byte(text)
		}
		var proposed AssistantResponse
		err = assistantDecode(arguments, &proposed)
		if err == nil && (strings.TrimSpace(proposed.Message) == "" || len(proposed.Message) > assistantTextLimit) {
			err = errors.New("proposal needs a short explanation")
		}
		if err == nil && len(proposed.Document) > 0 {
			proposed.Document, err = assistantValidateDocument(request.Kind, proposed.Document)
		}
		if err == nil {
			return proposed, nil
		}
		// Normalize arguments for providers that return a JSON object instead
		// of the usual JSON-encoded string. Only validation feedback is added.
		call.Function.Arguments, _ = json.Marshal(string(arguments))
		answer.Role = "assistant"
		answer.Content = ""
		messages = append(messages, answer, assistantModelMessage{Role: "tool", ToolCallID: call.ID,
			Content: "The edit was not applied. Return a corrected complete document: " + assistantFeedback(err)})
	}
	return AssistantResponse{}, ErrAssistantInvalidReply
}

func (a *Assistant) complete(ctx context.Context, messages []assistantModelMessage) (assistantModelMessage, error) {
	var empty assistantModelMessage
	tool := map[string]any{"type": "function", "function": map[string]any{
		"name": "propose_document", "description": "Propose one complete editable document of the same kind, or a clarification without a document.",
		"parameters": map[string]any{"type": "object", "properties": map[string]any{
			"message": map[string]any{"type": "string"}, "document": map[string]any{"type": "object"},
		}, "required": []string{"message"}, "additionalProperties": false},
	}}
	payload := map[string]any{"model": a.model, "messages": messages, "tools": []any{tool}, "tool_choice": "auto", "stream": false, "max_tokens": 16384}
	if a.reasoningEffort != "" {
		payload["reasoning_effort"] = a.reasoningEffort
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return empty, ErrAssistantInvalidReply
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(data))
	if err != nil {
		return empty, ErrAssistantUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.key)
	response, err := a.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return empty, ErrAssistantTimeout
		}
		return empty, ErrAssistantUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return empty, ErrAssistantUnavailable
	}
	data, err = io.ReadAll(io.LimitReader(response.Body, assistantResponseLimit+1))
	if ctx.Err() != nil {
		return empty, ErrAssistantTimeout
	}
	if err != nil || len(data) > assistantResponseLimit {
		return empty, ErrAssistantInvalidReply
	}
	var result struct {
		Choices []struct {
			Message      assistantModelMessage `json:"message"`
			FinishReason string                `json:"finish_reason"`
		} `json:"choices"`
	}
	if json.Unmarshal(data, &result) != nil || len(result.Choices) != 1 ||
		(result.Choices[0].FinishReason != "stop" && result.Choices[0].FinishReason != "tool_calls") {
		return empty, ErrAssistantInvalidReply
	}
	return result.Choices[0].Message, nil
}

func assistantValidateDocument(kind string, data json.RawMessage) (json.RawMessage, error) {
	if len(data) > assistantDocumentLimit || bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil, errors.New("document must be an object of at most 256 KiB")
	}
	switch kind {
	case "workflow":
		document, err := DecodeWorkflow(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		if _, err := workflow.Generate(document); err != nil {
			return nil, err
		}
		return json.Marshal(document)
	case "experiment":
		document, err := DecodeExperiment(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		if ds := workflow.ValidateExperiment(document); len(ds) != 0 {
			return nil, fmt.Errorf("participant %s node %s: %s", ds[0].Participant, ds[0].Node, ds[0].Message)
		}
		return json.Marshal(document)
	}
	return nil, errors.New("unsupported document kind")
}

func assistantDecode(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("expected one JSON object")
	}
	return nil
}

func assistantFeedback(err error) string {
	text := err.Error()
	if len(text) > 2048 {
		text = text[:2048]
	}
	return text
}

const assistantInstructions = `You help a researcher author Debuglet experiments. Propose source for the visible editor, never claim to have run, saved or deployed it. Use the current document and request supplied in the last message. Preserve existing unrelated blocks, positions, identifiers and settings. Ask a concise clarification when essential targets or requirements are missing; do not invent results or public targets. Use the propose_document function to return a complete document and a short explanation. Prefer built-in blocks; custom Go actions remain visible and must follow the existing graph format. Never return code fences, patches, compiled bundles or credentials as the document.
The kind must remain unchanged. Workflow JSON is {version:1,name,entry,nodes:[{id,block,inputs,position:{x,y}}],edges:[{kind:"control"|"data",from:{node,port},to:{node,port}}],custom_blocks?:[],groups?:[]}. Nodes use catalog block IDs and exact port names. Each action's control input is "in"; its control outputs are listed in the catalog. Data edges carry typed values, and do not execute actions. Pure blocks evaluate on demand. The entry must be an action. Connect required data or supply literal inputs. Control flow is bounded: use repeat/for_each rather than cycles. Outcomes such as HTTP transport success, HTTP status, and run completion are distinct. Include clear report metrics/tables/charts where useful.
Node inputs contain literal JSON values only. To use another node's output, omit that destination port from inputs and add a top-level data edge. Do not put {"node":...,"port":...}, reference strings or expressions in inputs as references: objects there are literal objects, including for ports of type any. For HTTP node http1 feeding report_metric node metric1, use metric1.inputs={"title":"Duration","unit":"ms"} and the data edge {"kind":"data","from":{"node":"http1","port":"duration_ms"},"to":{"node":"metric1","port":"value"}}. Execute those actions with the separate control edge {"kind":"control","from":{"node":"http1","port":"next"},"to":{"node":"metric1","port":"in"}}. The same data-edge rule applies to emit and every other block. When repairing a connection, preserve the requested data dependency instead of substituting a placeholder literal.
Experiment JSON is {version:1,kind:"experiment",name,participants:[{id,label,workflow}],channels:[{id,from,to,type,response_type?}]}. It has 2–3 participants, each with ordinary Workflow JSON and no injected experiment context. Declared channels connect distinct participant IDs. send_message/await_message/phase_barrier require this whole-experiment context. Every participant must contain each named phase barrier. Direct TCP reachability and listener permissions are deployment choices; executor selection and runtime permissions are not part of the editable source. A workflow can independently run on many executors without adding messaging blocks. Treat the catalog as the authority for available blocks and types.`

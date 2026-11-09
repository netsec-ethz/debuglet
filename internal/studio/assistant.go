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
	assistantFeedbackLimit = 4096
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
	Kind      string             `json:"kind"`
	Document  json.RawMessage    `json:"document"`
	Message   string             `json:"message"`
	History   []AssistantMessage `json:"history,omitempty"`
	AllowCode bool               `json:"allow_code,omitempty"`
}

type AssistantResponse struct {
	Message  string          `json:"message"`
	Document json.RawMessage `json:"document,omitempty"`
	Action   string          `json:"action,omitempty"`
}

// Assistant only proposes editable source. It has no compiler, database,
// submission capability or access to another account's saved documents.
type Assistant struct {
	endpoint        string
	model           string
	key             string
	reasoningEffort string
	tokenLimitField string
	strictSchema    bool
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
	case "", "none", "low", "high", "max":
	default:
		return nil, errors.New("assistant reasoning_effort must be empty, none, low, high or max")
	}
	key := strings.TrimSpace(cfg.APIKey)
	if key == "" || len(key) > 8192 || strings.ContainsFunc(key, unicode.IsSpace) || strings.ContainsFunc(key, unicode.IsControl) {
		return nil, errors.New("assistant API key is missing or malformed")
	}
	tokenLimitField := "max_tokens"
	if strings.EqualFold(u.Hostname(), "api.openai.com") {
		tokenLimitField = "max_completion_tokens"
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxResponseHeaderBytes = 16 << 10
	transport.ResponseHeaderTimeout = AssistantTimeout
	return &Assistant{endpoint: u.String(), model: cfg.Model, key: key, reasoningEffort: cfg.ReasoningEffort, tokenLimitField: tokenLimitField, strictSchema: strings.EqualFold(u.Hostname(), "api.openai.com"), client: &http.Client{
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
	switch doc := document.(type) {
	case workflow.Workflow:
		if doc.GoCode != nil && !request.AllowCode {
			return request, errors.New("choose Go authoring or restore blocks before asking the assistant to edit this program; manual Go code is preserved")
		}
	case workflow.Experiment:
		for _, participant := range doc.Participants {
			if participant.Workflow.GoCode != nil && !request.AllowCode {
				return request, errors.New("choose Go authoring or restore blocks for programs with manual Go code before asking the assistant to edit this experiment")
			}
		}
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
	return a.ReplyChecked(ctx, request, nil)
}

// AssistantCompileCheck checks a structurally valid proposal with the existing
// compiler. A diagnostic permits one model correction; an infrastructure error
// stops the request. It must not execute or submit the generated program.
type AssistantCompileCheck func(context.Context, string, json.RawMessage) (diagnostic string, err error)

// ReplyChecked adds compilation feedback to the bounded proposal/repair cycle.
// A nil check keeps source-only visual authoring; Go mode requires compilation.
func (a *Assistant) ReplyChecked(ctx context.Context, request AssistantRequest, check AssistantCompileCheck) (AssistantResponse, error) {
	return a.ReplyObserved(ctx, request, check, nil)
}

// ReplyObserved reports actual processing boundaries. An observer error stops
// the request, so a disconnected client does not keep generating a proposal.
func (a *Assistant) ReplyObserved(ctx context.Context, request AssistantRequest, check AssistantCompileCheck, observe func(string) error) (AssistantResponse, error) {
	notify := func(stage string) error {
		if observe != nil {
			return observe(stage)
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, AssistantTimeout)
	defer cancel()
	if !request.AllowCode && assistantHasGoCode(request.Kind, request.Document) {
		return AssistantResponse{}, assistantError("invalid_graph", 0)
	}
	catalog, _ := json.Marshal(workflow.Catalog())
	instructions := assistantInstructions
	var codeContext any
	if request.AllowCode {
		var err error
		request.Document, codeContext, err = assistantPrepareCode(request.Kind, request.Document)
		if err != nil {
			return AssistantResponse{}, assistantError("invalid_graph", 0)
		}
		instructions = assistantCodeInstructions
	} else {
		if a.strictSchema {
			instructions += assistantStrictInstructions
		} else {
			instructions += assistantLegacyInstructions
		}
		instructions += "\nAvailable blocks: " + string(catalog)
	}
	messages := []assistantModelMessage{{Role: "system", Content: instructions}}
	for _, item := range request.History {
		messages = append(messages, assistantModelMessage{Role: item.Role, Content: item.Content})
	}
	input, _ := json.Marshal(map[string]any{"kind": request.Kind, "document": request.Document, "request": request.Message, "allow_code": request.AllowCode, "code_context": codeContext})
	messages = append(messages, assistantModelMessage{Role: "user", Content: string(input)})
	editBase := request.Document
	for attempt := 0; attempt < 2; attempt++ {
		stage := "generating"
		if attempt > 0 {
			stage = "repairing"
		}
		if err := notify(stage); err != nil {
			return AssistantResponse{}, err
		}
		answer, err := a.complete(ctx, messages, request.Kind, request.AllowCode)
		if err != nil {
			return AssistantResponse{}, err
		}
		if len(answer.ToolCalls) == 0 {
			if strings.TrimSpace(answer.Content) == "" || len(answer.Content) > assistantTextLimit {
				return AssistantResponse{}, assistantError("invalid_response", 0)
			}
			return AssistantResponse{Message: answer.Content}, nil
		}
		if len(answer.ToolCalls) != 1 || answer.ToolCalls[0].Function.Name != "propose_document" || answer.ToolCalls[0].Type != "function" ||
			answer.ToolCalls[0].ID == "" || len(answer.ToolCalls[0].ID) > 128 {
			return AssistantResponse{}, assistantError("invalid_response", 0)
		}
		call := &answer.ToolCalls[0]
		arguments := call.Function.Arguments
		if len(arguments) > 0 && arguments[0] == '"' {
			var text string
			if json.Unmarshal(arguments, &text) != nil {
				return AssistantResponse{}, assistantError("invalid_response", 0)
			}
			arguments = []byte(text)
		}
		if err := notify("validating"); err != nil {
			return AssistantResponse{}, err
		}
		var proposed struct {
			AssistantResponse
			Edits *assistantEdits     `json:"edits,omitempty"`
			Code  []assistantCodeEdit `json:"code,omitempty"`
		}
		failureCode := "invalid_response"
		err = assistantDecode(arguments, &proposed)
		if a.strictSchema && bytes.Equal(bytes.TrimSpace(proposed.Document), []byte("null")) {
			proposed.Document = nil
		}
		if err == nil && (strings.TrimSpace(proposed.Message) == "" || len(proposed.Message) > assistantTextLimit) {
			err = errors.New("proposal needs a short explanation")
		}
		if err == nil && proposed.Edits != nil && (!a.strictSchema || len(proposed.Document) != 0) {
			err = errors.New("return either edits or a document, not both; edits require the strict provider schema")
		}
		if err == nil && proposed.Action != "" &&
			((proposed.Action != "coordinate" && proposed.Action != "code") ||
				(proposed.Action == "coordinate" && request.Kind != "workflow") ||
				len(proposed.Document) != 0 || proposed.Edits != nil || len(proposed.Code) != 0 || request.AllowCode) {
			err = errors.New("offer coordinate for a workflow or code without any document or edits; wait for the user's explicit choice")
		}
		if err == nil && request.AllowCode && (len(proposed.Document) != 0 || proposed.Edits != nil) {
			err = errors.New("Go mode replaces functions through code only; the saved visual graph must remain unchanged")
		}
		if err == nil && len(proposed.Code) != 0 {
			if !request.AllowCode || proposed.Edits != nil || len(proposed.Document) != 0 || proposed.Action != "" {
				err = errors.New("Go code needs explicit allow_code consent and cannot be combined with visual edits")
			} else {
				failureCode = "invalid_graph"
				proposed.Document, err = assistantApplyCode(request.Kind, editBase, proposed.Code)
			}
		}
		baseDescription := "Edits still target the current document in the user request."
		completeRepair := false
		if err == nil && proposed.Edits != nil {
			failureCode = "invalid_graph"
			proposed.Document, err = assistantApplyEdits(request.Kind, editBase, *proposed.Edits)
		}
		if err == nil && len(proposed.Document) > 0 {
			failureCode = "invalid_graph"
			completeRepair = a.strictSchema && proposed.Edits == nil && !request.AllowCode
			if a.strictSchema && proposed.Edits == nil && !request.AllowCode {
				proposed.Document, err = assistantDecodeWireDocument(request.Kind, proposed.Document)
			}
			if err == nil && !request.AllowCode && assistantHasGoCode(request.Kind, proposed.Document) {
				err = errors.New("Go code requires an explicit code offer and allow_code consent")
			}
			if err == nil {
				// Retain the proposed source even when semantic validation fails, so
				// a correction only needs to replace the failing nodes/connections.
				editBase = proposed.Document
				baseDescription = "Edits now target the rejected proposal above, including its earlier edits, not the original user document."
				proposed.Document, err = assistantValidateDocument(request.Kind, proposed.Document)
				if err == nil && !request.AllowCode {
					err = assistantValidateReachability(request.Kind, request.Document, proposed.Document)
				}
				if err == nil && !request.AllowCode {
					err = assistantValidatePresentation(request.Kind, proposed.Document)
				}
				if err == nil {
					completeRepair = false // A compiler-only correction can stay incremental.
				}
				if err == nil && request.AllowCode && check == nil {
					return AssistantResponse{}, assistantError("provider_unavailable", 0)
				}
				if err == nil && check != nil && (assistantHasCustomCode(request.Kind, proposed.Document) || assistantHasGoCode(request.Kind, proposed.Document)) {
					if observeErr := notify("compiling"); observeErr != nil {
						return AssistantResponse{}, observeErr
					}
					diagnostic, checkErr := check(ctx, request.Kind, proposed.Document)
					if ctx.Err() != nil {
						return AssistantResponse{}, assistantContextError(ctx)
					}
					if checkErr != nil {
						return AssistantResponse{}, checkErr
					}
					if diagnostic != "" {
						err = errors.New("Custom code did not compile: " + assistantBoundText(diagnostic, assistantFeedbackLimit))
					}
				}
			}
		}
		if err == nil {
			return proposed.AssistantResponse, nil
		}
		if attempt == 1 {
			return AssistantResponse{}, assistantError(failureCode, 0)
		}
		// Normalize arguments for providers that return a JSON object instead
		// of the usual JSON-encoded string. Only validation feedback is added.
		call.Function.Arguments, _ = json.Marshal(string(arguments))
		answer.Role = "assistant"
		answer.Content = ""
		instruction := "Return a corrected complete document."
		if request.AllowCode {
			instruction = "Return corrected complete function replacements only for failing programs in code; replacements for other programs are retained from the rejected proposal and saved blocks are unchanged."
		} else if a.strictSchema {
			instruction = baseDescription + " Return edits for the failing parts, or a corrected complete document."
			if completeRepair {
				instruction = "Return a corrected complete compact document with edits null. Preserve all requested measurements and report actions; repair their bindings and control paths instead of deleting them."
			}
		}
		messages = append(messages, answer, assistantModelMessage{Role: "tool", ToolCallID: call.ID,
			Content: "The edit was not applied. " + instruction + " Diagnostics: " + assistantFeedback(err)})
	}
	return AssistantResponse{}, assistantError("invalid_response", 0)
}

func assistantHasCustomCode(kind string, document json.RawMessage) bool {
	var source struct {
		CustomBlocks []json.RawMessage `json:"custom_blocks"`
		Participants []struct {
			Workflow struct {
				CustomBlocks []json.RawMessage `json:"custom_blocks"`
			} `json:"workflow"`
		} `json:"participants"`
	}
	_ = json.Unmarshal(document, &source) // The full document was validated above.
	if kind == "workflow" {
		return len(source.CustomBlocks) > 0
	}
	for _, participant := range source.Participants {
		if len(participant.Workflow.CustomBlocks) > 0 {
			return true
		}
	}
	return false
}

func (a *Assistant) complete(ctx context.Context, messages []assistantModelMessage, kind string, allowCode bool) (assistantModelMessage, error) {
	var empty assistantModelMessage
	tool := map[string]any{"type": "function", "function": map[string]any{
		"name": "propose_document", "description": "Propose one complete editable document of the same kind, ask for clarification, or offer to convert a workflow to a coordinated experiment.",
		"parameters": map[string]any{"type": "object", "properties": map[string]any{
			"message": map[string]any{"type": "string"}, "document": map[string]any{"type": "object"},
			"action": map[string]any{"type": "string", "enum": []string{"coordinate", "code"}, "description": "Offer coordinated or Go authoring without a document; the user must accept first."},
		}, "required": []string{"message"}, "additionalProperties": false},
	}}
	if a.strictSchema {
		function := tool["function"].(map[string]any)
		function["description"] = "Propose compact edits or one complete editable document of the same kind, ask for clarification, or offer to convert a workflow to a coordinated experiment."
		function["strict"] = true
		function["parameters"] = assistantDocumentSchema(kind)
	}
	if allowCode {
		function := tool["function"].(map[string]any)
		function["parameters"] = assistantCodeSchema()
		function["description"] = "Propose complete function replacements for the explicitly selected Go program, preserving its saved visual source."
	}
	payload := map[string]any{"model": a.model, "messages": messages, "tools": []any{tool}, "tool_choice": "auto", "stream": false, a.tokenLimitField: 16384}
	if a.strictSchema {
		payload["parallel_tool_calls"] = false
		payload["tool_choice"] = map[string]any{"type": "function", "function": map[string]any{"name": "propose_document"}}
	}
	if a.reasoningEffort != "" {
		payload["reasoning_effort"] = a.reasoningEffort
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return empty, assistantError("invalid_response", 0)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(data))
	if err != nil {
		return empty, assistantError("provider_unavailable", 0)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.key)
	response, err := a.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return empty, assistantContextError(ctx)
		}
		return empty, assistantError("provider_unavailable", 0)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		code := "provider_unavailable"
		if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
			code = "provider_auth"
		}
		if response.StatusCode == http.StatusTooManyRequests {
			code = "provider_rate_limit"
		}
		return empty, assistantError(code, response.StatusCode)
	}
	data, err = io.ReadAll(io.LimitReader(response.Body, assistantResponseLimit+1))
	if ctx.Err() != nil {
		return empty, assistantContextError(ctx)
	}
	if err != nil || len(data) > assistantResponseLimit {
		return empty, assistantError("invalid_response", 0)
	}
	var result struct {
		Choices []struct {
			Message      assistantModelMessage `json:"message"`
			FinishReason string                `json:"finish_reason"`
		} `json:"choices"`
	}
	if json.Unmarshal(data, &result) != nil || len(result.Choices) != 1 {
		return empty, assistantError("invalid_response", 0)
	}
	if result.Choices[0].FinishReason == "length" {
		return empty, assistantError("output_truncated", 0)
	}
	if result.Choices[0].FinishReason != "stop" && result.Choices[0].FinishReason != "tool_calls" {
		return empty, assistantError("invalid_response", 0)
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
		ds := workflow.Validate(document)
		if len(ds) == 0 && document.GoCode == nil {
			ds = workflow.ValidateOutputAvailability(document)
		}
		if len(ds) != 0 {
			diagnostics := make([]workflow.ExperimentDiagnostic, len(ds))
			for i, d := range ds {
				diagnostics[i].Diagnostic = d
			}
			return nil, assistantValidationError(diagnostics)
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
			return nil, assistantValidationError(ds)
		}
		var availability []workflow.ExperimentDiagnostic
		for _, participant := range document.Participants {
			if participant.Workflow.GoCode != nil {
				continue
			}
			for _, diagnostic := range workflow.ValidateOutputAvailability(participant.Workflow) {
				availability = append(availability, workflow.ExperimentDiagnostic{Participant: participant.ID, Diagnostic: diagnostic})
			}
		}
		if len(availability) != 0 {
			return nil, assistantValidationError(availability)
		}
		for _, participant := range document.Participants {
			if _, _, err := workflow.GenerateParticipant(document, participant.ID); err != nil {
				return nil, err
			}
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
	return assistantBoundText(err.Error(), assistantFeedbackLimit)
}

func assistantValidationError(diagnostics []workflow.ExperimentDiagnostic) error {
	report := struct {
		Diagnostics []workflow.ExperimentDiagnostic `json:"diagnostics"`
		Omitted     int                             `json:"omitted,omitempty"`
	}{Diagnostics: []workflow.ExperimentDiagnostic{}, Omitted: len(diagnostics)}
	for _, d := range diagnostics[:min(len(diagnostics), 16)] {
		d.Participant = assistantBoundText(d.Participant, 128)
		d.Node = assistantBoundText(d.Node, 128)
		d.Port = assistantBoundText(d.Port, 128)
		d.Message = assistantBoundText(d.Message, 256)
		report.Diagnostics = append(report.Diagnostics, d)
		report.Omitted--
		encoded, _ := json.Marshal(report)
		if len(encoded) > assistantFeedbackLimit {
			report.Diagnostics = report.Diagnostics[:len(report.Diagnostics)-1]
			report.Omitted++
			break
		}
	}
	encoded, _ := json.Marshal(report)
	return errors.New(string(encoded))
}

func assistantBoundText(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	return strings.ToValidUTF8(text[:limit-3], "") + "..."
}

const assistantInstructions = `You author editable Debuglet measurements. Use propose_document and its response format; the supplied snapshot is current editor source. Never claim to have run, saved or deployed it. The catalog defines blocks, ports and types. Give a brief explanation; no code fences, bundles or credentials.

1. For every request to create or change an experiment, return the complete document or substantive edits in propose_document in this same response. A message with no document or edits is only for a necessary clarification or an explicit coordinate/code consent offer, never an acknowledgment such as "I will build it". Complete EVERY participant and requested measurement, exchange and comparison. Each required action/report must be reachable from its participant entry. Never return a scaffold, partial participant, placeholder result or promise to finish later. Ask one concise clarification only if an essential target/capability is missing. When the user answers a clarification, resume the original unfinished request from the conversation and return the complete graph proposal in this response. Do not return only an acknowledgment, a summary of agreed settings or a promise to build next; ask again only if another essential requirement truly remains missing. Repairs preserve the entire requested experiment; do not delete a failing stage to pass validation.

2. Keep it small. Preserve unrelated source, identifiers, settings and layout on edits. Use built-in network, control and messaging blocks. Add only requested operations, necessary correctness checks and output. No unrequested retries, sampling, statistics, charts or duplicate reports. Actions already record all outputs including errors/timings: no set_field/emit chains to repeat them. Reuse outputs and literal settings; choose one clear report for a derived comparison.

3. Separate execution from data. Entry must be an action; control connections execute actions through in and their catalog outputs. Data connections supply typed values but execute nothing. Pure blocks evaluate on demand and have no in/next ports. Custom blocks are ALWAYS actions, including data helpers. Wire or supply literals for required inputs. Literal objects do not evaluate nested expressions. Independent branches execute sequentially.

4. Preserve failures. Skipped actions have NO outputs, including ok/error: never read them on bypass paths. Guard address-dependent connections; consume their outputs only where they executed. A failed resolver/check must not discard another valid result. Failed timings/differences are null, never zero. Compare only complete successful responses. Transport completion, protocol success, completeness and run completion differ. Missing messages/DNS failures cannot produce successful comparisons.
Example for requested independent resolver comparisons: handle resolver A, then resolver B. If both selected local/peer addresses are valid: true -> local TCP -> peer TCP -> comparison helper -> table -> next resolver; false -> unavailable row -> next resolver. Both TCP checks execute even if the first connection fails. The comparison helper consumes ONLY this resolver's outputs, inside the true branch. The unavailable row uses DNS/message status, never skipped TCP outputs. Do not merge optional TCP outputs into one shared all-resolver comparison. Reuse the helper definition and group each resolver's check/comparison stage into one named expandable group.

5. Use simple defaults. Use catalog defaults for optional inputs. For resolving a supplied web hostname then connecting, default to one IPv4 A query and TCP 443. Cloudflare DNS is 1.1.1.1:53; Google DNS is 8.8.8.8:53. Select the first IPv4 address only after ok, rcode NOERROR, not truncated and nonempty addresses; do not add all-address loops unless requested. State meaningful defaults briefly. Executor selection, listener permissions and listener address/port allocation are launch choices. Initial experiment readiness and reservation/start times are managed by the runtime and launch setup, outside the editable graph; they are not drafting blockers. Do not ask about these settings while drafting. Add phase_barrier only for explicitly requested additional synchronization during the measurement, never to implement the managed initial readiness.

6. Use small custom processing actions when they replace many elementary field/formatting blocks. Give each a clear label, short description, typed inputs/outputs and visible code; define it in every workflow that uses it. Code is a Go FUNCTION BODY for func(inputs map[string]any) (map[string]any,error), not a declaration. Only fmt, json, os, guest, debuglet, time, strings and math packages are available; no imports. JSON arrays arrive as []any. Prefer helpers that only transform explicit inputs. If a genuinely missing operation needs custom network I/O, make it a clearly named, described custom action with typed inputs/outputs and bounded runtime; never disguise it as processing or hide an entire experiment inside one block. If tightly coupled sockets/state/concurrency would be clearer in Go functions, explain the missing capability and offer action:"code" with no document. Do not switch to code because the graph is large; grouping is for size. Wait for allow_code:true before returning any Go override.
Worked example: tcp_connect actions a and b -> custom comparison -> report_table. Both checks execute before comparison. Data connections provide a.ok/b.ok and a.duration_ms/b.duration_ms to helper inputs a_ok:boolean,b_ok:boolean,a_ms:number,b_ms:number; rows:any feeds the table. A helper body is:
aOK,_:=inputs["a_ok"].(bool); bOK,_:=inputs["b_ok"].(bool)
row:=map[string]any{"a_ms":nil,"b_ms":nil,"difference_ms":nil}
if aOK {row["a_ms"]=inputs["a_ms"]}; if bOK {row["b_ms"]=inputs["b_ms"]}
if aOK&&bOK {row["difference_ms"]=inputs["a_ms"].(float64)-inputs["b_ms"].(float64)}
return map[string]any{"rows":[]any{row}},nil
This is four actions with independent failed values retained. Adapt the pattern only when requested; do not add these targets or comparisons to other tasks.

7. Bound repetition. Use repeat/for_each for finite work and every with explicit interval/duration for periodic work; no cycles. Loops have in input and body/done outputs. End the body without a back edge; done leads to the next stage. Create collections before a loop, collect inside, read after done. Long runs publish bounded summaries/live samples, not unbounded raw output. Use catalog measurement services for background work: start before the loop, read bounded windows, stop afterward. Check validity flags before nullable timing/loss values. TCP goodput measures delivered useful bytes per transfer time, not available bandwidth.

8. Coordinate only when needed. One workflow can run independently at many vantage points: the user selects executors at launch. Different programs, exchanges or cross-participant aggregation require an experiment with 2–16 participants and declared channels between distinct IDs. Keep the current document kind. If a workflow needs coordination, offer action:"coordinate" with an explanation and no document; wait for acceptance rather than telling the user to switch editors. In an experiment, fully author every participant. send_message/await_message/phase_barrier need experiment context, and every participant must contain every named barrier. Use admitted peers for peer measurement services. Do not combine the managed TCP responder with experiment messaging/barriers, or managed UDP probes with raw UDP receive/reply.

9. Respect SCION scope. Use explicit SCION UDP blocks only. Discover paths to a complete ISD-AS,IP:port endpoint, select an opaque path ID, then exchange on it. Preserve failure if that path disappears; never silently substitute another. path_id identifies the outgoing path, not its return path. A coordinated receiver publishes scion_listener_address through the TCP control channel before discovery; never invent a listener/echo service. Use base64 for exact payload bytes and correlate replies. SCION blocks do not supply SCION TCP/HTTP or TESLA attribution.

10. Show at most TEN cards in EVERY view: root and inside each group. A card is an immediate child group or an ungrouped node at that level. Group related work into meaningful named stages and decompose recursively, without changing nodes or execution. Each group lists ALL contained leaf node IDs, 2–128 existing nodes in the same workflow. A nested group is a strict subset of its parent; siblings are disjoint. Equal memberships and partial overlaps are invalid. Groups are presentation, not executable nodes or ports. Keep simple graphs ungrouped; preserve source, identifiers and positions on edits, adding only grouping needed to satisfy the ten-card budget. Never suppress requested measurements to meet the limit.`

// Native editor serialization is used only by providers without the strict
// transport schema. Keep it out of compact-response instructions.
const assistantLegacyInstructions = `
Return the native editor document format. Workflow JSON is {version:1,name,entry,nodes:[{id,block,inputs,position:{x,y}}],edges:[{kind:"control"|"data",from:{node,port},to:{node,port}}],custom_blocks?:[],groups?:[]}. Experiment JSON is {version:1,kind:"experiment",name,participants:[{id,label,workflow}],channels:[{id,from,to,type,response_type?}]}. It has 2–16 participants, each with ordinary Workflow JSON and no injected experiment context. Node inputs contain literal JSON values only. To use another node's output, omit that destination port from inputs and add a top-level data edge. Do not put {"node":...,"port":...}, reference strings or expressions in inputs as references: objects there are literal objects, including for ports of type any. For HTTP node http1 feeding report_metric node metric1, use metric1.inputs={"title":"Duration","unit":"ms"} and the data edge {"kind":"data","from":{"node":"http1","port":"duration_ms"},"to":{"node":"metric1","port":"value"}}. Execute those actions with the separate control edge {"kind":"control","from":{"node":"http1","port":"next"},"to":{"node":"metric1","port":"in"}}. The same data-edge rule applies to emit and every other block. When repairing a connection, preserve the requested data dependency instead of substituting a placeholder literal.
Positions are optional; preserve existing positions. Use meaningful groups as {id,label,node_ids}; groups refer to existing nodes, never replace them. Return only the propose_document call and a short explanation.`

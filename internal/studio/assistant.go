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
	Kind     string             `json:"kind"`
	Document json.RawMessage    `json:"document"`
	Message  string             `json:"message"`
	History  []AssistantMessage `json:"history,omitempty"`
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
		if doc.GoCode != nil {
			return request, errors.New("restore blocks before asking the assistant to edit this program; manual Go code is preserved")
		}
	case workflow.Experiment:
		for _, participant := range doc.Participants {
			if participant.Workflow.GoCode != nil {
				return request, errors.New("restore blocks for programs with manual Go code before asking the assistant to edit this experiment")
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

// ReplyChecked adds compilation feedback for custom code to the same bounded
// proposal/repair cycle. A nil check keeps Reply's source-only authoring behavior.
func (a *Assistant) ReplyChecked(ctx context.Context, request AssistantRequest, check AssistantCompileCheck) (AssistantResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, AssistantTimeout)
	defer cancel()
	catalog, _ := json.Marshal(workflow.Catalog())
	instructions := assistantInstructions
	if a.strictSchema {
		instructions += assistantStrictInstructions
	} else {
		instructions += assistantLegacyInstructions
	}
	messages := []assistantModelMessage{{Role: "system", Content: instructions + "\nAvailable blocks: " + string(catalog)}}
	for _, item := range request.History {
		messages = append(messages, assistantModelMessage{Role: item.Role, Content: item.Content})
	}
	input, _ := json.Marshal(map[string]any{"kind": request.Kind, "document": request.Document, "request": request.Message})
	messages = append(messages, assistantModelMessage{Role: "user", Content: string(input)})
	editBase := request.Document
	for attempt := 0; attempt < 2; attempt++ {
		answer, err := a.complete(ctx, messages, request.Kind)
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
		var proposed struct {
			AssistantResponse
			Edits *assistantEdits `json:"edits,omitempty"`
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
		if err == nil && proposed.Action != "" && (proposed.Action != "coordinate" || request.Kind != "workflow" || len(proposed.Document) != 0 || proposed.Edits != nil) {
			err = errors.New("action must be coordinate, for a workflow, without a document; ask the user before converting")
		}
		baseDescription := "Edits still target the current document in the user request."
		if err == nil && proposed.Edits != nil {
			failureCode = "invalid_graph"
			proposed.Document, err = assistantApplyEdits(request.Kind, editBase, *proposed.Edits)
		}
		if err == nil && len(proposed.Document) > 0 {
			failureCode = "invalid_graph"
			if a.strictSchema && proposed.Edits == nil {
				proposed.Document, err = assistantDecodeWireDocument(request.Kind, proposed.Document)
			}
			if err == nil {
				// Retain the proposed source even when semantic validation fails, so
				// a correction only needs to replace the failing nodes/connections.
				editBase = proposed.Document
				baseDescription = "Edits now target the rejected proposal above, including its earlier edits, not the original user document."
				proposed.Document, err = assistantValidateDocument(request.Kind, proposed.Document)
				if err == nil && check != nil && assistantHasCustomCode(request.Kind, proposed.Document) {
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
		if a.strictSchema {
			instruction = baseDescription + " Return edits for the failing parts, or a corrected complete document."
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

func (a *Assistant) complete(ctx context.Context, messages []assistantModelMessage, kind string) (assistantModelMessage, error) {
	var empty assistantModelMessage
	tool := map[string]any{"type": "function", "function": map[string]any{
		"name": "propose_document", "description": "Propose one complete editable document of the same kind, ask for clarification, or offer to convert a workflow to a coordinated experiment.",
		"parameters": map[string]any{"type": "object", "properties": map[string]any{
			"message": map[string]any{"type": "string"}, "document": map[string]any{"type": "object"},
			"action": map[string]any{"type": "string", "enum": []string{"coordinate"}, "description": "Offer to convert a workflow to a coordinated experiment. Omit document; the user must accept first."},
		}, "required": []string{"message"}, "additionalProperties": false},
	}}
	if a.strictSchema {
		function := tool["function"].(map[string]any)
		function["description"] = "Propose compact edits or one complete editable document of the same kind, ask for clarification, or offer to convert a workflow to a coordinated experiment."
		function["strict"] = true
		function["parameters"] = assistantDocumentSchema(kind)
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
		if len(ds) == 0 {
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

const assistantInstructions = `You help a researcher author Debuglet experiments. Propose source for the visible editor, never claim to have run, saved or deployed it. Use the current document and request supplied in the last message. That snapshot is the existing editor document; encode your response using the function schema and the response-format instructions below. Preserve existing unrelated blocks, positions, identifiers and settings. Ask a concise clarification only when the target or a decision essential to the requested measurement is missing; do not invent results or public targets. Use the propose_document function to return a complete document, or compact edits when supported by its schema, and a short explanation. Prefer built-in network actions. For repeated data preparation or validation that would otherwise need many elementary blocks, use one clearly named, small custom action with a short description and explicit typed inputs and outputs; keep network I/O in built-in actions. Custom code is a Go function body with signature func(inputs map[string]any) (map[string]any,error), not a declaration. Available package names are fmt, json, os, guest, debuglet, time, strings and math only; do not add imports or use unavailable packages such as net. JSON arrays arrive as []any. For example, one visible DNS-address validation helper can check ok, rcode, truncation and a nonempty address list before selecting an address, returning valid=false and an empty address on failure. Custom actions need control connections and their code remains visible in custom_blocks. Never return code fences, patches, compiled bundles or credentials as the document.
Use catalog defaults for optional settings without asking. For a supplied web hostname, default to one IPv4 A query and TCP port 443 when the user asks to resolve and connect; state these choices briefly. Cloudflare DNS means 1.1.1.1:53 and Google DNS means 8.8.8.8:53. For a singular address comparison, select the first returned IPv4 address after checking ok, rcode NOERROR, not truncated, and a nonempty address list; do not add an all-address sampling loop unless requested. Preserve errors as results and do not compare failed measurements. Do not ask about executor selection or listener permissions while drafting source.
Complete the requested measurement first, preserve correct failure handling second, then simplify its presentation. Return a complete implementation, not a scaffold that still needs measurement actions or a later user prompt to finish. Before proposing, check that every requested network operation, message exchange and comparison is represented and reachable; table columns filled with placeholder nulls are not an implementation of a missing measurement. If an essential capability is unavailable, ask a concise question instead of returning a partial graph as the answer. Build the smallest understandable graph that fulfills the request. Every added block must contribute to a requested measurement, its correctness, or its necessary output. Do not add unrequested retries, sampling loops, statistics, charts, debug output or duplicate reports. Every executed action already records all of its outputs in the run results, including network ok/error/timing fields; do not copy these outputs into set_field chains or extra emit blocks merely to preserve them. Add a report only for the requested presentation or derived comparison. Use literal inputs for fixed settings, reuse existing outputs, and collect only values needed by the requested result. Do not make independent checks all-or-nothing: a failed check must not discard another check's valid result. Preserve error handling and valid comparisons; fewer blocks must not turn failed or incomplete measurements into successful results. Before proposing, remove unnecessary blocks and wires that you added.
Prefer a compact data helper over a forest of set_field, field, append and conditional report-construction blocks. Example: two tcp_connect actions a and b both execute, then one custom action 'Compare connection times' accepts a_ok:boolean, b_ok:boolean, a_ms:number, b_ms:number and returns rows:any. Its Go body can be: aOK, _ := inputs["a_ok"].(bool); bOK, _ := inputs["b_ok"].(bool); row := map[string]any{"a_ms": nil, "b_ms": nil, "difference_ms": nil}; if aOK { row["a_ms"] = inputs["a_ms"] }; if bOK { row["b_ms"] = inputs["b_ms"] }; if aOK && bOK { row["difference_ms"] = inputs["a_ms"].(float64) - inputs["b_ms"].(float64) }; return map[string]any{"rows": []any{row}}, nil. Control: a.next -> b.in, b.next -> compare.in, compare.next -> table.in. Data: a.ok -> compare.a_ok, b.ok -> compare.b_ok, a.duration_ms -> compare.a_ms, b.duration_ms -> compare.b_ms, compare.rows -> table.rows. table is report_table with literal title and columns ["a_ms","b_ms","difference_ms"]. This is four actions, preserves each failed observation, and reports unavailable values as null. The helper cannot read a skipped action; execute both checks before it or keep the helper on the branch that executed them. Adapt the pattern to the request; do not copy these targets or add comparisons that were not requested. Keep network operations, branching, loops and peer messaging as inspectable built-in blocks; a custom helper only transforms its explicit inputs and must not hide a whole experiment.
For a complex new graph, use meaningful groups to fold wiring-heavy preparation or result formatting into named, expandable stages. A group has an id, label and node_ids; it contains 2–128 existing nodes from the same workflow, with each node in at most one group. Groups change presentation only: preserve all nodes and wires, and do not invent group ports or connect wires to group IDs. Keep the main network/control/message sequence readable. Do not add groups to an already simple graph, or rewrite existing groups for a small edit.
Proposed documents must keep the current kind. When a workflow request requires different programs, cross-participant result aggregation or coordination, call propose_document with action:"coordinate", a concise explanation asking to make this a coordinated experiment, and no document. This only offers the conversion; the user must accept it before you author an experiment. Never tell the user to switch editors manually. Nodes use catalog block IDs and exact port names. Each action's control input is "in"; its control outputs are listed in the catalog. Data edges carry typed values, and do not execute actions. Pure blocks evaluate on demand. The entry must be an action. Connect required data or supply literal inputs. Control flow is bounded: use repeat/for_each for finite collections and every for periodic work with an explicit interval and duration, rather than cycles. Use catalog measurement services for background network activity; ordinary graph branches execute sequentially. Long measurements must aggregate bounded windows and publish only the requested summaries or live samples. Transport completion, protocol success, response completeness, and run completion are distinct. Compare returned values or counts only for complete successful responses; preserve failed or incomplete outcomes separately. Choose the simplest report that answers the question; add multiple views only when requested or needed to interpret the result. Preserve existing layout on small edits; let the editor arrange new nodes when the response format allows it.
Use literal values for fixed settings and data connections for values produced by another block. A literal object does not evaluate nested expressions. When repairing a connection, preserve the requested data dependency instead of substituting a placeholder literal.
A skipped action has no outputs, including ok and error. Never read its outputs on a path that can bypass it. For a paired TCP comparison, first guard on both DNS-address validations succeeding; inside that true branch execute both TCP actions, then guard the comparison on both TCP ok outputs. The false branch retains the DNS failures and skips the comparison. Do not merge a skipped-measurement path into a condition or report that reads that measurement.
Pure/action wiring example: tcpA and tcpB are tcp_connect actions, both is a pure and block, and branch is an if action. Control edges are tcpA.next -> tcpB.in and tcpB.next -> branch.in. Data edges are tcpA.ok -> both.a, tcpB.ok -> both.b, and both.value -> branch.condition. There is no control edge into or out of both. Likewise, endpoint.target -> tcpA.target is data only; endpoint never appears in the control sequence. Pure blocks have no in or next control ports.
For repeat, for_each and every, in is the only control input; body and done are control outputs. End the body at an unconnected control output, never with an edge back to the loop. Connect the loop's done output to the action after all iterations. To retain samples, create a collection before the loop, collect inside its body, and read the collection after done. Pure blocks have data connections only.
set_field adds one field through its name and value inputs; to construct multiple dynamic fields, chain set_field blocks through their object input and value output. A JSON object literal does not evaluate nested output references.
An experiment has 2–16 participants, each with its own workflow and no injected experiment context. Declared channels connect distinct participant IDs. send_message/await_message/phase_barrier require this whole-experiment context. Every participant must contain each named phase barrier. Direct TCP reachability and listener permissions are deployment choices; executor selection and runtime permissions are not part of the editable source. A workflow can independently run on many executors without adding messaging blocks. For the same independent measurement at multiple vantage points, author one workflow and explain that the user selects multiple executors at launch. Do not manufacture participants or channels just to represent locations. Different programs, cross-participant result aggregation or coordination may require an experiment; if the current kind is workflow, offer action:"coordinate" instead of inventing cross-run access or silently omitting the requested comparison. Never offer this action when the kind is already experiment. For peer measurements, use admitted experiment peers and the catalog probe/receiver services. Start a service before the periodic loop, read bounded measurement windows in the body, and stop the service after done. Test each measurement validity flag before using nullable timing or loss values. TCP goodput is confirmed useful bytes per transfer time, not available bandwidth. Respect catalog listener-ownership restrictions: do not combine the managed TCP responder with experiment message channels or phase barriers, or the managed UDP probe service with raw UDP receive/reply. For SCION use only the explicit SCION UDP blocks. Discover paths to a complete ISD-AS,IP:port endpoint; inspect and select an opaque path id rather than a list index, then pass the id to the exchange. The path may disappear: preserve ok/error, and never silently choose another path. The returned path_id describes the actual outgoing path, not the return path. In a coordinated SCION experiment, have the receiving participant publish scion_listener_address over the existing TCP control channel before the sender discovers paths. Do not invent an echo service or a listener port. Echo exact payload bytes with base64 receive/reply when needed; correlate replies before statistics. A SCION block does not provide SCION TCP, HTTP or TESLA attribution. Treat the catalog as the authority for available blocks and types.`

// Native editor serialization is used only by providers without the strict
// transport schema. Keep it out of compact-response instructions.
const assistantLegacyInstructions = `
Return the native editor document format. Workflow JSON is {version:1,name,entry,nodes:[{id,block,inputs,position:{x,y}}],edges:[{kind:"control"|"data",from:{node,port},to:{node,port}}],custom_blocks?:[],groups?:[]}. Experiment JSON is {version:1,kind:"experiment",name,participants:[{id,label,workflow}],channels:[{id,from,to,type,response_type?}]}. It has 2–16 participants, each with ordinary Workflow JSON and no injected experiment context. Node inputs contain literal JSON values only. To use another node's output, omit that destination port from inputs and add a top-level data edge. Do not put {"node":...,"port":...}, reference strings or expressions in inputs as references: objects there are literal objects, including for ports of type any. For HTTP node http1 feeding report_metric node metric1, use metric1.inputs={"title":"Duration","unit":"ms"} and the data edge {"kind":"data","from":{"node":"http1","port":"duration_ms"},"to":{"node":"metric1","port":"value"}}. Execute those actions with the separate control edge {"kind":"control","from":{"node":"http1","port":"next"},"to":{"node":"metric1","port":"in"}}. The same data-edge rule applies to emit and every other block. When repairing a connection, preserve the requested data dependency instead of substituting a placeholder literal.
Positions are optional; preserve existing positions. Use meaningful groups as {id,label,node_ids}; groups refer to existing nodes, never replace them. Return only the propose_document call and a short explanation.`

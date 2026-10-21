// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"unicode/utf16"
	"unicode/utf8"
)

// retainedWorkflowEvent uses the same accepted-record ordering as the console:
// complete JSONL records, including non-report blocks. Node IDs may repeat.
func retainedWorkflowEvent(output []byte, index int64) (json.RawMessage, string, string) {
	accepted := int64(0)
	for len(output) > 0 && accepted < 1000 {
		end := bytes.IndexByte(output, '\n')
		if end < 0 {
			break
		}
		line := output[:end]
		output = output[end+1:]
		if utf16Length(string(line)) > 65536 || !utf8.Valid(line) || !bytes.Contains(line, []byte("debuglet.workflow.v1")) {
			continue
		}
		var event struct {
			Schema         string                     `json:"schema"`
			WorkflowSHA256 string                     `json:"workflow_sha256"`
			NodeID         string                     `json:"node_id"`
			Block          string                     `json:"block"`
			Status         string                     `json:"status"`
			Outputs        map[string]json.RawMessage `json:"outputs"`
			Error          json.RawMessage            `json:"error"`
			Duration       json.RawMessage            `json:"duration_ms"`
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(line, &fields) != nil || fields == nil {
			continue
		}
		if json.Unmarshal(fields["schema"], &event.Schema) != nil ||
			json.Unmarshal(fields["workflow_sha256"], &event.WorkflowSHA256) != nil ||
			json.Unmarshal(fields["node_id"], &event.NodeID) != nil ||
			json.Unmarshal(fields["block"], &event.Block) != nil ||
			json.Unmarshal(fields["status"], &event.Status) != nil ||
			json.Unmarshal(fields["outputs"], &event.Outputs) != nil ||
			event.Schema != "debuglet.workflow.v1" || !lowerSHA256(event.WorkflowSHA256) ||
			!boundedEventText(event.NodeID, 128) || !boundedEventText(event.Block, 128) ||
			(event.Status != "completed" && event.Status != "failed") || event.Outputs == nil {
			continue
		}
		event.Error = fields["error"]
		event.Duration = fields["duration_ms"]
		if len(event.Error) > 0 {
			var message string
			if bytes.Equal(event.Error, []byte("null")) || json.Unmarshal(event.Error, &message) != nil || !boundedEventText(message, 8192) {
				continue
			}
		}
		if len(event.Duration) > 0 {
			var duration float64
			if bytes.Equal(event.Duration, []byte("null")) || json.Unmarshal(event.Duration, &duration) != nil || duration < 0 {
				continue
			}
		}
		if accepted == index {
			return append(json.RawMessage(nil), line...), event.NodeID, event.Block
		}
		accepted++
	}
	return nil, "", ""
}
func lowerSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
func boundedEventText(s string, limit int) bool { return s != "" && utf16Length(s) <= limit }
func utf16Length(s string) int {
	n := 0
	for _, r := range s {
		n += utf16.RuneLen(r)
	}
	return n
}

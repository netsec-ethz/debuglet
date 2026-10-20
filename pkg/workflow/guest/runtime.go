// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// Package guest contains operations linked into generated workflow WASI guests.
package guest

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"reflect"
	"time"
)

// Runtime holds this run's action results and emits bounded block events.
type Runtime struct {
	digest               string
	writer               io.Writer
	values               map[string]map[string]any
	steps, events, bytes int
}

func New(digest string) *Runtime {
	return &Runtime{digest: digest, writer: os.Stdout, values: map[string]map[string]any{}}
}
func (r *Runtime) Step() error {
	r.steps++
	if r.steps > 1000 {
		return fmt.Errorf("workflow exceeded 1000 action steps")
	}
	return nil
}
func (r *Runtime) Forget(ids ...string) {
	for _, id := range ids {
		delete(r.values, id)
	}
}
func (r *Runtime) Output(node, port string) (any, error) {
	outputs, ok := r.values[node]
	if !ok {
		return nil, fmt.Errorf("action %s has not executed on this control path", node)
	}
	value, ok := outputs[port]
	if !ok {
		return nil, fmt.Errorf("node %s has no output %s", node, port)
	}
	return value, nil
}
func (r *Runtime) Record(node, block string, outputs map[string]any) error {
	if outputs == nil {
		outputs = map[string]any{}
	}
	if err := r.event(node, block, "completed", outputs, ""); err != nil {
		return err
	}
	r.values[node] = outputs
	return nil
}
func (r *Runtime) Fail(node, block string, err error) error {
	if err == nil {
		return nil
	}
	message := err.Error()
	if len(message) > 1024 {
		message = message[:1024]
	}
	if emitErr := r.event(node, block, "failed", map[string]any{}, message); emitErr != nil {
		return fmt.Errorf("node %s: %w (trace: %v)", node, err, emitErr)
	}
	return fmt.Errorf("node %s: %w", node, err)
}
func (r *Runtime) event(node, block, status string, outputs map[string]any, message string) error {
	if err := checkValue(outputs, 0); err != nil {
		return err
	}
	event := struct {
		Schema   string         `json:"schema"`
		Workflow string         `json:"workflow_sha256"`
		Node     string         `json:"node_id"`
		Block    string         `json:"block"`
		Status   string         `json:"status"`
		Outputs  map[string]any `json:"outputs"`
		Error    string         `json:"error,omitempty"`
	}{"debuglet.workflow.v1", r.digest, node, block, status, outputs, message}
	b, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if len(b) > 65536 {
		return fmt.Errorf("node output exceeds 64 KiB")
	}
	if r.events >= 4096 || r.bytes+len(b)+1 > 4*1024*1024 {
		return fmt.Errorf("workflow trace exceeds its output limit")
	}
	b = append(b, '\n')
	n, err := r.writer.Write(b)
	r.events++
	r.bytes += n
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	return err
}

// Check validates JSON values at each typed boundary, including dynamic data.
func Check(values map[string]any, types map[string]string) error {
	for name, kind := range types {
		v, ok := values[name]
		if !ok {
			return fmt.Errorf("missing value %s", name)
		}
		if !Matches(v, kind) {
			return fmt.Errorf("%s requires %s", name, kind)
		}
		if err := checkValue(v, 0); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}
func Matches(v any, kind string) bool {
	switch kind {
	case "any":
		return true
	case "string":
		_, ok := v.(string)
		return ok
	case "number":
		n, ok := v.(float64)
		return ok && !math.IsNaN(n) && !math.IsInf(n, 0)
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "numbers", "strings":
		items, ok := v.([]any)
		if !ok {
			return false
		}
		itemType := "number"
		if kind == "strings" {
			itemType = "string"
		}
		for _, x := range items {
			if !Matches(x, itemType) {
				return false
			}
		}
		return true
	}
	return false
}
func checkValue(v any, depth int) error {
	if depth > 16 {
		return fmt.Errorf("value is nested more than 16 levels")
	}
	switch x := v.(type) {
	case nil, bool:
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return fmt.Errorf("number must be finite")
		}
	case string:
		if len(x) > 16384 {
			return fmt.Errorf("string exceeds 16 KiB")
		}
	case []any:
		if len(x) > 1024 {
			return fmt.Errorf("list exceeds 1024 values")
		}
		for _, v := range x {
			if err := checkValue(v, depth+1); err != nil {
				return err
			}
		}
	case map[string]any:
		if len(x) > 1024 {
			return fmt.Errorf("object exceeds 1024 fields")
		}
		for k, v := range x {
			if len(k) > 256 {
				return fmt.Errorf("field name exceeds 256 bytes")
			}
			if err := checkValue(v, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("value of type %T is not a JSON workflow value", v)
	}
	return nil
}

// Normalize converts custom Go results to the same JSON types used by wires.
func Normalize(values map[string]any) (map[string]any, error) {
	b, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}
	if len(b) > 65536 {
		return nil, fmt.Errorf("custom result exceeds 64 KiB")
	}
	var out map[string]any
	if err = json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = map[string]any{}
	}
	return out, checkValue(out, 0)
}

// Pure evaluates a built-in operation with already type-checked inputs.
func Pure(block string, in map[string]any) (map[string]any, error) {
	var value any
	switch block {
	case "constant":
		value = in["value"]
	case "field":
		v, ok := in["object"].(map[string]any)[in["name"].(string)]
		if !ok {
			return nil, fmt.Errorf("field %q is absent", in["name"])
		}
		value = v
	case "parse_json":
		if err := json.Unmarshal([]byte(in["text"].(string)), &value); err != nil {
			return nil, fmt.Errorf("invalid JSON: %w", err)
		}
	case "mean", "min", "max":
		items := in["values"].([]any)
		if len(items) == 0 {
			return nil, fmt.Errorf("%s requires at least one sample", block)
		}
		n := items[0].(float64)
		for i, item := range items {
			if i == 0 {
				continue
			}
			x := item.(float64)
			switch block {
			case "mean":
				n += x
			case "min":
				n = math.Min(n, x)
			case "max":
				n = math.Max(n, x)
			}
		}
		if block == "mean" {
			n /= float64(len(items))
		}
		value = n
	case "count":
		items, ok := in["values"].([]any)
		if !ok {
			return nil, fmt.Errorf("count requires a list")
		}
		value = float64(len(items))
	case "add":
		value = in["a"].(float64) + in["b"].(float64)
	case "subtract":
		value = in["a"].(float64) - in["b"].(float64)
	case "greater_than":
		value = in["a"].(float64) > in["b"].(float64)
	case "less_than":
		value = in["a"].(float64) < in["b"].(float64)
	case "equals":
		value = reflect.DeepEqual(in["a"], in["b"])
	case "and":
		value = in["a"].(bool) && in["b"].(bool)
	case "or":
		value = in["a"].(bool) || in["b"].(bool)
	case "not":
		value = !in["value"].(bool)
	default:
		return nil, fmt.Errorf("unsupported pure block %s", block)
	}
	out := map[string]any{"value": value}
	return out, checkValue(out, 0)
}
func RepeatCount(v any) (int, error) {
	n, ok := v.(float64)
	if !ok || math.IsNaN(n) || n < 1 || n > 100 || math.Trunc(n) != n {
		return 0, fmt.Errorf("repeat count must be an integer from 1 to 100")
	}
	return int(n), nil
}
func Wait(v any) error {
	n, ok := v.(float64)
	if !ok || math.IsNaN(n) || n < 0 || n > 60000 {
		return fmt.Errorf("wait must be between 0 and 60000 ms")
	}
	time.Sleep(time.Duration(n * float64(time.Millisecond)))
	return nil
}

// RunCustom reports a returned error or panic at the calling block boundary.
// The executor still bounds code that does not return, including infinite loops.
func RunCustom(fn func(map[string]any) (map[string]any, error), inputs map[string]any) (out map[string]any, err error) {
	defer func() {
		if problem := recover(); problem != nil {
			out = nil
			err = fmt.Errorf("custom block panicked: %v", problem)
		}
	}()
	out, err = fn(inputs)
	if err != nil {
		return nil, err
	}
	return Normalize(out)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

func input(name, kind string) Port               { return Port{Name: name, Type: kind, Required: true} }
func optional(name, kind string, value any) Port { return Port{Name: name, Type: kind, Default: value} }
func output(name, kind string) Port              { return Port{Name: name, Type: kind} }

// Catalog returns independent descriptions of the supported primitives.
func Catalog() []Block {
	return []Block{
		{"http", "HTTP request", "Network", "Send one HTTP request. ok describes transport completion; compare status to choose an HTTP success policy. Redirects are returned, not followed.", false, []Port{input("url", "string"), optional("method", "string", "GET"), optional("timeout_ms", "number", float64(2000))}, []Port{output("ok", "boolean"), output("error", "string"), output("status", "number"), output("body", "string"), output("duration_ms", "number")}, []string{"next"}},
		{"tcp_connect", "TCP connect", "Network", "Measure one TCP connection to host:port.", false, []Port{input("target", "string"), optional("timeout_ms", "number", float64(2000))}, []Port{output("ok", "boolean"), output("error", "string"), output("duration_ms", "number")}, []string{"next"}},
		{"ping", "Ping", "Network", "Send up to ten ICMPv4 echo requests. rtts_ms contains successful replies; loss is a percentage.", false, []Port{input("target", "string"), optional("count", "number", float64(3)), optional("timeout_ms", "number", float64(2000))}, []Port{output("ok", "boolean"), output("error", "string"), output("rtts_ms", "numbers"), output("sent", "number"), output("received", "number"), output("loss", "number")}, []string{"next"}},
		{"constant", "Constant", "Data", "Provide a JSON value.", true, []Port{input("value", "any")}, []Port{output("value", "any")}, []string{}},
		{"field", "Get field", "Data", "Read one named field from an object; missing fields are errors.", true, []Port{input("object", "object"), input("name", "string")}, []Port{output("value", "any")}, []string{}},
		{"parse_json", "Parse JSON", "Data", "Parse a JSON string into a value.", true, []Port{input("text", "string")}, []Port{output("value", "any")}, []string{}},
		{"mean", "Mean", "Analysis", "Arithmetic mean of a nonempty number list.", true, []Port{input("values", "numbers")}, []Port{output("value", "number")}, []string{}},
		{"min", "Minimum", "Analysis", "Smallest value in a nonempty number list.", true, []Port{input("values", "numbers")}, []Port{output("value", "number")}, []string{}},
		{"max", "Maximum", "Analysis", "Largest value in a nonempty number list.", true, []Port{input("values", "numbers")}, []Port{output("value", "number")}, []string{}},
		{"count", "Count", "Analysis", "Number of items in a JSON list.", true, []Port{input("values", "any")}, []Port{output("value", "number")}, []string{}},
		{"add", "Add", "Math", "Add two numbers.", true, []Port{input("a", "number"), input("b", "number")}, []Port{output("value", "number")}, []string{}},
		{"subtract", "Subtract", "Math", "Subtract b from a.", true, []Port{input("a", "number"), input("b", "number")}, []Port{output("value", "number")}, []string{}},
		{"greater_than", "Greater than", "Logic", "Whether a is greater than b.", true, []Port{input("a", "number"), input("b", "number")}, []Port{output("value", "boolean")}, []string{}},
		{"less_than", "Less than", "Logic", "Whether a is less than b.", true, []Port{input("a", "number"), input("b", "number")}, []Port{output("value", "boolean")}, []string{}},
		{"equals", "Equals", "Logic", "Compare JSON values without coercion.", true, []Port{input("a", "any"), input("b", "any")}, []Port{output("value", "boolean")}, []string{}},
		{"and", "And", "Logic", "Both conditions are true.", true, []Port{input("a", "boolean"), input("b", "boolean")}, []Port{output("value", "boolean")}, []string{}},
		{"or", "Or", "Logic", "At least one condition is true.", true, []Port{input("a", "boolean"), input("b", "boolean")}, []Port{output("value", "boolean")}, []string{}},
		{"not", "Not", "Logic", "Invert a condition.", true, []Port{input("value", "boolean")}, []Port{output("value", "boolean")}, []string{}},
		{"if", "If", "Control", "Run exactly the selected branch.", false, []Port{input("condition", "boolean")}, []Port{}, []string{"true", "false"}},
		{"repeat", "Repeat", "Control", "Run the body sequentially up to 100 times, then continue on done. The body ends at an unconnected control output.", false, []Port{input("count", "number")}, []Port{output("iteration", "number")}, []string{"body", "done"}},
		{"wait", "Wait", "Control", "Wait between actions, at most 60 seconds per call.", false, []Port{input("duration_ms", "number")}, []Port{}, []string{"next"}},
		{"emit", "Emit result", "Results", "Publish a named JSON result.", false, []Port{input("name", "string"), input("value", "any")}, []Port{output("name", "string"), output("value", "any")}, []string{"next"}},
	}
}

func catalogFor(w Workflow) map[string]Block {
	m := map[string]Block{}
	for _, b := range Catalog() {
		m[b.ID] = b
	}
	for _, b := range w.CustomBlocks {
		m[b.ID] = Block{b.ID, b.Label, "Custom", "Custom Go action", false, b.Inputs, b.Outputs, []string{"next"}}
	}
	return m
}

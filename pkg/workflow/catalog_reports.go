// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

func reportCatalog() []Block {
	return []Block{
		{"select_field", "Select field", "Data", "Read one named field from every object in a list, preserving order. Missing fields and non-object rows are errors. Connect a number field to existing statistics blocks.", true,
			[]Port{input("values", "any"), input("field", "string")}, []Port{output("values", "any")}, []string{}},
		{"filter_rows", "Filter rows", "Data", "Keep rows whose named field matches a value. Operators: equals, not_equals, greater_than, less_than, at_least, at_most. Equality compares JSON without coercion; ordering requires numbers. Missing fields and non-object rows are errors.", true,
			[]Port{input("rows", "any"), input("field", "string"), optional("operator", "string", "equals"), input("value", "any")}, []Port{output("rows", "any")}, []string{}},
		{"report_metric", "Report metric", "Results", "Publish a titled finite number and optional unit in the run's report. Uses the ordinary workflow output limits.", false,
			[]Port{input("title", "string"), input("value", "number"), optional("unit", "string", "")}, []Port{output("title", "string"), output("value", "number"), output("unit", "string")}, []string{"next"}},
		{"report_table", "Report table", "Results", "Publish a titled list of objects as a report table. Choose 1–32 distinct field names in columns; every row must contain them. All rows remain in the output, including fields not displayed. Uses the ordinary workflow output limits.", false,
			[]Port{input("title", "string"), input("rows", "any"), input("columns", "strings")}, []Port{output("title", "string"), output("rows", "any"), output("columns", "strings")}, []string{"next"}},
		{"report_text", "Report text", "Results", "Publish titled plain text in the run's report. Text is displayed literally, without HTML or Markdown interpretation. Uses the ordinary workflow output limits.", false,
			[]Port{input("title", "string"), input("text", "string")}, []Port{output("title", "string"), output("text", "string")}, []string{"next"}},
	}
}

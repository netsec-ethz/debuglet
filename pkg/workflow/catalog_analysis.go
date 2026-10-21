// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

func analysisCatalog() []Block {
	return []Block{
		{"standard_deviation", "Standard deviation", "Analysis", "Spread of finite samples. sample divides squared deviations by n−1 and requires at least two values; population divides by n and requires at least one. Does not estimate confidence or statistical significance.", true,
			[]Port{input("values", "numbers"), optional("mode", "string", "sample")}, []Port{output("value", "number")}, []string{}},
		{"histogram", "Histogram", "Analysis", "Count values in 1–256 bins defined by strictly increasing finite edges. Bins include their lower edge and exclude their upper edge, except the final bin includes both. Rows contain lower, upper, midpoint and count. Underflow and overflow count values outside the edges; no samples are dropped.", true,
			[]Port{input("values", "numbers"), input("edges", "numbers")}, []Port{output("rows", "any"), output("underflow", "number"), output("overflow", "number"), output("count", "number")}, []string{}},
		{"sort_rows", "Sort rows", "Data", "Return rows ordered by one named field, ascending or descending. Equal keys retain input order. Every key must be a finite number or every key a string; strings use lexical order, without locale rules. Missing fields are errors. The input list is unchanged.", true,
			[]Port{input("rows", "any"), input("field", "string"), optional("order", "string", "ascending")}, []Port{output("rows", "any")}, []string{}},
		{"report_chart", "Report chart", "Results", "Publish 1–256 rows with finite numeric x and y fields as a line or bar chart and an exact-value table. Lines connect points in input order on a numeric x axis; bars keep row order and include a zero baseline. Uses ordinary workflow output limits.", false,
			[]Port{input("title", "string"), input("rows", "any"), input("x", "string"), input("y", "string"), optional("kind", "string", "line"), optional("x_label", "string", ""), optional("y_label", "string", "")}, []Port{output("title", "string"), output("rows", "any"), output("x", "string"), output("y", "string"), output("kind", "string"), output("x_label", "string"), output("y_label", "string")}, []string{"next"}},
	}
}

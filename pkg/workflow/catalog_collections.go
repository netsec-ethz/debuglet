// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

func collectionCatalog() []Block {
	return []Block{
		{"distinct", "Distinct values", "Data", "Remove duplicate JSON values, preserving their first occurrence. No string or number coercion.", true, []Port{input("values", "any")}, []Port{output("values", "any")}, []string{}},
		{"group_by", "Group rows", "Data", "Group object rows by a named field. Returns groups with key, rows and count, in first-seen key order. Missing fields are errors.", true, []Port{input("rows", "any"), input("field", "string")}, []Port{output("groups", "any")}, []string{}},
		{"set_union", "Set union", "Data", "Distinct JSON values present in either list, in first-seen order across a then b.", true, []Port{input("a", "any"), input("b", "any")}, []Port{output("values", "any")}, []string{}},
		{"set_intersection", "Set intersection", "Data", "Distinct JSON values present in both lists, in the order first encountered in a.", true, []Port{input("a", "any"), input("b", "any")}, []Port{output("values", "any")}, []string{}},
		{"set_difference", "Set difference", "Data", "Distinct JSON values present in a but absent from b, preserving their first occurrence in a.", true, []Port{input("a", "any"), input("b", "any")}, []Port{output("values", "any")}, []string{}},
		{"join_rows", "Join tables", "Data", "Inner join on named fields using JSON equality. Each matching pair becomes {left, right}; duplicate keys produce every pair in left then right order. Missing fields and more than 1024 result rows are errors.", true, []Port{input("left", "any"), input("right", "any"), input("left_key", "string"), input("right_key", "string")}, []Port{output("rows", "any")}, []string{}},
		{"endpoint", "Address and port", "Network", "Combine a hostname or IP address with a port from 1 to 65535. IPv6 addresses are bracketed automatically. This does not resolve the address or send traffic.", true, []Port{input("address", "string"), input("port", "number")}, []Port{output("target", "string")}, []string{}},
	}
}

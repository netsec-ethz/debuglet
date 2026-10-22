// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

func iterationCatalog() []Block {
	return []Block{{"for_each", "For each item", "Control", "Visit a list of up to 100 items sequentially. item and zero-based index are available inside body; an empty list goes straight to done. Use a collection to retain results after the loop.", false, []Port{input("values", "any")}, []Port{output("item", "any"), output("index", "number")}, []string{"body", "done"}}}
}

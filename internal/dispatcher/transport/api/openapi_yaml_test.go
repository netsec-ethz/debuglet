// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"reflect"
	"testing"
)

func TestContractYAMLTypes(t *testing.T) {
	value, err := parseYAML([]byte("200:\n  quoted: \"true\"\n  boolean: true\n  integer: 08\n  number: 1.5\n  date: 2026-10-21\n  empty: []\n  null: null\n"))
	want := map[string]any{"200": map[string]any{"quoted": "true", "boolean": true, "integer": int64(8), "number": 1.5, "date": "2026-10-21", "empty": []any{}, "null": nil}}
	if err != nil || !reflect.DeepEqual(value, want) {
		t.Fatalf("decoded %#v, %v; want %#v", value, err, want)
	}
}

func TestContractYAMLRejectsAmbiguity(t *testing.T) {
	for name, document := range map[string]string{
		"duplicate":          "200: first\n\"200\": second\n",
		"anchor":             "a: &first value\n",
		"alias":              "a: *missing\n",
		"explicit tag":       "a: !!str 12\n",
		"composite key":      "? [a, b]\n: value\n",
		"merge":              "a:\n  <<: value\n",
		"multiple documents": "a: first\n---\na: second\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseYAML([]byte(document)); err == nil {
				t.Fatal("accepted ambiguous contract")
			}
		})
	}
}

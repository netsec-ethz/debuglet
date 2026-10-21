// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

package netaddr

import (
	"reflect"
	"testing"
)

func TestParsePortRanges(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		want    []int
		wantErr bool
	}{
		{name: "empty", spec: "", want: []int{}},
		{name: "single port", spec: "2022", want: []int{2022}},
		{name: "single range", spec: "2025-3005", want: seq(2025, 3005)},
		{name: "mixed", spec: "2022,2025-3005,56000-62000", want: append(append([]int{2022}, seq(2025, 3005)...), seq(56000, 62000)...)},
		{name: "whitespace", spec: " 2022 , 2025 - 3005 , 56000-62000 ", want: append(append([]int{2022}, seq(2025, 3005)...), seq(56000, 62000)...)},
		{name: "dedupe", spec: "2022,2022,2022-2024", want: []int{2022, 2023, 2024}},
		{name: "trailing comma", spec: "2022,", want: []int{2022}},
		{name: "out of range low", spec: "0", wantErr: true},
		{name: "out of range high", spec: "65536", wantErr: true},
		{name: "start greater than end", spec: "3005-2025", wantErr: true},
		{name: "non-numeric", spec: "abc", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePortRanges(tt.spec)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParsePortRanges(%q) expected error, got %v", tt.spec, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePortRanges(%q) unexpected error: %v", tt.spec, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParsePortRanges(%q) = %v, want %v", tt.spec, got, tt.want)
			}
		})
	}
}

func seq(lo, hi int) []int {
	out := make([]int, 0, hi-lo+1)
	for p := lo; p <= hi; p++ {
		out = append(out, p)
	}
	return out
}

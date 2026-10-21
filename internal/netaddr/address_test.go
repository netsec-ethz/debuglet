// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

package netaddr

import "testing"

func TestDeclaredHostReadsSCIONAndPortedEntries(t *testing.T) {
	for declared, want := range map[string]string{
		"127.0.0.1":                       "127.0.0.1",
		"target.example":                  "target.example",
		"target.example:443":              "target.example",
		"1-ff00:0:110,127.0.0.1":          "127.0.0.1",
		"1-ff00:0:110,[::1]:443":          "::1",
		" 1-ff00:0:110,target.example:80": "target.example",
	} {
		if got := DeclaredHost(declared); got != want {
			t.Errorf("DeclaredHost(%q) = %q, want %q", declared, got, want)
		}
	}
}

func TestDestinationKey(t *testing.T) {
	for input, want := range map[string]string{
		"":                         "",
		"  TARGET.Example.:443 ":   "target.example",
		"[::ffff:192.0.2.131]:443": "192.0.2.131",
		"fe80::1%eth0":             "fe80::1",
		"1-ff00:0:110,[::1]:443":   "::1",
		"[2001:db8::1]":            "2001:db8::1",
		"target.example:bad":       "target.example:bad",
		"target.example:65536":     "target.example:65536",
	} {
		if got := DestinationKey(input); got != want {
			t.Errorf("DestinationKey(%q) = %q, want %q", input, got, want)
		}
	}
}

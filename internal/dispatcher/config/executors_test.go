// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import (
	"strings"
	"testing"
)

func TestExecutorDisplayMetadata(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, baseSections+`
[executors."eth-zurich-1"]
display_name = "ETH Zürich lab"
city = "Zürich"
country = "CH"
network = "SWITCH (AS559)"

[executors.bare]
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Executors["eth-zurich-1"]; got != (ExecutorDisplay{DisplayName: "ETH Zürich lab", City: "Zürich", Country: "CH", Network: "SWITCH (AS559)"}) {
		t.Fatalf("decoded %+v", got)
	}
	if got, ok := cfg.Executors["bare"]; !ok || got != (ExecutorDisplay{}) {
		t.Fatalf("empty entry: %+v %v", got, ok)
	}

	long := strings.Repeat("é", MaxDisplayTextLength+1)
	for _, tc := range []struct{ name, body, want string }{
		{"lower-case country", "[executors.a]\ncountry = 'ch'\n", `executors."a".country`},
		{"unassigned country", "[executors.a]\ncountry = 'XX'\n", "ISO 3166-1 alpha-2"},
		{"alpha-3 country", "[executors.a]\ncountry = 'CHE'\n", `executors."a".country`},
		{"long name", "[executors.a]\ndisplay_name = '" + long + "'\n", "at most 64 characters, got 65"},
		{"control character", "[executors.a]\ncity = \"Z\\u0007rich\"\n", `executors."a".city must not contain control`},
		{"padded network", "[executors.a]\nnetwork = ' AS559'\n", `executors."a".network`},
		{"key with space", "[executors.'bad id']\ncity = 'Bern'\n", `executors key "bad id"`},
		{"unknown key", "[executors.a]\nlatitude = 47.3\n", `unsupported configuration key "executors.a.latitude"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadConfig(writeConfig(t, baseSections+tc.body))
			if err == nil || cfg != nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error naming %q", err, tc.want)
			}
		})
	}
	if !isoCountry("GB") || isoCountry("UK") || isoCountry("") {
		t.Fatal("country table")
	}
}

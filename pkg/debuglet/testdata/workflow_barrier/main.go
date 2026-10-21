// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/netsec-ethz/debuglet/pkg/workflow/guest"
)

func main() {
	self, scenario := os.Args[0], os.Args[1]
	config, _ := json.Marshal(map[string]any{
		"participant": self, "fingerprint": strings.Repeat("a", 64),
		"participants": []string{"a", "b", "c"},
		"channels":     []map[string]any{{"id": "notice", "from": "a", "to": "b", "type": "string"}},
	})
	e, err := guest.JoinExperiment(string(config))
	if err != nil {
		panic(err)
	}
	barrier := func(phase string, timeout float64, want bool) {
		out, err := e.Barrier(map[string]any{"phase": phase, "timeout_ms": timeout})
		if err != nil || out["ok"] != want {
			panic(fmt.Sprintf("%s phase %s: %#v %v", self, phase, out, err))
		}
		if !want {
			missing := out["missing"].([]any)
			found := false
			for _, peer := range missing {
				found = found || peer == "c"
			}
			if !found || out["error"] == "" {
				panic(fmt.Sprintf("missing participant not reported: %#v", out))
			}
		}
		encoded, _ := json.Marshal(out)
		fmt.Println(string(encoded))
	}
	if scenario == "timeout" {
		if self != "c" {
			barrier("missing", 200, false)
			barrier("missing", 200, false)
		}
		barrier("recovery", 10000, true)
	} else {
		if self == "a" {
			out, err := e.Send(map[string]any{"destination": "b", "channel": "notice", "value": "preserved", "timeout_ms": float64(10000)})
			if err != nil || out["ok"] != true {
				panic(fmt.Sprintf("send: %#v %v", out, err))
			}
		}
		barrier("ready", 10000, true)
		if self == "b" {
			out, err := e.Await(map[string]any{"source": "a", "channel": "notice", "timeout_ms": float64(10000)})
			if err != nil || out["ok"] != true || out["value"] != "preserved" {
				panic(fmt.Sprintf("user message: %#v %v", out, err))
			}
			fmt.Println("user message preserved")
		}
		for range 3 {
			barrier("sample", 10000, true)
		}
	}
	fmt.Println("barrier scenario complete")
}

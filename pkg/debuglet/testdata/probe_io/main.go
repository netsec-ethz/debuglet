// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"encoding/json"
	"fmt"
	"github.com/netsec-ethz/debuglet/pkg/debuglet"
	"os"
	"time"
)

func main() {
	var value any
	var err error
	switch os.Args[1] {
	case "tls":
		value, err = debuglet.InspectTLS(os.Args[2], 2*time.Second)
	case "hop":
		value, err = debuglet.ProbeHop(os.Args[2], 1, 2*time.Second)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(value); err != nil {
		panic(err)
	}
}

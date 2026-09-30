// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import "testing"

func TestPublicTerminalProjectionPreservesFailureTruth(t *testing.T) {
	for _, message := range []string{"", outcomeUnknown, "debuglet exited with code 42", "debuglet cancelled", "timeout of 2s exceeded", "guest socket quota exceeded", "compilation resource budget exceeded", "destination refused: outside the job's destination policy"} {
		if got := PublicTerminalError(message); got != message {
			t.Fatalf("%q became %q", message, got)
		}
	}
	for _, message := range []string{"SENTINEL credential stack /private/path", "module does not compile: SENTINEL argument", "debuglet exited with code 0\nSENTINEL", "timeout of invalid exceeded", "debuglet exited with code 999999999999"} {
		got := PublicTerminalError(message)
		if got == "" || got == message {
			t.Fatalf("unclassified failure exposed or cleared: %q", got)
		}
	}
}

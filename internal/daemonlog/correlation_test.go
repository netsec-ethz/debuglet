// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package daemonlog

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestCorrelationIdentifiers(t *testing.T) {
	for _, value := range []string{"line\nbreak", "space id", "\x00hidden", strings.Repeat("x", 129), "é"} {
		got := Identifier(value)
		if !strings.HasPrefix(got, "sha256:") || len(got) != 71 || got != Identifier(value) {
			t.Fatalf("unsafe identifier: %q", got)
		}
	}
	if Identifier("executor-1") != "executor-1" || Identifier("") != "unknown" || Identifier("line\nbreak") == Identifier("line\rbreak") {
		t.Fatal("lost identifier distinction")
	}
	rendered := Identifier(strings.Repeat("x", 129))
	if Identifier(rendered) == rendered || Identifier("unknown") == Identifier("") {
		t.Fatal("literal identifier aliases rendered namespace")
	}
	ctx := context.Background()
	if RequestID(ctx) != "unknown" {
		t.Fatal("absent request identity invented")
	}
	id := uuid.New()
	if RequestID(WithRequestID(ctx, id)) != id.String() {
		t.Fatal("request identity lost")
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// An exit report's message is stored as one line of valid UTF-8, cut at 512
// bytes; the exit-code and NULL normalizations are unchanged.
func TestTerminalErrorStoresOneBoundedLine(t *testing.T) {
	// The two-byte rune starts at byte 511, so a byte cut at 512 would split it.
	split := strings.Repeat("a", 511) + "é" + strings.Repeat("b", 1487)
	exact := strings.Repeat("c", 512)
	longer := exact + "d"
	cases := []struct {
		name string
		code int32
		msg  *string
		want sql.NullString
	}{
		{"line breaks and control characters become spaces", -1, tgStr("line one\nline two\r\n\ttab\x00nul\x7fdel\x1b[31m\u0085end"),
			tgText("line one line two   tab nul del [31m end")},
		{"invalid UTF-8 is replaced", -1, tgStr("bad \xff\xfe byte"), tgText("bad �� byte")},
		{"a long message is cut on a rune boundary", -1, &split, tgText(strings.Repeat("a", 511) + "...")},
		{"a message of exactly the bound is kept", -1, &exact, tgText(exact)},
		{"one byte over the bound is cut", -1, &longer, tgText(exact + "...")},
		{"an abort reason is unchanged", -1, tgStr("cancelled via API"), tgText("cancelled via API")},
		{"an exit code text is unchanged", -1, tgStr("debuglet exited with code 7"), tgText("debuglet exited with code 7")},
		{"a short message is unchanged", 5, tgStr("crashed: segfault at 0x0"), tgText("crashed: segfault at 0x0")},
		{"nonzero exit and empty message", -1, tgStr(""), tgText("debuglet exited with code -1")},
		{"nonzero exit and nil message", 3, nil, tgText("debuglet exited with code 3")},
		{"zero exit and empty message", 0, tgStr(""), tgNull},
		{"zero exit and nil message", 0, nil, tgNull},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := terminalError(tc.code, tc.msg)
			if got != tc.want {
				t.Fatalf("stored %d bytes %q, want %q", len(got.String), got.String, tc.want.String)
			}
			if len(got.String) > 515 || !utf8.ValidString(got.String) || strings.ContainsAny(got.String, "\r\n") {
				t.Fatalf("stored text is not one bounded line: %q", got.String)
			}
		})
	}
}

// The reported message stays at the debug level: an operator log at info and
// above does not carry a run owner's result text.
func TestTerminalErrorStaysOutOfInfoLogs(t *testing.T) {
	f := newTGFixture(t, nil)
	deb := f.seedDirect(t, tgFloorA)
	core, logs := observer.New(zapcore.InfoLevel)
	f.d.logger = zap.New(core)
	const detail = "reported detail 5f1c"
	if err := f.exit(t, deb.id, -1, tgStr("run failed: "+detail)); err != nil {
		t.Fatalf("OnDebugletExit: %v", err)
	}
	tgAssertRow(t, f.row(t, deb.id), models.RunStateExited, tgText("run failed: "+detail))
	for _, entry := range logs.All() {
		if strings.Contains(entry.Message, detail) || strings.Contains(fmt.Sprint(entry.ContextMap()), detail) {
			t.Fatalf("reported message logged at %s: %q %v", entry.Level, entry.Message, entry.ContextMap())
		}
	}
}

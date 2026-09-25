// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/pkg/client"
)

// A failure report that spans lines and exceeds the stored bound reaches the
// SDK and the CLI as the one bounded line the dispatcher recorded: 512 bytes
// of the report followed by "...".
func TestTerminalErrorReachesClientsAsOneLine(t *testing.T) {
	f := ccNewFixture(t)
	f.dbl = ccBuildCLI(t)
	c := f.client(f.root.URL, false)
	message := "first line\nsecond line\r\n" + strings.Repeat("x", 2000)
	// One line of 515 bytes: the report's first 512 bytes with its line breaks
	// turned into spaces, and the marker.
	head := "first line second line  "
	want := head + strings.Repeat("x", 512-len(head)) + "..."

	f.peer.setUploadHook(f.exitHook(-1, &message))
	sub := f.submit(c, nil)
	ctx, cancel := f.requestCtx()
	defer cancel()
	st, err := c.Status(ctx, sub.IDs[0])
	if err != nil || st.State != client.StateExited || st.Error != want {
		t.Fatalf("status reported %d bytes %q (err %v), want %q", len(st.Error), st.Error, err, want)
	}
	page, err := c.Logs(ctx, sub.IDs[0], client.LogOptions{})
	if err != nil || page.State != client.StateExited || page.Error != want {
		t.Fatalf("logs reported %d bytes %q (err %v), want %q", len(page.Error), page.Error, err, want)
	}

	code, stdout, stderr := f.runCLI("--endpoint", f.root.URL, "--output", "json", "status", sub.IDs[0])
	if code != 0 {
		t.Fatalf("dbl status exit %d: %s", code, stderr)
	}
	var cliState struct {
		ID    string `json:"id"`
		State string `json:"state"`
		Error string `json:"error"`
	}
	ccDecode(t, "dbl status", stdout, &cliState)
	if cliState.ID != sub.IDs[0] || cliState.State != client.StateExited || cliState.Error != want {
		t.Fatalf("dbl status reported %d bytes %q, want %q", len(cliState.Error), cliState.Error, want)
	}
}

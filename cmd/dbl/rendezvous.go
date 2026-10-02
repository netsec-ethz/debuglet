// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/demo"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/client"
)

const rendezvousUsage = `Usage:
  dbl rendezvous --server-executor ID --client-executor ID --server-allow ADDRESS
      [--server-wasm FILE --client-wasm FILE] [--duration 30s] [--ready-timeout 10s]
      [--allow-remote-test]

Run the installed TCP echo server and client on two distinct executors.
--server-allow identifies an allowed client source address (repeatable). The
client destination is obtained from the server's structured readiness report.
No address is read from guest output. Both runs are cleaned up on every exit;
retain printed IDs when delivery or cleanup cannot be confirmed. No replay is
attempted. Custom programs must accept the installed demo's echo-server/echo-client modes.
`

func rendezvousCommand(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer) int {
	fs := newCommandFlagSet("rendezvous")
	var serverID, clientID, serverWasm, clientWasm string
	var allow stringList
	var duration, ready time.Duration
	var remote bool
	fs.StringVar(&serverID, "server-executor", "", "")
	fs.StringVar(&clientID, "client-executor", "", "")
	fs.StringVar(&serverWasm, "server-wasm", "", "")
	fs.StringVar(&clientWasm, "client-wasm", "", "")
	fs.Var(&allow, "server-allow", "")
	fs.DurationVar(&duration, "duration", 30*time.Second, "")
	fs.DurationVar(&ready, "ready-timeout", 10*time.Second, "")
	fs.BoolVar(&remote, "allow-remote-test", false, "")
	if code, ok := parseCommandFlags(fs, args, rendezvousUsage, stdout, stderr); !ok {
		return code
	}
	if fs.NArg() != 0 || serverID == "" || clientID == "" || serverID == clientID || len(allow) == 0 || duration < time.Second || duration > 5*time.Minute || ready < time.Millisecond || ready > time.Minute {
		return usageError("dbl rendezvous", rendezvousUsage, stderr, "two distinct executors, a server allowlist and bounded durations are required")
	}
	if serverWasm == "" || clientWasm == "" {
		executable, err := os.Executable()
		if err != nil {
			return reportFailure(ctx, "dbl rendezvous: executable", stderr, err)
		}
		assets, err := demo.ResolveAssets(executable)
		if err != nil {
			return reportFailure(ctx, "dbl rendezvous: installed samples", stderr, err)
		}
		if serverWasm == "" {
			serverWasm = filepath.Join(assets.Root, "share", "debuglet", "demo.wasm")
		}
		if clientWasm == "" {
			clientWasm = filepath.Join(assets.Root, "share", "debuglet", "demo.wasm")
		}
	}
	serverBytes, err := readWasm(serverWasm)
	if err != nil {
		return reportFailure(ctx, "dbl rendezvous: server program", stderr, err)
	}
	clientBytes, err := readWasm(clientWasm)
	if err != nil {
		return reportFailure(ctx, "dbl rendezvous: client program", stderr, err)
	}
	c, code, ok := connect("dbl rendezvous", options, remote, stderr)
	if !ok {
		return code
	}
	nonce := strings.ReplaceAll(uuid.NewString(), "-", "")
	server := client.Request{ExecutorID: serverID, Wasm: serverBytes, Args: []string{"echo-server", nonce}, Label: "TCP echo server", ProgramName: "demo.wasm", Policy: client.Policy{FloorBW: 100000, CeilBW: 100000, TimeoutMS: duration.Milliseconds(), Addresses: []string(allow), ListenTCP: true}}
	peer := client.Request{ExecutorID: clientID, Wasm: clientBytes, Args: []string{"echo-client", client.ServerEndpoint, nonce}, Label: "TCP echo client", ProgramName: "demo.wasm", Policy: client.Policy{FloorBW: 100000, CeilBW: 100000, TimeoutMS: duration.Milliseconds(), Addresses: []string{}}}
	result, err := c.RendezvousTEST(ctx, server, peer, client.RendezvousOptions{Timeout: duration, ReadinessTimeout: ready, Output: func(role, id string, page client.LogPage) error {
		if options.Output == outputJSON {
			return writeJSON(stdout, struct {
				Role   string         `json:"role"`
				RunID  string         `json:"run_id"`
				Output client.LogPage `json:"output"`
			}{role, id, page})
		}
		for _, entry := range page.Logs {
			if _, err := fmt.Fprintf(stdout, "[%s %s] %s\n", role, id, entry.Output); err != nil {
				return err
			}
		}
		return nil
	}})
	if options.Output == outputJSON {
		if writeErr := writeJSON(stdout, result); writeErr != nil {
			return reportFailure(ctx, "dbl rendezvous: receipt", stderr, writeErr)
		}
	} else {
		if _, writeErr := fmt.Fprintf(stdout, "server=%s cleanup=%s\nclient=%s cleanup=%s\n", result.Server.ID, result.Server.Cleanup, result.Client.ID, result.Client.Cleanup); writeErr != nil {
			return reportFailure(ctx, "dbl rendezvous: receipt", stderr, writeErr)
		}
	}
	if err != nil {
		return reportFailure(ctx, "dbl rendezvous", stderr, err)
	}
	return exitOK
}

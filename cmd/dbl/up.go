package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/netsec-ethz/debuglet/internal/demo"
)

const upUsage = `Usage:
  dbl [--timeout DURATION] [--output human|json] up [--state-dir DIR] [--port 9000]

Start a persistent local development environment in the foreground.
State defaults to $XDG_STATE_HOME/debuglet or ~/.local/state/debuglet.
Startup is bounded to 30 seconds. Press Ctrl-C to stop and retain results.
Use --port 0 to let the operating system choose an available HTTP port.
`

type upDependencies struct {
	executable func() (string, error)
	resolve    func(string) (demo.Assets, error)
	up         func(context.Context, demo.Assets, demo.LocalOptions) error
}

func upCommand(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer) int {
	return upCommandWith(ctx, args, options, stdout, stderr, upDependencies{
		executable: os.Executable, resolve: demo.ResolveAssets, up: demo.Up,
	})
}

func upCommandWith(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer, deps upDependencies) int {
	fs := newCommandFlagSet("up")
	var local demo.LocalOptions
	fs.StringVar(&local.StateDir, "state-dir", "", "directory retaining local databases and executor identity")
	fs.IntVar(&local.Port, "port", 9000, "loopback HTTP port (0 selects an available port)")
	if code, ok := parseCommandFlags(fs, args, upUsage, stdout, stderr); !ok {
		return code
	}
	if fs.NArg() != 0 || options.EndpointSet {
		return usageError("dbl up", upUsage, stderr, "up accepts no positional arguments or explicit endpoint")
	}
	if local.Port < 0 || local.Port > 65535 {
		return usageError("dbl up", upUsage, stderr, "--port must be between 0 and 65535")
	}
	blankState := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "state-dir" && strings.TrimSpace(local.StateDir) == "" {
			blankState = true
		}
	})
	if blankState {
		return usageError("dbl up", upUsage, stderr, "--state-dir must not be blank")
	}
	exe, err := deps.executable()
	if err != nil {
		return reportFailure(ctx, "dbl up", stderr, err)
	}
	assets, err := deps.resolve(exe)
	if err != nil {
		return reportFailure(ctx, "dbl up", stderr, err)
	}
	local.Ready = func(record demo.LocalEnvironment) error {
		if options.Output == outputJSON {
			return writeJSON(stdout, record)
		}
		_, err := fmt.Fprintf(stdout, "Debuglet is ready at %s\nExecutor: %s\nState: %s\n\nIn a second terminal:\n  dbl --endpoint %s nodes\n  dbl --endpoint %s run --sample hello --executor auto --wait\n\nPress Ctrl-C to stop; databases and results will be retained.\n", record.Endpoint, record.ExecutorID, record.StateDir, record.Endpoint, record.Endpoint)
		return err
	}
	if err := deps.up(ctx, assets, local); err != nil {
		return reportFailure(ctx, "dbl up", stderr, err)
	}
	return exitOK
}

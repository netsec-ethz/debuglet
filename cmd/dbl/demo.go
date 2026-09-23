package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/netsec-ethz/debuglet/internal/demo"
)

const demoUsage = "Usage:\n  dbl [--timeout 60s] [--output human|json] demo\n"

type demoDependencies struct {
	executable func() (string, error)
	resolve    func(string) (demo.Assets, error)
	run        func(context.Context, demo.Assets) (demo.Result, error)
}

func runDemo(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer) int {
	return runDemoWith(ctx, args, options, stdout, stderr, demoDependencies{
		executable: os.Executable, resolve: demo.ResolveAssets, run: demo.Run,
	})
}

func runDemoWith(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer, deps demoDependencies) int {
	fs := newCommandFlagSet("demo")
	if code, ok := parseCommandFlags(fs, args, demoUsage, stdout, stderr); !ok {
		return code
	}
	if fs.NArg() != 0 || options.EndpointSet {
		return usageError("dbl demo", demoUsage, stderr, "demo accepts no arguments or explicit endpoint")
	}
	exe, err := deps.executable()
	if err != nil {
		return reportFailure(ctx, "dbl demo", stderr, err)
	}
	assets, err := deps.resolve(exe)
	if err != nil {
		return reportFailure(ctx, "dbl demo", stderr, err)
	}
	result, err := deps.run(ctx, assets)
	if err != nil {
		return reportFailure(ctx, "dbl demo", stderr, err)
	}
	return emitReported(ctx, "dbl demo", options.Output, stdout, stderr, result, func(w io.Writer) error {
		_, err := fmt.Fprintf(w, "Debuglet %s completed locally: %s\nExecutor: %s\nRun: %s\nCleanup: %s\n", result.Version, result.Response, result.ExecutorID, result.RunID, result.Cleanup)
		return err
	})
}

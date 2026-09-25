package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/netsec-ethz/debuglet/internal/connections"
	"github.com/netsec-ethz/debuglet/internal/demo"
)

const dispatcherUpUsage = `Usage:
  dbl [--config FILE] dispatcher up [--name local] [--port 9000] [--grpc-port 9001] [--state-dir DIR]

Start a local dispatcher and save its connection. Keep this terminal open.
State, database and configuration are managed automatically. Ctrl-C stops only
this dispatcher and retains results. Use port 0 to select an available port.
`

const executorUpUsage = `Usage:
  dbl [--config FILE] executor up [--name worker] [--dispatcher NAME|URL] [--state-dir DIR]

Start an executor on the selected local dispatcher. State, database and identity
are managed automatically. Ctrl-C stops only this executor. The selected server
must publish local connection metadata; no internal port configuration is needed.
`

type roleUpDependencies struct {
	executable func() (string, error)
	resolve    func(string) (demo.Assets, error)
	start      func(context.Context, demo.Assets, demo.RoleOptions) error
}

func dispatcherUpCommand(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer) int {
	return roleUpCommand(ctx, args, options, stdout, stderr, true, roleUpDependencies{os.Executable, demo.ResolveAssets, demo.DispatcherUp})
}

func executorUpCommand(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer) int {
	return roleUpCommand(ctx, args, options, stdout, stderr, false, roleUpDependencies{os.Executable, demo.ResolveAssets, demo.ExecutorUp})
}

func roleUpCommand(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer, dispatcher bool, deps roleUpDependencies) int {
	name, usage, defaultName := "dbl executor up", executorUpUsage, "worker"
	if dispatcher {
		name, usage, defaultName = "dbl dispatcher up", dispatcherUpUsage, "local"
	}
	fs := newCommandFlagSet(name)
	var local demo.RoleOptions
	var selected string
	fs.StringVar(&local.Name, "name", defaultName, "name for this local service")
	fs.StringVar(&local.StateDir, "state-dir", "", "override the automatically managed state directory")
	if dispatcher {
		fs.IntVar(&local.Port, "port", 9000, "loopback HTTP port (0 chooses an available port)")
		fs.IntVar(&local.GRPCPort, "grpc-port", 9001, "loopback control port (0 chooses an available port)")
	} else {
		fs.StringVar(&selected, "dispatcher", "", "saved dispatcher name or literal-loopback HTTP URL")
	}
	if code, ok := parseCommandFlags(fs, args, usage, stdout, stderr); !ok {
		return code
	}
	if fs.NArg() != 0 {
		return usageError(name, usage, stderr, "unexpected positional arguments")
	}
	if err := connections.ValidateName(local.Name); err != nil {
		return usageError(name, usage, stderr, "%v", err)
	}
	if local.Port < 0 || local.Port > 65535 || local.GRPCPort < 0 || local.GRPCPort > 65535 {
		return usageError(name, usage, stderr, "ports must be between 0 and 65535")
	}
	blank := false
	fs.Visit(func(f *flag.Flag) {
		if (f.Name == "state-dir" || f.Name == "dispatcher") && strings.TrimSpace(f.Value.String()) == "" {
			blank = true
		}
	})
	if blank {
		return usageError(name, usage, stderr, "explicit state directory and dispatcher values must not be blank")
	}
	if dispatcher && (options.EndpointSet || options.Dispatcher != "") {
		return usageError(name, usage, stderr, "dispatcher up creates a connection; do not supply --endpoint or global --dispatcher")
	}
	if !dispatcher && selected != "" && (options.EndpointSet || options.Dispatcher != "") {
		return usageError(name, usage, stderr, "cannot combine executor --dispatcher with global --endpoint or --dispatcher")
	}
	if !dispatcher {
		profile, err := roleDispatcher(options, selected)
		if err != nil {
			return usageError(name, usage, stderr, "%v", err)
		}
		local.Dispatcher = profile
	}
	exe, err := deps.executable()
	if err != nil {
		return reportFailure(ctx, name, stderr, err)
	}
	assets, err := deps.resolve(exe)
	if err != nil {
		return reportFailure(ctx, name, stderr, err)
	}
	local.Ready = func(record demo.RoleEnvironment) error {
		if dispatcher {
			profile := connections.Profile{Name: local.Name, Endpoint: record.Endpoint, GRPCAddress: record.GRPCAddress, YamuxAddress: record.YamuxAddress}
			if err := connections.Save(options.ConfigPath, profile, false); err != nil {
				return fmt.Errorf("save dispatcher connection: %w", err)
			}
		}
		if options.Output == outputJSON {
			return writeJSON(stdout, record)
		}
		prefix := "dbl"
		if options.ConfigPath != "" {
			prefix += " --config " + roleShellWord(options.ConfigPath)
		}
		if dispatcher {
			_, err := fmt.Fprintf(stdout, "Dispatcher %s is ready at %s.\n\nIn another terminal, start an executor:\n  %s executor up --dispatcher %s\n\nThen submit a measurement:\n  %s --dispatcher %s run --sample hello --wait\n\nKeep this terminal open; Ctrl-C stops the dispatcher and retains results.\n", record.Name, record.Endpoint, prefix, roleShellWord(record.Name), prefix, roleShellWord(record.Name))
			return err
		}
		_, err := fmt.Fprintf(stdout, "Executor %s is ready on %s.\nExecutor ID: %s\n\nIn another terminal:\n  %s connect %s\n  %s run --sample hello --wait\n\nKeep this terminal open; Ctrl-C stops only this executor.\n", record.Name, record.Endpoint, record.ExecutorID, prefix, roleShellWord(record.Endpoint), prefix)
		return err
	}
	if err := deps.start(ctx, assets, local); err != nil {
		return reportFailure(ctx, name, stderr, err)
	}
	return exitOK
}

func roleDispatcher(options globalOptions, selected string) (connections.Profile, error) {
	if selected != "" {
		if strings.Contains(selected, "://") {
			return connections.Profile{Endpoint: selected}, nil
		}
		return connections.Resolve(options.ConfigPath, selected)
	}
	if options.Dispatcher != "" {
		return connections.Resolve(options.ConfigPath, options.Dispatcher)
	}
	if options.EndpointSet {
		return connections.Profile{Endpoint: options.Endpoint}, nil
	}
	cfg, err := connections.Load(options.ConfigPath)
	if err != nil {
		return connections.Profile{}, err
	}
	if cfg.Current != "" {
		return connections.Resolve(options.ConfigPath, "")
	}
	return connections.Profile{Endpoint: defaultEndpoint}, nil
}

func roleShellWord(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

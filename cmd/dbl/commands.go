package main

import (
	"context"
	"fmt"
	"io"
	"time"
)

// Exit codes shared by every command. A command "completes" when its request
// finished and its output was written; a submission receipt, a cancellation
// acknowledgement or a status/log query completes without implying workload
// success.
const (
	exitOK             = 0   // command completed
	exitFailure        = 1   // transport, API, protocol or local I/O failure
	exitUsage          = 2   // usage or validation error
	exitWorkloadFailed = 3   // run --wait observed a terminal workload failure
	exitDeadline       = 124 // client deadline exceeded
	exitInterrupted    = 130 // user interruption
)

// defaultEndpoint is used when --endpoint is not given.
const defaultEndpoint = "http://127.0.0.1:9000"

// globalOptions are the options parsed before the command name. EndpointSet
// and TimeoutSet record whether the flag was given explicitly (FlagSet.Visit),
// so later commands can distinguish a default from an operator choice.
type globalOptions struct {
	Endpoint    string
	Dispatcher  string
	ConfigPath  string
	Timeout     time.Duration
	Output      string
	EndpointSet bool
	TimeoutSet  bool
}

// defaultCommandTimeout returns the default whole-command timeout for a
// command when --timeout is not given. The command is parsed before this is
// consulted so commands such as demo can select their own default.
func defaultCommandTimeout(command string, args ...string) time.Duration {
	if (command == "dispatcher" || command == "executor") && len(args) > 0 && args[0] == "up" {
		return 0
	}
	switch command {
	case "up":
		return 0 // Foreground lifetime; startup has a separate bound.
	case "service", "drain":
		// A managed operation waits for a service manager and for local
		// work to join, both of which are bounded in seconds, not requests.
		return 5 * time.Minute
	case "demo":
		return 60 * time.Second
	default:
		return 30 * time.Second
	}
}

// dispatch runs one command with its already-parsed global options and the
// remaining arguments. ctx is already bounded by the command timeout. Unknown
// commands are usage errors.
func dispatch(ctx context.Context, command string, args []string, options globalOptions, stdout, stderr io.Writer) int {
	switch command {
	case "connect":
		return connectCommand(ctx, args, options, stdout, stderr)
	case "login":
		return loginCommand(ctx, args, options, stdout, stderr)
	case "logout":
		return logoutCommand(ctx, args, options, stdout, stderr)
	case "dispatcher":
		return dispatcherCommand(ctx, args, options, stdout, stderr)
	case "dispatchers":
		return dispatcherCommand(ctx, append([]string{"list"}, args...), options, stdout, stderr)
	case "executor":
		return executorCommand(ctx, args, options, stdout, stderr)
	case "executors":
		return nodesCommand(ctx, args, options, stdout, stderr)
	case "up":
		return upCommand(ctx, args, options, stdout, stderr)
	case "service":
		return serviceCommand(ctx, args, options, stdout, stderr)
	case "drain":
		return drainCommand(ctx, args, options, stdout, stderr)
	case "demo":
		return runDemo(ctx, args, options, stdout, stderr)
	case "nodes":
		return nodesCommand(ctx, args, options, stdout, stderr)
	case "validate":
		return validateCommand(ctx, args, options, stdout, stderr)
	case "run":
		return runCommand(ctx, args, options, stdout, stderr)
	case "status":
		return statusCommand(ctx, args, options, stdout, stderr)
	case "logs":
		return logsCommand(ctx, args, options, stdout, stderr)
	case "cancel":
		return cancelCommand(ctx, args, options, stdout, stderr)
	case "version":
		return versionCommand(ctx, args, options, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "dbl: unknown command %q\n", command)
		return exitUsage
	}
}

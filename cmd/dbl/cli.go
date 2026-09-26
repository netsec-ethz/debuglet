package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/internal/connections"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

// Output modes accepted by --output.
const (
	outputHuman = "human"
	outputJSON  = "json"
)

// pollInterval is the context-aware pause between state or log polls for
// `run --wait` and `logs --follow`. It is a variable only so package tests can
// shorten it; it is not a configuration surface.
var pollInterval = 250 * time.Millisecond

// newClient is the single seam through which commands construct the SDK
// client. Tests may replace it to observe the options a command passes; the
// endpoint itself is selected with --endpoint.
var newClient = client.New

const usageText = `Usage:
  dbl [--endpoint URL | --dispatcher NAME] [--config FILE] [--timeout 30s]
      [--output human|json] COMMAND ...

Commands:
  demo                                  run an installed local measurement
  up [--state-dir DIR] [--port 9000]      keep a local environment running
  service install|start|stop|status|uninstall --role ROLE [--name NAME]
                                        manage an installed role as a service
  drain --role ROLE [--name NAME] [--resume]
                                        take a managed role out of service
  dispatcher up|list|use|remove          start or manage saved dispatchers
  executor up|list                       start an executor or list registered ones
  connect URL [--name NAME]              save and select a dispatcher connection
  login [--account-key-file FILE] [--register NAME]
                                        obtain and store a session credential
  logout                                revoke and forget the stored credential
  nodes                                 list registered executors
  validate (--wasm FILE | --sample hello) [--executor ID|auto] [--allow ADDRESS ...]
      [--duration 10s] [--floor-bps 1048576] [--ceil-bps 1048576]
                                        validate one workload locally
  run (--wasm FILE | --sample hello) [--executor ID|auto] [--allow ADDRESS ...]
      [--duration 10s] [--floor-bps 1048576] [--ceil-bps 1048576]
      [--wait] [--allow-remote-test] [-- guest arguments ...]
                                        submit one TEST-funded debuglet
  status ID                             report a debuglet's state
  logs [--after N] [--limit N] [--follow] ID
                                        read stored guest output
  cancel ID                             ask the dispatcher to abort a debuglet
  version [--server]                    print client (and server) version

Global options must precede the command; command options precede positionals.
Use "dbl COMMAND --help" for a command's options.
`

// run is the whole of main() apart from signal handling: it parses the global
// options, applies the command's default timeout unless --timeout was given,
// and dispatches under the resulting context.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	var options globalOptions
	fs := flag.NewFlagSet("dbl", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&options.Endpoint, "endpoint", defaultEndpoint, "dispatcher base URL")
	fs.StringVar(&options.Dispatcher, "dispatcher", "", "saved dispatcher name")
	fs.StringVar(&options.ConfigPath, "config", "", "client connections file")
	fs.DurationVar(&options.Timeout, "timeout", 0, "whole-command timeout (default depends on the command)")
	fs.StringVar(&options.Output, "output", outputHuman, "output mode: human or json")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, usageText)
			return exitOK
		}
		fmt.Fprintf(stderr, "dbl: %v\n", err)
		fmt.Fprint(stderr, usageText)
		return exitUsage
	}
	var dispatcherSet, configSet bool
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "endpoint":
			options.EndpointSet = true
		case "timeout":
			options.TimeoutSet = true
		case "dispatcher":
			dispatcherSet = true
		case "config":
			configSet = true
		}
	})
	if fs.NArg() == 0 {
		fmt.Fprintln(stderr, "dbl: missing command")
		fmt.Fprint(stderr, usageText)
		return exitUsage
	}
	command := fs.Arg(0)
	commandArgs := fs.Args()[1:]

	if !options.TimeoutSet {
		options.Timeout = defaultCommandTimeout(command, commandArgs...)
	}
	switch {
	case options.Output != outputHuman && options.Output != outputJSON:
		fmt.Fprintf(stderr, "dbl: invalid --output %q: want human or json\n", options.Output)
		return exitUsage
	case options.Timeout <= 0 && (options.TimeoutSet || defaultCommandTimeout(command, commandArgs...) != 0):
		fmt.Fprintf(stderr, "dbl: invalid --timeout %s: must be positive\n", options.Timeout)
		return exitUsage
	case strings.TrimSpace(options.Endpoint) == "":
		fmt.Fprintln(stderr, "dbl: --endpoint must not be blank")
		return exitUsage
	case options.EndpointSet && dispatcherSet:
		fmt.Fprintln(stderr, "dbl: --endpoint and --dispatcher cannot be used together")
		return exitUsage
	case dispatcherSet && strings.TrimSpace(options.Dispatcher) == "":
		fmt.Fprintln(stderr, "dbl: --dispatcher must not be blank")
		return exitUsage
	case configSet && strings.TrimSpace(options.ConfigPath) == "":
		fmt.Fprintln(stderr, "dbl: --config must not be blank")
		return exitUsage
	}
	if dispatcherSet {
		if err := connections.ValidateName(options.Dispatcher); err != nil {
			fmt.Fprintf(stderr, "dbl: --dispatcher: %v\n", err)
			return exitUsage
		}
	}

	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}
	return dispatch(ctx, command, commandArgs, options, stdout, stderr)
}

// newCommandFlagSet returns a FlagSet whose own diagnostics are suppressed;
// commands print their errors and usage themselves so stdout stays clean.
func newCommandFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("dbl "+name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// parseCommandFlags reports help (exit 0, usage on stdout) or a usage error
// (exit 2, error and usage on stderr). ok is true when the command continues.
func parseCommandFlags(fs *flag.FlagSet, args []string, usage string, stdout, stderr io.Writer) (code int, ok bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, usage)
			return exitOK, false
		}
		return usageError(fs.Name(), usage, stderr, "%v", err), false
	}
	return exitOK, true
}

// usageError prints a validation message plus the command usage to stderr
// and returns exitUsage.
func usageError(name, usage string, stderr io.Writer, format string, args ...any) int {
	fmt.Fprintf(stderr, "%s: %s\n", name, fmt.Sprintf(format, args...))
	fmt.Fprint(stderr, usage)
	return exitUsage
}

// failureExit maps a failed request or wait to the exit code the contract
// prescribes, classified by the command context alone: its expired deadline
// yields 124, a cancellation of the parent context (a signal) yields 130 and
// everything else is a transport, API, protocol or local I/O failure.
func failureExit(ctx context.Context) int {
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return exitDeadline
	case errors.Is(ctx.Err(), context.Canceled):
		return exitInterrupted
	}
	return exitFailure
}

// reportFailure writes the SDK's diagnostic to stderr and returns its exit
// code. SDK errors redact recognized credential fields and known submission
// keys; arbitrary server text is subject to the documented diagnostic limits.
func reportFailure(ctx context.Context, name string, stderr io.Writer, err error) int {
	code := failureExit(ctx)
	switch code {
	case exitDeadline:
		fmt.Fprintf(stderr, "%s: command timed out: %v\n", name, err)
	case exitInterrupted:
		fmt.Fprintf(stderr, "%s: interrupted: %v\n", name, err)
	default:
		fmt.Fprintf(stderr, "%s: %v\n", name, err)
		// An authentication failure has one action behind it, and the
		// dispatcher deliberately does not say which credential state it
		// was, so the client names the action instead.
		if authenticationRequired(err) {
			fmt.Fprintf(stderr, "%s: this dispatcher requires a valid credential; run dbl login\n", name)
		}
	}
	return code
}

// connect builds the SDK client for a command. Its per-request timeout is the
// whole-command timeout, which the command context already enforces, and
// client.New only validates the operator's endpoint, so its failure is a usage
// error rather than a transport one.
func connect(name string, options globalOptions, allowRemoteTEST bool, stderr io.Writer) (*client.Client, int, bool) {
	c, _, code, ok := connectProfile(name, options, allowRemoteTEST, stderr)
	return c, code, ok
}

// connectProfile is connect plus the saved profile it selected, for the
// commands that have to record or forget that profile's credential.
func connectProfile(name string, options globalOptions, allowRemoteTEST bool, stderr io.Writer) (*client.Client, connections.Profile, int, bool) {
	profile, err := selectedProfile(options)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", name, err)
		return nil, profile, exitFailure, false
	}
	// The credential store is consulted only for a saved connection, and only
	// for the endpoint that connection recorded; a mismatch is reported
	// instead of being sent. An explicit --endpoint selects no saved
	// connection, so nothing is read and the client configuration directory is
	// never located: dbl version --server against an explicit endpoint works
	// where there is no configuration directory at all.
	credential, err := connections.CredentialFor(options.ConfigPath, profile.Name, profile.Endpoint)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", name, err)
		return nil, profile, exitFailure, false
	}
	c, err := newClient(profile.Endpoint, client.Options{
		RequestTimeout:  options.Timeout,
		AllowRemoteTEST: allowRemoteTEST,
		Credential:      credential.Token,
	})
	if err != nil {
		fmt.Fprintf(stderr, "%s: --endpoint: %v\n", name, err)
		return nil, profile, exitUsage, false
	}
	return c, profile, exitOK, true
}

// connectProfileWithoutCredential builds a client for credential-establishing
// operations. Login must work when a profile has moved to another endpoint, so
// it deliberately does not read or present the session issued by the old one.
func connectProfileWithoutCredential(name string, options globalOptions, stderr io.Writer) (*client.Client, connections.Profile, int, bool) {
	profile, err := selectedProfile(options)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", name, err)
		return nil, profile, exitFailure, false
	}
	c, err := newClient(profile.Endpoint, client.Options{RequestTimeout: options.Timeout})
	if err != nil {
		fmt.Fprintf(stderr, "%s: --endpoint: %v\n", name, err)
		return nil, profile, exitUsage, false
	}
	return c, profile, exitOK, true
}

// Selection is lazy: local commands and explicit endpoints never read the
// user's configuration. A profile without a name is an endpoint the operator
// named directly, which belongs to no saved connection.
func selectedProfile(options globalOptions) (connections.Profile, error) {
	if options.EndpointSet {
		return connections.Profile{Endpoint: options.Endpoint}, nil
	}
	if options.Dispatcher != "" {
		return connections.Resolve(options.ConfigPath, options.Dispatcher)
	}
	cfg, err := connections.Load(options.ConfigPath)
	if err != nil {
		return connections.Profile{}, err
	}
	for _, profile := range cfg.Dispatchers {
		if profile.Name == cfg.Current {
			return profile, nil
		}
	}
	if options.Endpoint != "" {
		return connections.Profile{Endpoint: options.Endpoint}, nil
	}
	return connections.Profile{Endpoint: defaultEndpoint}, nil
}

// writeJSON writes exactly one JSON document followed by a newline.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// render writes a command's single result document in the selected output
// mode: the value as JSON, or whatever human writes.
func render(output string, stdout io.Writer, value any, human func(io.Writer) error) error {
	if output == outputJSON {
		return writeJSON(stdout, value)
	}
	return human(stdout)
}

// emit renders the result and turns a write failure into a local I/O failure.
func emit(name, output string, stdout, stderr io.Writer, value any, human func(io.Writer) error) int {
	if err := render(output, stdout, value, human); err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", name, err)
		return exitFailure
	}
	return exitOK
}

// emitReported is emit for the commands whose write failure is classified by
// the command context, so an expired deadline still yields 124.
func emitReported(ctx context.Context, name, output string, stdout, stderr io.Writer, value any, human func(io.Writer) error) int {
	if err := render(output, stdout, value, human); err != nil {
		return reportFailure(ctx, name, stderr, err)
	}
	return exitOK
}

// sleepContext pauses for d or until ctx is done, returning ctx.Err() in the
// latter case.
func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// validateJobID checks the lowercase canonical 36-character UUID spelling the
// dispatcher accepts and rejects the nil UUID, before the ID is ever placed in
// a URL.
func validateJobID(id string) error {
	if !uuidPattern.MatchString(id) {
		return fmt.Errorf("invalid debuglet ID %q: want a lowercase canonical UUID", id)
	}
	if strings.Trim(id, "0-") == "" {
		return fmt.Errorf("invalid debuglet ID %q: the nil UUID is not a job", id)
	}
	return nil
}

// singleID returns the one positional ID a command takes or a usage message.
func singleID(fs *flag.FlagSet) (string, string) {
	switch fs.NArg() {
	case 0:
		return "", "missing debuglet ID"
	case 1:
		if err := validateJobID(fs.Arg(0)); err != nil {
			return "", err.Error()
		}
		return fs.Arg(0), ""
	default:
		return "", fmt.Sprintf("unexpected extra arguments %q", fs.Args()[1:])
	}
}

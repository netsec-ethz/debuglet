package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/internal/demo"
	"github.com/netsec-ethz/debuglet/internal/ids"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

// maxWasmBytes bounds the raw guest file read by `run`. The SDK applies its
// own, larger bound on the whole encoded envelope afterwards.
const maxWasmBytes = 24 << 20

// Receipt states emitted by `run` besides the dispatcher's own state strings.
const (
	stateSubmitted         = "submitted"
	stateSubmissionFailed  = "submission_failed"
	stateSubmissionUnknown = "submission_unknown"
)

const runUsage = `Usage:
  dbl run (--wasm FILE | --sample hello) [--executor ID|auto] [--allow ADDRESS ...] \
      [--duration 10s] [--floor-bps 1048576] [--ceil-bps 1048576] \
      [--wait] [--allow-remote-test] [-- guest arguments ...]

Options:
  --wasm FILE            regular guest WASM file (at most 24 MiB)
  --sample hello         use the hello guest bundled with the full installation
  --executor ID|auto     executor ID (default: auto selects the sole ready executor)
  --protocol NAME        required tcp/tls/udp/icmp/scion support; repeatable
  --enforcement MODE     actual packet counter: ebpf or fallback
  --min-capacity-bps N    minimum advertised total bandwidth (not a reservation)
  --allow ADDRESS        allowed destination address; repeatable
  --duration 10s         server-side run budget, whole milliseconds, >= 1ms
  --floor-bps N          bandwidth floor in bits per second (>= 0)
  --ceil-bps N           bandwidth ceiling in bits per second (>= floor)
  --wait                 poll until the debuglet exits; exit 3 on failure
  --allow-remote-test    permit a TEST submission to a non-loopback endpoint
  -- ARGS...             everything after -- is passed to the guest verbatim
`

// receipt is the single stdout document of `run`. Unknown IDs are omitted;
// an ID is never invented.
type receipt struct {
	Retry         *client.RetryLink `json:"retry,omitempty"`
	ID            string            `json:"id,omitempty"`
	TransactionID string            `json:"transaction_id,omitempty"`
	ExecutorID    string            `json:"executor_id"`
	State         string            `json:"state"`
	Error         string            `json:"error,omitempty"`
}

// write emits the receipt once in the selected output mode.
func (r receipt) write(w io.Writer, output string) error {
	if output == outputJSON {
		return writeJSON(w, r)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "state: %s\n", r.State)
	if r.Retry != nil {
		fmt.Fprintf(&b, "parent_run_id: %s\nrequest_id: %s\n", r.Retry.ParentRunID, r.Retry.RequestID)
	}
	if r.ID != "" {
		fmt.Fprintf(&b, "id: %s\n", r.ID)
	}
	if r.TransactionID != "" {
		fmt.Fprintf(&b, "transaction_id: %s\n", r.TransactionID)
	}
	fmt.Fprintf(&b, "executor_id: %s\n", r.ExecutorID)
	if r.Error != "" {
		fmt.Fprintf(&b, "error: %s\n", r.Error)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// runOptions are the validated inputs of one `run` invocation.
type runOptions struct {
	retry           *client.RetryLink
	wasmPath        string
	sample          string
	executor        string
	filter          client.ExecutorFilter
	allow           stringList
	duration        time.Duration
	floorBPS        int64
	ceilBPS         int64
	wait            bool
	allowRemoteTEST bool
	guestArgs       []string
}

// splitGuestArgs separates command arguments from guest arguments at the
// first "--". The separator is never consumed as a flag value, so a flag
// missing its value before "--" is a usage error rather than a mis-parse.
func splitGuestArgs(args []string) (flags, guest []string) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

// parseRunOptions parses and validates every option before any file read or
// request. A nonempty message is a usage error.
func parseRunOptions(args []string, stdout, stderr io.Writer) (runOptions, int, bool) {
	return parseSubmissionOptions(args, "", stdout, stderr)
}

func parseSubmissionOptions(args []string, parentID string, stdout, stderr io.Writer) (runOptions, int, bool) {
	var o runOptions
	var requestID string
	command, usage := "run", runUsage
	if parentID != "" {
		command, usage = "retry", retryUsage
	}
	fs := newCommandFlagSet(command)
	if parentID != "" {
		fs.StringVar(&requestID, "request-id", "", "")
	}
	capabilityFlags(fs, &o.filter)
	fs.StringVar(&o.wasmPath, "wasm", "", "")
	fs.StringVar(&o.sample, "sample", "", "")
	fs.StringVar(&o.executor, "executor", "auto", "")
	fs.Var(&o.allow, "allow", "")
	fs.DurationVar(&o.duration, "duration", 10*time.Second, "")
	fs.Int64Var(&o.floorBPS, "floor-bps", 1048576, "")
	fs.Int64Var(&o.ceilBPS, "ceil-bps", 1048576, "")
	fs.BoolVar(&o.wait, "wait", false, "")
	fs.BoolVar(&o.allowRemoteTEST, "allow-remote-test", false, "")

	flagArgs, guest := splitGuestArgs(args)
	if code, ok := parseCommandFlags(fs, flagArgs, usage, stdout, stderr); !ok {
		return o, code, false
	}
	if err := o.filter.Validate(); err != nil {
		return o, usageError("dbl "+command, usage, stderr, "%v", err), false
	}
	o.guestArgs = guest
	fail := func(format string, a ...any) (runOptions, int, bool) {
		return o, usageError("dbl "+command, usage, stderr, format, a...), false
	}
	switch {
	case fs.NArg() > 0:
		return fail("unexpected positional argument %q: guest arguments must follow --", fs.Arg(0))
	case o.sample != "" && o.sample != "hello":
		return fail("--sample must be hello")
	case o.sample != "" && o.wasmPath != "":
		return fail("--sample and --wasm cannot be used together")
	case o.sample == "" && strings.TrimSpace(o.wasmPath) == "":
		return fail("--wasm or --sample hello is required")
	case strings.TrimSpace(o.executor) == "":
		return fail("--executor is required")
	case o.duration < time.Millisecond:
		return fail("--duration %s is below the 1ms minimum", o.duration)
	case o.duration%time.Millisecond != 0:
		return fail("--duration %s is not a whole number of milliseconds", o.duration)
	case o.floorBPS < 0:
		return fail("--floor-bps %d must not be negative", o.floorBPS)
	case o.ceilBPS < 0:
		return fail("--ceil-bps %d must not be negative", o.ceilBPS)
	case o.floorBPS > o.ceilBPS:
		return fail("--floor-bps %d exceeds --ceil-bps %d", o.floorBPS, o.ceilBPS)
	}
	for _, a := range o.allow {
		if strings.TrimSpace(a) == "" {
			return fail("--allow must not be blank")
		}
	}
	if parentID != "" {
		if _, ok := ids.ParseCanonical(parentID); !ok {
			return fail("parent must be a canonical nonzero UUID")
		}
		if _, ok := ids.ParseCanonical(requestID); !ok {
			return fail("--request-id must be a fixed canonical nonzero UUID")
		}
		if o.executor == "auto" || !o.filter.Empty() {
			return fail("retry requires --executor ID without discovery filters")
		}
		o.retry = &client.RetryLink{ParentRunID: parentID, RequestID: requestID}
	}
	return o, exitOK, true
}

// readWasm accepts regular files, including symlinks to regular files. Check
// before opening to reject FIFOs without waiting for a writer, then recheck
// the opened file. Filesystem operations remain synchronous: these checks
// do not bound a stalled filesystem or a hostile path replacement race.
// The limited reader also catches a file growing beyond its reported size.
func readWasm(path string) ([]byte, error) {
	checkFile := func(info os.FileInfo) error {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file", path)
		}
		if info.Size() > maxWasmBytes {
			return fmt.Errorf("%s is %d bytes; the limit is %d bytes (24 MiB)", path, info.Size(), maxWasmBytes)
		}
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if err := checkFile(info); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return nil, err
	}
	if err := checkFile(info); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxWasmBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > maxWasmBytes {
		return nil, fmt.Errorf("%s exceeds the limit of %d bytes (24 MiB)", path, maxWasmBytes)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%s is empty", path)
	}
	return data, nil
}

func runCommand(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer) int {
	o, code, ok := parseRunOptions(args, stdout, stderr)
	if !ok {
		return code
	}
	return executeSubmission(ctx, o, options, stdout, stderr)
}

func executeSubmission(ctx context.Context, o runOptions, options globalOptions, stdout, stderr io.Writer) int {
	command, usage := "dbl run", runUsage
	if o.retry != nil {
		command, usage = "dbl retry", retryUsage
	}
	wasmPath := o.wasmPath
	if o.sample != "" {
		executable, err := os.Executable()
		if err != nil {
			return reportFailure(ctx, command+": locate installed sample", stderr, err)
		}
		assets, err := demo.ResolveAssets(executable)
		if err != nil {
			return reportFailure(ctx, command+": --sample requires the full installed package", stderr, err)
		}
		wasmPath = filepath.Join(assets.Root, "share", "debuglet", "hello.wasm")
	}
	wasm, err := readWasm(wasmPath)
	if err != nil {
		return usageError(command, usage, stderr, "--wasm: %v", err)
	}
	addresses := []string(o.allow)
	if addresses == nil {
		addresses = []string{}
	}
	c, code, ok := connect(command, options, o.allowRemoteTEST, stderr)
	if !ok {
		return code
	}
	if o.executor == "auto" || !o.filter.Empty() {
		id := o.executor
		if id == "auto" {
			id = ""
		}
		node, err := c.SelectExecutor(ctx, id, o.filter)
		if errors.Is(err, client.ErrNoMatchingExecutor) && id == "" && o.filter.Empty() {
			err = errNoReadyExecutor
		}
		if err != nil {
			return reportFailure(ctx, command+": discover executor", stderr, err)
		}
		o.executor = node.ID
	}
	batch, err := client.Prepare([]client.Request{{
		OrderID:    0,
		ExecutorID: o.executor,
		Args:       o.guestArgs,
		Wasm:       wasm,
		Policy: client.Policy{
			FloorBW:     o.floorBPS,
			CeilBW:      o.ceilBPS,
			TimeoutMS:   int64(o.duration / time.Millisecond),
			Addresses:   addresses,
			RequireICMP: slices.Contains(o.filter.Protocols, "icmp"),
		},
	}})
	if err != nil {
		return usageError(command, usage, stderr, "invalid request: %v", err)
	}
	var submission client.Submission
	if o.retry == nil {
		submission, err = c.SubmitTEST(ctx, batch)
	} else {
		submission, err = c.RetryTEST(ctx, o.retry.ParentRunID, o.retry.RequestID, batch)
	}
	if err != nil {
		if o.retry != nil {
			r := receipt{ExecutorID: o.executor, Retry: o.retry, State: stateSubmissionFailed}
			var subErr *client.SubmissionError
			if errors.As(err, &subErr) {
				r.TransactionID = subErr.TransactionID
				if subErr.OutcomeUnknown {
					r.State = stateSubmissionUnknown
				}
			}
			if werr := r.write(stdout, options.Output); werr != nil {
				fmt.Fprintf(stderr, "dbl retry: write receipt: %v\n", werr)
			}
			return reportFailure(ctx, "dbl retry: retain this request ID and unchanged request to recover the attempt", stderr, err)
		}
		return reportSubmissionFailure(ctx, err, o.executor, options.Output, stdout, stderr)
	}
	r := receipt{ExecutorID: o.executor, TransactionID: submission.TransactionID, State: stateSubmitted, Retry: o.retry}
	if len(submission.IDs) > 0 {
		r.ID = submission.IDs[0]
	}
	if !o.wait {
		if err := r.write(stdout, options.Output); err != nil {
			fmt.Fprintf(stderr, command+": write receipt: %v\n", err)
			return exitFailure
		}
		return exitOK
	}
	if r.ID == "" {
		// Cannot happen with a conforming SDK, which requires one ID per
		// request; without an ID there is nothing to poll.
		_ = r.write(stdout, options.Output)
		fmt.Fprintln(stderr, command+": submission returned no debuglet ID; cannot wait")
		return exitFailure
	}
	code, waitErr := waitForExit(ctx, func(ctx context.Context) (client.State, error) {
		return c.Status(ctx, r.ID)
	}, &r)
	if err := r.write(stdout, options.Output); err != nil {
		fmt.Fprintf(stderr, command+": write receipt: %v\n", err)
		return exitFailure
	}
	switch {
	case waitErr != nil:
		return reportFailure(ctx, command+": submitted; waiting failed", stderr, waitErr)
	case code == exitWorkloadFailed:
		fmt.Fprintf(stderr, command+": debuglet %s failed: %s\n", r.ID, r.Error)
	}
	return code
}

// reportSubmissionFailure emits a receipt only when a transaction is already
// known (a second-step failure), naming its outcome truthfully, and maps the
// exit code from the command context.
func reportSubmissionFailure(ctx context.Context, err error, executor, output string, stdout, stderr io.Writer) int {
	var subErr *client.SubmissionError
	if errors.As(err, &subErr) && subErr.Stage == "submit" && subErr.TransactionID != "" {
		r := receipt{ExecutorID: executor, TransactionID: subErr.TransactionID, State: stateSubmissionFailed}
		if len(subErr.AdmittedIDs) == 1 {
			r.ID = subErr.AdmittedIDs[0]
		}
		if subErr.OutcomeUnknown {
			r.State = stateSubmissionUnknown
		}
		if werr := r.write(stdout, output); werr != nil {
			fmt.Fprintf(stderr, "dbl run: write receipt: %v\n", werr)
		}
	}
	return reportFailure(ctx, "dbl run", stderr, err)
}

// waitForExit polls status every pollInterval until StateExited, keeping r at
// the latest observation even when it returns an error and its
// context-classified exit code. It never sends cancellation.
func waitForExit(ctx context.Context, status func(context.Context) (client.State, error), r *receipt) (int, error) {
	for {
		st, err := status(ctx)
		if err != nil {
			return failureExit(ctx), err
		}
		r.State = st.State
		r.Error = st.Error
		if st.ExecutorID != "" {
			r.ExecutorID = st.ExecutorID
		}
		if st.State == client.StateExited {
			if st.Error == "" {
				return exitOK, nil
			}
			return exitWorkloadFailed, nil
		}
		if err := sleepContext(ctx, pollInterval); err != nil {
			return failureExit(ctx), err
		}
	}
}

// errNoReadyExecutor keeps the first-run hint for an unfiltered selection:
// with no filters, the likely cause is that no executor has started yet.
var errNoReadyExecutor = errors.New("no executor is ready; start one with dbl up or sudo dbl service start --role executor --name NAME, then check dbl nodes (a newly started executor needs a few seconds)")

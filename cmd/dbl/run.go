package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/internal/demo"
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
	ID            string `json:"id,omitempty"`
	TransactionID string `json:"transaction_id,omitempty"`
	ExecutorID    string `json:"executor_id"`
	State         string `json:"state"`
	Error         string `json:"error,omitempty"`
}

// write emits the receipt once in the selected output mode.
func (r receipt) write(w io.Writer, output string) error {
	if output == outputJSON {
		return writeJSON(w, r)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "state: %s\n", r.State)
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
	wasmPath        string
	sample          string
	executor        string
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
	var o runOptions
	fs := newCommandFlagSet("run")
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
	if code, ok := parseCommandFlags(fs, flagArgs, runUsage, stdout, stderr); !ok {
		return o, code, false
	}
	o.guestArgs = guest
	fail := func(format string, a ...any) (runOptions, int, bool) {
		return o, usageError("dbl run", runUsage, stderr, format, a...), false
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
	wasmPath := o.wasmPath
	if o.sample != "" {
		executable, err := os.Executable()
		if err != nil {
			return reportFailure(ctx, "dbl run: locate installed sample", stderr, err)
		}
		assets, err := demo.ResolveAssets(executable)
		if err != nil {
			return reportFailure(ctx, "dbl run: --sample requires the full installed package", stderr, err)
		}
		wasmPath = filepath.Join(assets.Root, "share", "debuglet", "hello.wasm")
	}
	wasm, err := readWasm(wasmPath)
	if err != nil {
		return usageError("dbl run", runUsage, stderr, "--wasm: %v", err)
	}
	addresses := []string(o.allow)
	if addresses == nil {
		addresses = []string{}
	}
	c, code, ok := connect("dbl run", options, o.allowRemoteTEST, stderr)
	if !ok {
		return code
	}
	if o.executor == "auto" {
		nodes, err := c.Nodes(ctx)
		if err != nil {
			return reportFailure(ctx, "dbl run: discover executor", stderr, err)
		}
		o.executor, err = soleReadyExecutor(nodes)
		if err != nil {
			return reportFailure(ctx, "dbl run", stderr, err)
		}
	}
	batch, err := client.Prepare([]client.Request{{
		OrderID:    0,
		ExecutorID: o.executor,
		Args:       o.guestArgs,
		Wasm:       wasm,
		Policy: client.Policy{
			FloorBW:   o.floorBPS,
			CeilBW:    o.ceilBPS,
			TimeoutMS: int64(o.duration / time.Millisecond),
			Addresses: addresses,
		},
	}})
	if err != nil {
		return usageError("dbl run", runUsage, stderr, "invalid request: %v", err)
	}
	submission, err := c.SubmitTEST(ctx, batch)
	if err != nil {
		return reportSubmissionFailure(ctx, err, o.executor, options.Output, stdout, stderr)
	}
	r := receipt{ExecutorID: o.executor, TransactionID: submission.TransactionID, State: stateSubmitted}
	if len(submission.IDs) > 0 {
		r.ID = submission.IDs[0]
	}
	if !o.wait {
		if err := r.write(stdout, options.Output); err != nil {
			fmt.Fprintf(stderr, "dbl run: write receipt: %v\n", err)
			return exitFailure
		}
		return exitOK
	}
	if r.ID == "" {
		// Cannot happen with a conforming SDK, which requires one ID per
		// request; without an ID there is nothing to poll.
		_ = r.write(stdout, options.Output)
		fmt.Fprintln(stderr, "dbl run: submission returned no debuglet ID; cannot wait")
		return exitFailure
	}
	code, waitErr := waitForExit(ctx, func(ctx context.Context) (client.State, error) {
		return c.Status(ctx, r.ID)
	}, &r)
	if err := r.write(stdout, options.Output); err != nil {
		fmt.Fprintf(stderr, "dbl run: write receipt: %v\n", err)
		return exitFailure
	}
	switch {
	case waitErr != nil:
		return reportFailure(ctx, "dbl run: submitted; waiting failed", stderr, waitErr)
	case code == exitWorkloadFailed:
		fmt.Fprintf(stderr, "dbl run: debuglet %s failed: %s\n", r.ID, r.Error)
	}
	return code
}

func soleReadyExecutor(nodes []client.Node) (string, error) {
	var id string
	for _, node := range nodes {
		if !node.Ready || strings.TrimSpace(node.ID) == "" {
			continue
		}
		if id != "" {
			return "", errors.New("more than one executor is ready; use dbl nodes and choose --executor ID")
		}
		id = node.ID
	}
	if id == "" {
		return "", errors.New("no executor is ready; start one with dbl up or sudo dbl service start --role executor --name NAME, then check dbl nodes (a newly started executor needs a few seconds)")
	}
	return id, nil
}

// reportSubmissionFailure emits a receipt only when a transaction is already
// known (a second-step failure), naming its outcome truthfully, and maps the
// exit code from the command context.
func reportSubmissionFailure(ctx context.Context, err error, executor, output string, stdout, stderr io.Writer) int {
	var subErr *client.SubmissionError
	if errors.As(err, &subErr) && subErr.Stage == "submit" && subErr.TransactionID != "" {
		r := receipt{ExecutorID: executor, TransactionID: subErr.TransactionID, State: stateSubmissionFailed}
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

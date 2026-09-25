package main

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/internal/demo"
	"github.com/netsec-ethz/debuglet/pkg/client"

	"github.com/tetratelabs/wazero"
)

const validateUsage = `Usage:
  dbl validate (--wasm FILE | --sample hello) [--executor ID|auto] [--allow ADDRESS ...] \
      [--duration 10s] [--floor-bps 1048576] [--ceil-bps 1048576] [-- guest arguments ...]

Validates the local file, WASM structure, resources, and destination syntax.
It performs no DNS lookup and sends no network request.
`

type validateOptions struct {
	wasmPath  string
	sample    string
	executor  string
	allow     stringList
	duration  string
	floorBPS  string
	ceilBPS   string
	guestArgs []string
}

type validationDiagnostic struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

type validationResult struct {
	Valid        bool                   `json:"valid"`
	Source       string                 `json:"source,omitempty"`
	WasmBytes    int                    `json:"wasm_bytes,omitempty"`
	ExecutorID   string                 `json:"executor_id,omitempty"`
	DurationMS   int64                  `json:"duration_ms,omitempty"`
	FloorBPS     int64                  `json:"floor_bps,omitempty"`
	CeilBPS      int64                  `json:"ceil_bps,omitempty"`
	Destinations []string               `json:"destinations,omitempty"`
	Diagnostics  []validationDiagnostic `json:"diagnostics,omitempty"`
}

var (
	validateExecutable = os.Executable
	validateAssets     = demo.ResolveAssets
)

func parseValidateOptions(args []string, stdout, stderr io.Writer) (validateOptions, int, bool) {
	var o validateOptions
	fs := newCommandFlagSet("validate")
	fs.StringVar(&o.wasmPath, "wasm", "", "")
	fs.StringVar(&o.sample, "sample", "", "")
	fs.StringVar(&o.executor, "executor", "auto", "")
	fs.Var(&o.allow, "allow", "")
	fs.StringVar(&o.duration, "duration", "10s", "")
	fs.StringVar(&o.floorBPS, "floor-bps", "1048576", "")
	fs.StringVar(&o.ceilBPS, "ceil-bps", "1048576", "")
	flagArgs, guest := splitGuestArgs(args)
	if code, ok := parseCommandFlags(fs, flagArgs, validateUsage, stdout, stderr); !ok {
		return o, code, false
	}
	o.guestArgs = guest
	if fs.NArg() > 0 {
		return o, usageError("dbl validate", validateUsage, stderr,
			"unexpected positional argument %q: guest arguments must follow --", fs.Arg(0)), false
	}
	return o, exitOK, true
}

func validateCommand(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer) int {
	o, code, ok := parseValidateOptions(args, stdout, stderr)
	if !ok {
		return code
	}
	result := validationResult{}
	fail := func(field, message string) int {
		result.Diagnostics = []validationDiagnostic{{Field: field, Message: message}}
		if options.Output == outputJSON {
			if err := writeJSON(stdout, result); err != nil {
				fmt.Fprintf(stderr, "dbl validate: write result: %v\n", err)
				return exitFailure
			}
		} else {
			fmt.Fprintf(stderr, "dbl validate: %s: %s\n", field, message)
		}
		return exitUsage
	}

	switch {
	case o.sample != "" && o.sample != "hello":
		return fail("sample", "must be hello")
	case o.sample != "" && o.wasmPath != "":
		return fail("wasm", "use exactly one of --wasm or --sample hello")
	case o.sample == "" && strings.TrimSpace(o.wasmPath) == "":
		return fail("wasm", "--wasm or --sample hello is required")
	case strings.TrimSpace(o.executor) == "":
		return fail("executor_id", "must not be blank")
	}

	duration, err := time.ParseDuration(o.duration)
	if err != nil || duration < time.Millisecond || duration%time.Millisecond != 0 {
		return fail("duration", "must be a whole number of milliseconds at least 1ms")
	}
	floor, err := strconv.ParseInt(o.floorBPS, 10, 64)
	if err != nil {
		return fail("floor_bps", "must be a base-10 64-bit integer")
	}
	ceil, err := strconv.ParseInt(o.ceilBPS, 10, 64)
	if err != nil {
		return fail("ceil_bps", "must be a base-10 64-bit integer")
	}
	if floor < 0 {
		return fail("floor_bps", "must not be negative")
	}
	if ceil < 0 {
		return fail("ceil_bps", "must not be negative")
	}
	if floor > ceil {
		return fail("floor_bps", "must not exceed ceil_bps")
	}
	for i, destination := range o.allow {
		if err := validateDestination(destination); err != nil {
			return fail(fmt.Sprintf("destinations[%d]", i), err.Error())
		}
	}

	wasmPath := o.wasmPath
	result.Source = wasmPath
	if o.sample != "" {
		executable, err := validateExecutable()
		if err != nil {
			return fail("wasm", "could not locate the installed sample")
		}
		assets, err := validateAssets(executable)
		if err != nil {
			return fail("wasm", "sample hello requires the full installed package")
		}
		wasmPath = filepath.Join(assets.Root, "share", "debuglet", "hello.wasm")
		result.Source = "sample:hello"
	}
	wasm, err := readWasm(wasmPath)
	if err != nil {
		return fail("wasm", err.Error())
	}
	if err := validateWasmStructure(ctx, wasm); err != nil {
		return fail("wasm", err.Error())
	}

	addresses := append([]string(nil), o.allow...)
	if addresses == nil {
		addresses = []string{}
	}
	_, err = client.Prepare([]client.Request{{
		OrderID:    0,
		ExecutorID: o.executor,
		Args:       o.guestArgs,
		Wasm:       wasm,
		Policy: client.Policy{
			FloorBW:   floor,
			CeilBW:    ceil,
			TimeoutMS: int64(duration / time.Millisecond),
			Addresses: addresses,
		},
	}})
	if err != nil {
		return fail("request", err.Error())
	}

	result.Valid = true
	result.WasmBytes = len(wasm)
	result.ExecutorID = o.executor
	result.DurationMS = int64(duration / time.Millisecond)
	result.FloorBPS = floor
	result.CeilBPS = ceil
	result.Destinations = addresses
	if options.Output == outputJSON {
		if err := writeJSON(stdout, result); err != nil {
			fmt.Fprintf(stderr, "dbl validate: write result: %v\n", err)
			return exitFailure
		}
		return exitOK
	}
	fmt.Fprintln(stdout, "valid: true")
	fmt.Fprintf(stdout, "source: %s\n", result.Source)
	fmt.Fprintf(stdout, "wasm_bytes: %d\n", result.WasmBytes)
	fmt.Fprintf(stdout, "executor_id: %s\n", result.ExecutorID)
	fmt.Fprintf(stdout, "duration_ms: %d\n", result.DurationMS)
	fmt.Fprintf(stdout, "floor_bps: %d\n", result.FloorBPS)
	fmt.Fprintf(stdout, "ceil_bps: %d\n", result.CeilBPS)
	fmt.Fprintf(stdout, "destinations: %d\n", len(result.Destinations))
	return exitOK
}

func validateWasmStructure(ctx context.Context, wasm []byte) error {
	r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigInterpreter())
	defer r.Close(ctx)
	compiled, err := r.CompileModule(ctx, wasm)
	if err != nil {
		return fmt.Errorf("module is malformed or unsupported")
	}
	_ = compiled.Close(ctx)
	return nil
}

func validateDestination(raw string) error {
	if raw == "" || strings.TrimSpace(raw) != raw {
		return fmt.Errorf("must be a nonblank IP address or DNS name without surrounding whitespace")
	}
	if addr, err := netip.ParseAddr(raw); err == nil {
		if addr.Zone() != "" {
			return fmt.Errorf("scoped IP addresses are not supported")
		}
		return nil
	}
	if strings.Contains(raw, ":") {
		return fmt.Errorf("ports are not allowed; pass the destination port in the guest arguments")
	}
	if !validDNSName(raw) {
		return fmt.Errorf("must be a bare IP address or syntactically valid DNS name")
	}
	return nil
}

func validDNSName(name string) bool {
	if strings.HasSuffix(name, ".") {
		name = strings.TrimSuffix(name, ".")
	}
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if r > 127 || !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

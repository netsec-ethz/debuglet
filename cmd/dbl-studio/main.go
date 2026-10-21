// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// Command dbl-studio edits and compiles visual measurement workflows.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/netsec-ethz/debuglet/internal/studio"
	"github.com/netsec-ethz/debuglet/pkg/workflow"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "dbl-studio:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: dbl-studio catalog|validate|build|validate-experiment|build-experiment|serve|worker|mcp [options]")
	}
	command := args[0]
	if command == "--help" || command == "-h" || command == "help" {
		_, err := fmt.Fprintln(stdout, "usage: dbl-studio catalog|validate|build|validate-experiment|build-experiment|serve|worker|mcp [options]\nUse <command> -h for options.")
		return err
	}
	flags := flag.NewFlagSet("dbl-studio "+command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	sdk := flags.String("sdk", "", "trusted Debuglet source checkout (required for compilation)")
	input := flags.String("input", "-", "workflow JSON file, or - for stdin")
	output := flags.String("output", "-", "bundle JSON file, or - for stdout")
	address := flags.String("listen", "127.0.0.1:8090", "loopback HTTP address")
	ui := flags.String("ui", "", "built console directory containing index.html")
	dispatcher := flags.String("dispatcher", "", "owned loopback development dispatcher origin for the console API proxy")
	caFile := flags.String("ca-file", "", "additional PEM CA for the fixed dispatcher HTTPS connection")
	workspace := flags.String("workspace", "", "directory for MCP workflow and bundle files")
	socket := flags.String("socket", "", "absolute Unix socket path for the hosted compiler worker")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if command == "worker" {
		var unsupported string
		flags.Visit(func(f *flag.Flag) {
			if f.Name != "socket" && f.Name != "sdk" {
				unsupported = f.Name
			}
		})
		if unsupported != "" {
			return fmt.Errorf("worker does not support --%s; use only --socket and --sdk", unsupported)
		}
		if *socket == "" || *sdk == "" {
			return errors.New("worker requires --socket and --sdk")
		}
	}
	var builder *studio.Builder
	if *sdk != "" {
		var err error
		builder, err = studio.NewBuilder(*sdk)
		if err != nil {
			return err
		}
	}
	switch command {
	case "catalog":
		return json.NewEncoder(stdout).Encode(workflow.Catalog())
	case "serve":
		return studio.Serve(ctx, builder, studio.ServerConfig{Address: *address, UI: *ui, Dispatcher: *dispatcher, CAFile: *caFile}, func(address string) { fmt.Fprintln(stderr, "Open", address) })
	case "worker":
		return studio.ServeWorker(ctx, builder, *socket, func(path string) { fmt.Fprintln(stderr, "Studio compiler listening on", path) })
	case "mcp":
		if *workspace == "" {
			return errors.New("mcp requires --workspace for editable workflows and build bundles")
		}
		return studio.MCP(ctx, builder, *workspace)
	case "validate", "build", "validate-experiment", "build-experiment":
		var reader io.Reader = os.Stdin
		if *input != "-" {
			file, err := os.Open(*input)
			if err != nil {
				return err
			}
			defer file.Close()
			reader = file
		}
		var result any
		var err error
		if command == "validate-experiment" || command == "build-experiment" {
			experiment, decodeErr := studio.DecodeExperiment(reader)
			if decodeErr != nil {
				return decodeErr
			}
			if command == "validate-experiment" {
				diagnostics := workflow.ValidateExperiment(experiment)
				if diagnostics == nil {
					diagnostics = []workflow.ExperimentDiagnostic{}
				}
				if err := json.NewEncoder(stdout).Encode(map[string]any{"diagnostics": diagnostics}); err != nil {
					return err
				}
				if len(diagnostics) > 0 {
					return errors.New("experiment is invalid")
				}
				return nil
			}
			if builder == nil {
				return errors.New("build-experiment requires --sdk")
			}
			result, err = builder.BuildExperiment(ctx, experiment)
		} else {
			wf, decodeErr := studio.DecodeWorkflow(reader)
			if decodeErr != nil {
				return decodeErr
			}
			if command == "validate" {
				diagnostics := workflow.Validate(wf)
				if diagnostics == nil {
					diagnostics = []workflow.Diagnostic{}
				}
				if err := json.NewEncoder(stdout).Encode(map[string]any{"diagnostics": diagnostics}); err != nil {
					return err
				}
				if len(diagnostics) > 0 {
					return errors.New("workflow is invalid")
				}
				return nil
			}
			if builder == nil {
				return errors.New("build requires --sdk pointing to the matching Debuglet checkout")
			}
			result, err = builder.Build(ctx, wf)
		}
		if err != nil {
			return err
		}
		var writer io.Writer = stdout
		if *output != "-" {
			file, err := os.OpenFile(*output, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			defer file.Close()
			writer = file
		}
		return json.NewEncoder(writer).Encode(result)
	default:
		return fmt.Errorf("unknown command %q (use --help for commands)", command)
	}
}

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"text/tabwriter"

	"github.com/netsec-ethz/debuglet/internal/connections"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

const connectUsage = `Usage:
  dbl [--config FILE] connect URL [--name NAME]

Validate, save and select an HTTP dispatcher connection. The default name is local.
Older HTTP servers can be saved without local executor connection metadata.
`

const dispatcherUsage = `Usage:
  dbl dispatcher up [--name local] [--port 9000] [--grpc-port 9001] [--state-dir DIR]
  dbl dispatcher list
  dbl dispatcher use NAME
  dbl dispatcher remove NAME

list shows saved client connections, not global network discovery.
use selects a saved connection; remove forgets it without stopping a service.
Aliases: dbl dispatchers (saved connections), dbl executors (registered executors).
`

const executorUsage = `Usage:
  dbl executor up [--name worker] [--dispatcher NAME|URL] [--state-dir DIR]
  dbl executor list

list queries executors registered with the selected dispatcher (alias: dbl nodes).
`

func connectCommand(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer) int {
	fs := newCommandFlagSet("connect")
	name := fs.String("name", "local", "saved connection name")
	// Accept the documented URL-before-options spelling as well as ordinary
	// flag-before-positional syntax, without changing other command parsers.
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		args = append(append([]string{}, args[1:]...), args[0])
	}
	if code, ok := parseCommandFlags(fs, args, connectUsage, stdout, stderr); !ok {
		return code
	}
	if fs.NArg() != 1 || options.EndpointSet || options.Dispatcher != "" {
		return usageError("dbl connect", connectUsage, stderr, "supply one URL, without --endpoint or --dispatcher")
	}
	if err := connections.ValidateName(*name); err != nil {
		return usageError("dbl connect", connectUsage, stderr, "%v", err)
	}
	endpoint := fs.Arg(0)
	c, err := newClient(endpoint, client.Options{RequestTimeout: options.Timeout})
	if err != nil {
		return usageError("dbl connect", connectUsage, stderr, "%v", err)
	}
	if _, err := c.Version(ctx); err != nil {
		return reportFailure(ctx, "dbl connect: server version", stderr, err)
	}
	profile := connections.Profile{Name: *name, Endpoint: endpoint}
	info, err := c.Connection(ctx)
	if err != nil {
		var httpErr *client.HTTPError
		if !errors.As(err, &httpErr) || (httpErr.StatusCode != http.StatusNotFound && httpErr.StatusCode != http.StatusMethodNotAllowed && httpErr.StatusCode != http.StatusNotImplemented) {
			return reportFailure(ctx, "dbl connect: connection metadata", stderr, err)
		}
	} else {
		profile.GRPCAddress, profile.YamuxAddress = info.GRPCAddress, info.YamuxAddress
	}
	if err := ctx.Err(); err != nil {
		return reportFailure(ctx, "dbl connect", stderr, err)
	}
	if err := connections.Save(options.ConfigPath, profile, true); err != nil {
		return reportFailure(ctx, "dbl connect: save connection", stderr, err)
	}
	return emitReported(ctx, "dbl connect", options.Output, stdout, stderr, profile, func(w io.Writer) error {
		_, err := fmt.Fprintf(w, "Connected to %s (%s).\nTry: dbl executor list\n", profile.Name, profile.Endpoint)
		return err
	})
}

func dispatcherCommand(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "up" {
		return dispatcherUpCommand(ctx, args[1:], options, stdout, stderr)
	}
	if len(args) == 0 {
		return usageError("dbl dispatcher", dispatcherUsage, stderr, "missing subcommand")
	}
	if args[0] == "--help" || args[0] == "-h" {
		fmt.Fprint(stdout, dispatcherUsage)
		return exitOK
	}
	subcommand := args[0]
	fs := newCommandFlagSet("dispatcher " + subcommand)
	if code, ok := parseCommandFlags(fs, args[1:], dispatcherUsage, stdout, stderr); !ok {
		return code
	}
	if subcommand == "list" {
		if fs.NArg() != 0 {
			return usageError("dbl dispatcher list", dispatcherUsage, stderr, "list accepts no name")
		}
		cfg, err := connections.Load(options.ConfigPath)
		if err != nil {
			return reportFailure(ctx, "dbl dispatcher list", stderr, err)
		}
		return emitReported(ctx, "dbl dispatcher list", options.Output, stdout, stderr, cfg, func(w io.Writer) error {
			tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tCURRENT\tENDPOINT")
			for _, p := range cfg.Dispatchers {
				fmt.Fprintf(tw, "%s\t%t\t%s\n", p.Name, p.Name == cfg.Current, p.Endpoint)
			}
			return tw.Flush()
		})
	}
	if (subcommand != "use" && subcommand != "remove") || fs.NArg() != 1 {
		return usageError("dbl dispatcher", dispatcherUsage, stderr, "use or remove requires one saved name")
	}
	name := fs.Arg(0)
	if err := connections.ValidateName(name); err != nil {
		return usageError("dbl dispatcher", dispatcherUsage, stderr, "%v", err)
	}
	key, apply := "selected", connections.Select
	if subcommand == "remove" {
		key, apply = "removed", connections.Remove
	}
	if err := apply(options.ConfigPath, name); err != nil {
		return reportFailure(ctx, "dbl dispatcher "+subcommand, stderr, err)
	}
	return emitReported(ctx, "dbl dispatcher "+subcommand, options.Output, stdout, stderr,
		map[string]any{"name": name, key: true},
		func(w io.Writer) error { _, err := fmt.Fprintf(w, "%s: %s\n", subcommand, name); return err })
}

func executorCommand(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "up":
			return executorUpCommand(ctx, args[1:], options, stdout, stderr)
		case "list":
			return nodesCommand(ctx, args[1:], options, stdout, stderr)
		case "--help", "-h":
			fmt.Fprint(stdout, executorUsage)
			return exitOK
		}
	}
	return usageError("dbl executor", executorUsage, stderr, "expected up or list")
}

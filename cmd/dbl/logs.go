package main

import (
	"context"
	"fmt"
	"io"

	"github.com/netsec-ethz/debuglet/pkg/client"
)

const logsUsage = `Usage:
  dbl logs [--after N] [--limit N] [--follow] ID

Options:
  --after N     cursor: return entries with IDs greater than N (>= 0)
  --limit N     entries per page, 1..1000 (0 selects the server default 100)
  --follow      keep draining pages until the debuglet has exited

Human output writes the exact guest bytes to stdout and cursor/state
information to stderr; JSON output prints one LogPage per line.
`

// logsOptions are the validated inputs of one `logs` invocation.
type logsOptions struct {
	id     string
	after  int64
	limit  int64
	follow bool
}

func parseLogsOptions(args []string, stdout, stderr io.Writer) (logsOptions, int, bool) {
	var o logsOptions
	fs := newCommandFlagSet("logs")
	fs.Int64Var(&o.after, "after", 0, "")
	fs.Int64Var(&o.limit, "limit", 0, "")
	fs.BoolVar(&o.follow, "follow", false, "")
	if code, ok := parseCommandFlags(fs, args, logsUsage, stdout, stderr); !ok {
		return o, code, false
	}
	fail := func(format string, a ...any) (logsOptions, int, bool) {
		return o, usageError("dbl logs", logsUsage, stderr, format, a...), false
	}
	switch {
	case o.after < 0:
		return fail("--after %d must not be negative", o.after)
	case o.limit < 0 || o.limit > 1000:
		return fail("--limit %d must be within 1..1000 (or 0 for the default)", o.limit)
	}
	id, msg := singleID(fs)
	if msg != "" {
		return fail("%s", msg)
	}
	o.id = id
	return o, exitOK, true
}

// logFetcher returns one page for the given cursor and limit. The production
// fetcher is the SDK's Logs, which rejects a page whose entry IDs do not
// advance past the requested cursor or whose own cursor does not match them, so
// the follow loop below can neither spin nor lose output on a misbehaving
// server.
type logFetcher func(ctx context.Context, options client.LogOptions) (client.LogPage, error)

// followLogs drains pages while has_more and polls every pollInterval until an
// observed terminal page has been drained. A full terminal page may report
// has_more with no later data, so the empty page after it is permitted and ends
// the follow. emit is called once per page.
func followLogs(ctx context.Context, fetch logFetcher, start, limit int64, emit func(client.LogPage) error) error {
	cursor := start
	for {
		page, err := fetch(ctx, client.LogOptions{After: cursor, Limit: limit})
		if err != nil {
			return err
		}
		if err := emit(page); err != nil {
			return err
		}
		if len(page.Logs) > 0 {
			cursor = page.After
		}
		if page.HasMore {
			continue
		}
		if page.State == client.StateExited {
			return nil
		}
		if err := sleepContext(ctx, pollInterval); err != nil {
			return err
		}
	}
}

// logEmitter writes pages in the selected output mode. Human mode writes the
// exact guest bytes to stdout and progress to stderr; JSON mode writes one
// LogPage per line to stdout and nothing to stderr.
type logEmitter struct {
	output    string
	stdout    io.Writer
	stderr    io.Writer
	lastState string
}

func (e *logEmitter) emit(page client.LogPage) error {
	if e.output == outputJSON {
		return writeJSON(e.stdout, page)
	}
	for _, entry := range page.Logs {
		if _, err := e.stdout.Write(entry.Output); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
	}
	if len(page.Logs) > 0 || page.State != e.lastState {
		e.lastState = page.State
		fmt.Fprintf(e.stderr, "dbl logs: state=%s after=%d entries=%d has_more=%t", page.State, page.After, len(page.Logs), page.HasMore)
		if page.Error != "" {
			fmt.Fprintf(e.stderr, " error=%q", page.Error)
		}
		fmt.Fprintln(e.stderr)
	}
	return nil
}

func logsCommand(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer) int {
	o, code, ok := parseLogsOptions(args, stdout, stderr)
	if !ok {
		return code
	}
	c, code, ok := connect("dbl logs", options, false, stderr)
	if !ok {
		return code
	}
	emitter := &logEmitter{output: options.Output, stdout: stdout, stderr: stderr}
	fetch := func(ctx context.Context, lo client.LogOptions) (client.LogPage, error) {
		return c.Logs(ctx, o.id, lo)
	}
	if !o.follow {
		page, err := fetch(ctx, client.LogOptions{After: o.after, Limit: o.limit})
		if err != nil {
			return reportFailure(ctx, "dbl logs", stderr, err)
		}
		if err := emitter.emit(page); err != nil {
			fmt.Fprintf(stderr, "dbl logs: %v\n", err)
			return exitFailure
		}
		return exitOK
	}
	if err := followLogs(ctx, fetch, o.after, o.limit, emitter.emit); err != nil {
		return reportFailure(ctx, "dbl logs", stderr, err)
	}
	return exitOK
}

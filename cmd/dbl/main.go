// Command dbl is the Debuglet command-line client for the private alpha: it
// discovers nodes, submits TEST-funded WASM, inspects results and output and
// acknowledges cancellation through the dispatcher's HTTP API.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

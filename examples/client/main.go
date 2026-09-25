// Command client submits a WASM measurement to a Debuglet environment and
// prints its output using only the public Go SDK. Without flags it expects the
// loopback environment of dbl up; --register, --allow-remote-test and --allow
// add what a dispatcher on another host needs. See docs/quickstart-remote.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/client"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "client example:", err)
		os.Exit(1)
	}
}

func run() error {
	endpoint := flag.String("endpoint", "http://127.0.0.1:9000", "dispatcher URL")
	wasmPath := flag.String("wasm", "", "compiled WASI guest")
	executor := flag.String("executor", "", "executor ID (default: sole ready executor)")
	register := flag.String("register", "", "account name to create and log in as")
	allowRemote := flag.Bool("allow-remote-test", false, "permit TEST submission to a dispatcher that is not loopback")
	allow := flag.String("allow", "", "comma-separated destinations the guest may reach")
	flag.Parse()
	if *wasmPath == "" {
		return errors.New("--wasm FILE is required")
	}
	wasm, err := os.ReadFile(*wasmPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := client.New(*endpoint, client.Options{AllowRemoteTEST: *allowRemote})
	if err != nil {
		return err
	}
	// A dispatcher that does not serve the local development profile authenticates
	// every request that is not public, so the run needs an account and a session.
	// Neither the account key nor the session token is printed. This example also
	// keeps neither, so its account serves this run only; an application that wants
	// to log in again stores the returned key and recovery code with owner-only
	// permissions instead.
	if *register != "" {
		account, err := c.CreateAccount(ctx, *register)
		if err != nil {
			return err
		}
		session, err := c.Login(ctx, account.AccountKey)
		if err != nil {
			return err
		}
		if c, err = c.WithCredential(session.Token); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Registered %s as %s\n", account.Name, account.ID)
	}
	id := *executor
	if id == "" {
		nodes, err := c.Nodes(ctx)
		if err != nil {
			return err
		}
		for _, node := range nodes {
			if !node.Ready {
				continue
			}
			if id != "" {
				return errors.New("multiple ready executors; supply --executor ID")
			}
			id = node.ID
		}
		if id == "" {
			return errors.New("no ready executor; start dbl up first")
		}
	}
	// The allowlist narrows the executor's own destination policy; it never widens it.
	addresses := []string{}
	if *allow != "" {
		addresses = strings.Split(*allow, ",")
	}
	batch, err := client.Prepare([]client.Request{{
		OrderID: 0, ExecutorID: id, Wasm: wasm, Args: flag.Args(),
		Policy: client.Policy{FloorBW: 1_000_000, CeilBW: 1_000_000, TimeoutMS: 10_000, Addresses: addresses},
	}})
	if err != nil {
		return err
	}
	submission, err := c.SubmitTEST(ctx, batch)
	if err != nil {
		return err
	}
	jobID := submission.IDs[0]
	fmt.Fprintf(os.Stderr, "Submitted %s\n", jobID)
	// Read output as it arrives. A short final drain accommodates output which
	// is stored shortly after the terminal state; this is not a durability promise.
	var cursor int64
	var terminalSince time.Time
	for {
		page, err := c.Logs(ctx, jobID, client.LogOptions{After: cursor})
		if err != nil {
			return err
		}
		for _, entry := range page.Logs {
			if _, err := os.Stdout.Write(entry.Output); err != nil {
				return err
			}
		}
		cursor = page.After
		if page.State == client.StateExited {
			if page.Error != "" {
				return fmt.Errorf("workload failed: %s", page.Error)
			}
			if terminalSince.IsZero() {
				terminalSince = time.Now()
			}
			if !page.HasMore && time.Since(terminalSince) >= time.Second {
				return nil
			}
		}
		if page.HasMore {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

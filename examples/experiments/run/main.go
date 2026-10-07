// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// run submits a saved experiment definition and collects its existing run results.
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
	"time"

	"github.com/netsec-ethz/debuglet/internal/connections"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

func main() {
	if err := run(); err != nil { fmt.Fprintln(os.Stderr, "experiment:", err); os.Exit(1) }
}

func run() (failure error) {
	action := flag.String("action", "submit", "submit, results or cancel")
	manifest := flag.String("manifest", "", "experiment definition JSON (paths relative to working directory)")
	receiptPath := flag.String("receipt", "experiment.json", "new receipt for submit; existing receipt for results/cancel")
	endpoint := flag.String("endpoint", "", "explicit dispatcher URL; otherwise use saved dbl connection")
	config := flag.String("config", "", "saved dbl connections file")
	dispatcher := flag.String("dispatcher", "", "saved dbl connection name")
	remote := flag.Bool("allow-remote-test", false, "permit remote TEST submission")
	timeout := flag.Duration("timeout", 90*time.Second, "whole operation deadline")
	flag.Parse()
	if *action != "submit" && *action != "results" && *action != "cancel" { return errors.New("unknown action") }
	if *timeout <= 0 { return errors.New("timeout must be positive") }
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	profile := connections.Profile{Endpoint:*endpoint}
	var err error
	if *endpoint == "" { profile, err = connections.Resolve(*config, *dispatcher); if err != nil { return err } }
	credential, err := connections.CredentialFor(ctx, *config, profile.Name, profile.Endpoint)
	if err != nil { return err }
	c, err := client.New(profile.Endpoint, client.Options{Credential:credential.Token, AllowRemoteTEST:*remote})
	if err != nil { return err }
	var receipt client.ExperimentSubmission
	defer func() {
		if *action == "submit" && ctx.Err() != nil {
			cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
			defer done()
			failure = errors.Join(failure, c.CancelExperiment(cleanup, receipt))
		}
	}()
	if *action == "submit" {
		var definition client.ExperimentDefinition
		if err := readJSON(*manifest, &definition); err != nil { return err }
		file, err := os.OpenFile(*receiptPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil { return err }
		receipt, err = c.SubmitExperimentTEST(ctx, definition)
		writeErr := json.NewEncoder(file).Encode(receipt)
		closeErr := file.Close()
		if err != nil || writeErr != nil || closeErr != nil { return errors.Join(err, writeErr, closeErr) }
		fmt.Fprintf(os.Stderr, "Experiment %s; receipt %s\n", receipt.ExperimentID, *receiptPath)
	} else if err := readJSON(*receiptPath, &receipt); err != nil { return err }
	if receipt.ExperimentID == "" || len(receipt.Participants) == 0 { return errors.New("receipt has no admitted experiment") }
	if *action == "cancel" { return c.CancelExperiment(ctx, receipt) }
	for {
		group, err := c.ExportExperiment(ctx, receipt)
		if err != nil { return err }
		complete := true
		var failures []error
		for _, result := range group.Results {
			if result.Outcome.State != client.StateExited || (result.Output.Status.State != "complete" && result.Output.Status.State != "truncated") { complete = false }
			if result.Outcome.Error != "" { failures = append(failures, fmt.Errorf("run %s: %s", result.RunID, result.Outcome.Error)) }
		}
		if complete || *action == "results" {
			if err := json.NewEncoder(os.Stdout).Encode(group); err != nil { return err }
			return errors.Join(failures...)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500*time.Millisecond):
		}
	}
}

func readJSON(path string, destination any) error {
	file, err := os.Open(path)
	if err != nil { return err }
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil { return err }
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) { return errors.New("expected one JSON document") }
	return nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

// ServerEndpoint is replaced only when it is a complete client argument.
const ServerEndpoint = "{server_endpoint}"

type RendezvousOptions struct {
	ReadinessTimeout time.Duration
	Timeout          time.Duration
	Output           func(role, runID string, page LogPage) error
}

type RendezvousRun struct {
	ID            string `json:"id"`
	ExecutorID    string `json:"executor_id"`
	TransactionID string `json:"transaction_id"`
	State         string `json:"state"`
	Error         string `json:"error"`
	Cleanup       string `json:"cleanup"`
}

type RendezvousResult struct {
	Server   RendezvousRun `json:"server"`
	Client   RendezvousRun `json:"client"`
	Endpoint string        `json:"endpoint"`
}

// RendezvousTEST submits a listener once, waits for its bound endpoint, then
// submits one client on another executor. It never replays an uncertain request.
// Both known runs are cancelled and inspected on every exit, under an independent
// bounded cleanup context. Preserve the returned identities even on error.
func (c *Client) RendezvousTEST(ctx context.Context, server, peer Request, opts RendezvousOptions) (result RendezvousResult, failure error) {
	if opts.Timeout == 0 {
		opts.Timeout = time.Minute
	}
	if opts.ReadinessTimeout == 0 {
		opts.ReadinessTimeout = 10 * time.Second
	}
	if opts.Timeout < time.Second || opts.Timeout > 5*time.Minute || opts.ReadinessTimeout < time.Millisecond || opts.ReadinessTimeout > time.Minute {
		return result, errors.New("client: rendezvous timeout must be 1s..5m and readiness timeout 1ms..1m")
	}
	if server.ExecutorID == "" || peer.ExecutorID == "" || server.ExecutorID == peer.ExecutorID || !server.Policy.ListenTCP || server.StartTimestamp != nil || peer.StartTimestamp != nil {
		return result, errors.New("client: rendezvous requires two distinct executors, an immediate TCP listener and an immediate client")
	}
	placeholder := false
	for _, arg := range peer.Args {
		placeholder = placeholder || arg == ServerEndpoint
	}
	if !placeholder {
		return result, errors.New("client: client arguments must include {server_endpoint}")
	}
	serverBatch, err := Prepare([]Request{server})
	if err != nil {
		return result, err
	}
	if _, err := Prepare([]Request{peer}); err != nil {
		return result, err
	}
	ctx = context.WithValue(ctx, requiredVersionKey{}, "1.12")
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	result.Server.ExecutorID, result.Client.ExecutorID = server.ExecutorID, peer.ExecutorID
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer stop()
		for _, run := range []*RendezvousRun{&result.Server, &result.Client} {
			if run.ID == "" {
				continue
			}
			run.Cleanup = "unconfirmed"
			// Send both requests before polling, so one unresponsive executor
			// cannot prevent the sibling cancellation from being requested.
			request, stop := context.WithTimeout(cleanup, 2*time.Second)
			_ = c.Cancel(request, run.ID, run.ExecutorID)
			stop()
		}
		for _, run := range []*RendezvousRun{&result.Server, &result.Client} {
			if run.ID == "" {
				continue
			}
			for {
				report, err := c.Recovery(cleanup, run.ID)
				if err != nil {
					failure = errors.Join(failure, fmt.Errorf("inspect cleanup %s: %w", run.ID, err))
					break
				}
				if report.Observation.Classification == "absent" && report.Observation.CurrentAtCheck != nil && *report.Observation.CurrentAtCheck {
					run.Cleanup = "confirmed_absent"
					break
				}
				if err := rendezvousPause(cleanup); err != nil {
					failure = errors.Join(failure, fmt.Errorf("cleanup %s remains unconfirmed: %w", run.ID, err))
					break
				}
			}
		}
	}()
	if err := c.submitRendezvous(ctx, serverBatch, &result.Server); err != nil {
		return result, err
	}
	readyCtx, stop := context.WithTimeout(ctx, opts.ReadinessTimeout)
	defer stop()
	for {
		run, err := c.RunDetail(readyCtx, result.Server.ID)
		if err != nil {
			return result, err
		}
		result.Server.State, result.Server.Error = run.Outcome.State, run.Outcome.Error
		if run.ExecutorID != server.ExecutorID {
			return result, errors.New("client: listener belongs to another executor")
		}
		if run.Outcome.State == StateExited {
			return result, errors.New("client: listener exited before readiness")
		}
		if run.Execution != nil && run.Execution.ListenerReady && run.Execution.TCPListener != nil {
			host, port, err := net.SplitHostPort(*run.Execution.TCPListener)
			number, portErr := strconv.Atoi(port)
			if err != nil || portErr != nil || number < 1 || number > 65535 || host == "" || run.Outcome.State != "RunStateStarted" || run.Execution.TimeSource != "dispatcher-observed" || run.Execution.StartedObservedAt == nil || run.Execution.TerminalObservedAt != nil {
				return result, errors.New("client: inconsistent listener readiness")
			}
			result.Endpoint = *run.Execution.TCPListener
			peer.Args = append([]string{}, peer.Args...)
			for i, arg := range peer.Args {
				if arg == ServerEndpoint {
					peer.Args[i] = result.Endpoint
				}
			}
			peer.Policy.Addresses = append(append([]string{}, peer.Policy.Addresses...), host)
			break
		}
		if err := rendezvousPause(readyCtx); err != nil {
			return result, fmt.Errorf("wait for listener readiness: %w", err)
		}
	}
	peerBatch, err := Prepare([]Request{peer})
	if err != nil {
		return result, err
	}
	if err := c.submitRendezvous(ctx, peerBatch, &result.Client); err != nil {
		return result, err
	}
	runs := []*RendezvousRun{&result.Server, &result.Client}
	cursors := [2]int64{}
	for {
		complete := true
		for i, run := range runs {
			page, err := c.Logs(ctx, run.ID, LogOptions{After: cursors[i], Limit: 100})
			if err != nil {
				return result, err
			}
			run.State, run.Error = page.State, page.Error
			if opts.Output != nil && len(page.Logs) > 0 {
				role := []string{"server", "client"}[i]
				if err := opts.Output(role, run.ID, page); err != nil {
					return result, err
				}
			}
			cursors[i] = page.After
			if page.State == StateExited && page.Error != "" {
				return result, fmt.Errorf("%s run %s failed: %s", []string{"server", "client"}[i], run.ID, page.Error)
			}
			if page.State != StateExited || page.Output.FinalCursor == nil || page.After < *page.Output.FinalCursor {
				complete = false
			}
			if page.Output.State == "truncated" || page.State == StateExited && page.Output.State == "unknown" {
				return result, &IncompleteOutputError{Output: page.Output}
			}
		}
		if complete {
			return result, nil
		}
		if err := rendezvousPause(ctx); err != nil {
			return result, err
		}
	}
}

func (c *Client) submitRendezvous(ctx context.Context, batch *PreparedBatch, run *RendezvousRun) error {
	submission, err := c.SubmitTEST(ctx, batch)
	run.TransactionID = submission.TransactionID
	if len(submission.IDs) == 1 {
		run.ID = submission.IDs[0]
	}
	var failed *SubmissionError
	if errors.As(err, &failed) {
		run.TransactionID = failed.TransactionID
		if len(failed.AdmittedIDs) == 1 {
			run.ID = failed.AdmittedIDs[0]
		}
	}
	return err
}

func rendezvousPause(ctx context.Context) error {
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-timer.C:
		return nil
	}
}

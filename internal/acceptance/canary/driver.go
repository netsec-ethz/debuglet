package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	apispec "github.com/netsec-ethz/debuglet/api"
	"github.com/netsec-ethz/debuglet/internal/artifact"
	"github.com/netsec-ethz/debuglet/internal/demo"
	"github.com/netsec-ethz/debuglet/pkg/client"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"time"
)

const captureLimit = 4 << 20

var errInvalidInput = errors.New("invalid local compatibility input")

type commandResult struct {
	Started bool
	Stdout  []byte
	Err     error
}

// localSession owns all subprocess groups, even unsuccessful CLI invocations.
// No public command can replace this private testing seam.
type localSession interface {
	StartDispatcher(context.Context) (string, error)
	StartExecutor(context.Context) error
	StartTarget(context.Context) (address, nonce string, err error)
	Execute(context.Context, []string) commandResult
	TargetACK(context.Context) error
	StopExecutor(context.Context) error
	CloseTarget(context.Context) error
	Cleanup(context.Context) (CleanupEvidence, error)
}
type driverDependencies struct {
	validate func(Manifest, demo.Assets) error
	resolve  func(string) (demo.Assets, error)
	open     func(Options, string) localSession
	write    func(string, Evidence) error
	poll     func(context.Context) error
}

func productionDependencies() driverDependencies {
	return driverDependencies{Validate, demo.ResolveAssets, newLocalSession, WriteEvidence, pollContext}
}

// Run verifies installed bytes before effects. The protocol shares one deadline;
// final cleanup has at most five additional seconds. Submission is never retried.
func Run(ctx context.Context, opts Options) (Evidence, error) {
	return runDriver(ctx, opts, productionDependencies())
}
func runDriver(parent context.Context, opts Options, deps driverDependencies) (ev Evidence, err error) {
	ev = Evidence{SchemaVersion: 1, Environment: "local", ETHTestbed: "unconfirmed", Outcome: "failed", Phase: "validate", StartedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	defer func() {
		if ev.FinishedAt == nil {
			ev.FinishedAt = ptr(time.Now().UTC().Format(time.RFC3339Nano))
		}
		if err != nil && ev.Error == nil {
			ev.Error = ptr(safeFailure(ev.Phase, err))
		}
	}()
	if deps.validate(opts.Manifest, opts.Assets) != nil || !lowerHex(opts.ArchiveSHA256, 64) || !filepath.IsAbs(opts.EvidenceDir) || filepath.Clean(opts.EvidenceDir) == string(filepath.Separator) {
		return ev, errInvalidInput
	}
	ev.SourceSHA, ev.ArchiveSHA256, ev.ManifestSHA256, ev.ExecutorID = opts.Assets.Manifest.SourceSHA, opts.ArchiveSHA256, opts.Manifest.SourceSHA256, opts.Manifest.ExecutorID
	ev.Phase = "provenance"
	resolved, e := deps.resolve(opts.Assets.CLI)
	if e != nil || !reflect.DeepEqual(resolved, opts.Assets) {
		return ev, errInvalidInput
	}
	if opts.DryRun {
		ev.Outcome = "plan"
		return ev, nil
	}
	if runtime.GOOS != "linux" {
		return ev, errors.New("local compatibility requires Linux")
	}
	if e := parent.Err(); e != nil {
		return ev, e
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(opts.Manifest.Limits.AttemptMS)*time.Millisecond)
	defer cancel()
	// Refuse to adopt an existing directory, even if it appears empty.
	if e := os.Mkdir(opts.EvidenceDir, 0700); e != nil {
		return ev, errInvalidInput
	}
	var session localSession
	stateDir := ""
	defer func() {
		failedPhase := ev.Phase
		ev.Phase = "cleanup"
		cleanupCtx, end := context.WithTimeout(context.Background(), 5*time.Second)
		defer end()
		var cleanupErr error
		if session != nil {
			registry := ev.Cleanup.RegistryIneligible
			ev.Cleanup, cleanupErr = session.Cleanup(cleanupCtx)
			ev.Cleanup.RegistryIneligible = registry
		} else {
			ev.Cleanup.ChildrenReaped, ev.Cleanup.ForcedKills = ptr(true), ptr(0)
		}
		if stateDir != "" && ev.Cleanup.ChildrenReaped != nil && *ev.Cleanup.ChildrenReaped {
			removeErr := os.RemoveAll(stateDir)
			ev.Cleanup.StateRemoved = ptr(removeErr == nil)
			cleanupErr = errors.Join(cleanupErr, removeErr)
		} else if stateDir != "" {
			ev.Cleanup.StateRemoved = ptr(false)
		}
		if ev.Cleanup.ChildrenReaped == nil || !*ev.Cleanup.ChildrenReaped || ev.Cleanup.ForcedKills == nil || *ev.Cleanup.ForcedKills != 0 || stateDir != "" && (ev.Cleanup.StateRemoved == nil || !*ev.Cleanup.StateRemoved) {
			cleanupErr = errors.Join(cleanupErr, errors.New("owned cleanup was not complete and graceful"))
		}
		if err != nil {
			ev.Phase = failedPhase
		}
		err = errors.Join(err, cleanupErr, ctx.Err())
		if err == nil {
			ev.Outcome, ev.Phase = "passed", "complete"
		} else {
			ev.Error = ptr(safeFailure(ev.Phase, err))
		}
		ev.FinishedAt = ptr(time.Now().UTC().Format(time.RFC3339Nano))
		if e := deps.write(opts.EvidenceDir, ev); e != nil {
			err = errors.Join(err, errors.New("persist final evidence"))
			ev.Outcome, ev.Phase, ev.Error = "failed", "cleanup", ptr("cleanup: evidence persistence failed")
		}
	}()
	stateDir, err = os.MkdirTemp(opts.EvidenceDir, "state-")
	if err != nil {
		return ev, err
	}
	session = deps.open(opts, stateDir)
	ev.Phase = "startup"
	endpoint, err := session.StartDispatcher(ctx)
	if err != nil {
		return ev, err
	}
	ev.DispatcherSourceSHA = ptr(resolved.Manifest.SourceSHA)
	// Every installed CLI invocation carries the owned endpoint and whatever is
	// left of the deadline of the context it runs under.
	execIn := func(ctx context.Context, command ...string) commandResult {
		if e := ctx.Err(); e != nil {
			return commandResult{Err: e}
		}
		deadline, _ := ctx.Deadline()
		args := []string{"--endpoint", endpoint, "--timeout", time.Until(deadline).String(), "--output", "json"}
		return session.Execute(ctx, append(args, command...))
	}
	execCLI := func(command ...string) commandResult { return execIn(ctx, command...) }
	var version versionDocument
	if e := decodeCommand(execCLI("version", "--server"), &version); e != nil || version.Module != "github.com/netsec-ethz/debuglet" || version.Revision != resolved.Manifest.SourceSHA || version.Modified || version.Version != resolved.Manifest.Version || version.Server == nil || version.Server.Version != resolved.Manifest.Version || !candidateIdentities(*version.Server) {
		return ev, errors.Join(errors.New("candidate version mismatch"), e)
	}
	ev.ReportedVersion = ptr(version.Server.Version)
	ev.ReportedAPIVersion = ptr(version.Server.APIVersion)
	getNodes := func() ([]client.Node, error) {
		var nodes []client.Node
		e := decodeCommand(execCLI("nodes"), &nodes)
		return nodes, e
	}
	nodes, err := getNodes()
	if err != nil {
		return ev, err
	}
	for _, node := range nodes {
		if node.ID == opts.Manifest.ExecutorID {
			return ev, errors.New("executor ID already registered")
		}
	}
	if e := session.StartExecutor(ctx); e != nil {
		return ev, e
	}
	for {
		nodes, e := getNodes()
		if e != nil {
			return ev, e
		}
		ready, count := false, 0
		for _, node := range nodes {
			if node.ID == opts.Manifest.ExecutorID {
				count++
				if node.Version != resolved.Manifest.Version || node.TeslaDelaySec != 2 || node.Currency != "TEST" {
					return ev, errors.New("executor metadata mismatch")
				}
				ready = node.Ready
			} else {
				return ev, errors.New("unexpected executor in owned dispatcher")
			}
		}
		if count > 1 {
			return ev, errors.New("duplicate registered executor")
		}
		if ready {
			break
		}
		if e := deps.poll(ctx); e != nil {
			return ev, e
		}
	}
	address, nonce, err := session.StartTarget(ctx)
	if err != nil {
		return ev, err
	}
	ev.Target.Address, ev.Target.Nonce = ptr(address), ptr(nonce)
	ev.Phase = "run"
	run := execCLI("run", "--wasm", resolved.Guest, "--executor", opts.Manifest.ExecutorID, "--allow", "127.0.0.1", "--duration", (time.Duration(opts.Manifest.Limits.ExecutionMS) * time.Millisecond).String(), "--floor-bps", "64000", "--ceil-bps", strconv.FormatInt(opts.Manifest.Limits.CeilingBPS, 10), "--wait", "--", address, nonce)
	if run.Started {
		ev.Submission = &SubmissionEvidence{State: "unobserved", OutcomeUnknown: true}
	}
	receipt, receiptErr := DecodeReceipt(run.Stdout)
	if !run.Started || receiptErr != nil || !validReceipt(receipt, opts.Manifest.ExecutorID) {
		return ev, errors.Join(errors.New("run receipt unavailable or invalid"), run.Err)
	}
	ev.Submission = &SubmissionEvidence{State: receipt.State, OutcomeUnknown: receipt.State == "submission_unknown"}
	if receipt.TransactionID != "" {
		ev.Submission.TransactionID = ptr(receipt.TransactionID)
	}
	if receipt.ID != "" {
		ev.RunID = ptr(receipt.ID)
	}
	if receipt.State == client.StateExited {
		ev.Terminal.State, ev.Terminal.Error = ptr(receipt.State), ptr("")
		if receipt.Error != "" {
			ev.Terminal.Error = ptr("workload reported an error")
		}
	}
	if run.Err != nil || receipt.State != client.StateExited || receipt.Error != "" {
		return ev, errors.Join(errors.New("run did not complete successfully"), run.Err)
	}
	if e := session.TargetACK(ctx); e != nil {
		ev.Target.ACK = ptr(false)
		return ev, e
	}
	ev.Target.ACK = ptr(true)
	ev.Phase = "output"
	ev.OutputMarkerSeen = ptr(false)
	var cursor int64
	var output []byte
	for {
		var status statusDocument
		if e := decodeCommand(execCLI("status", receipt.ID), &status); e != nil || status.ID != receipt.ID || status.ExecutorID != opts.Manifest.ExecutorID {
			return ev, errors.Join(errors.New("run status identity mismatch"), e)
		}
		if status.State == client.StateExited && status.Error != "" {
			ev.Terminal.Error = ptr("workload reported an error")
		}
		if status.State != client.StateExited || status.Error != "" {
			return ev, errors.New("run status is not successful terminal state")
		}
		var page client.LogPage
		if e := decodeCommand(execCLI("logs", "--after", strconv.FormatInt(cursor, 10), "--limit", "1", receipt.ID), &page); e != nil {
			return ev, e
		}
		if page.State == client.StateExited && page.Error != "" {
			ev.Terminal.Error = ptr("workload reported an error")
		}
		last := cursor
		for _, entry := range page.Logs {
			if entry.ID <= last || len(output)+len(entry.Output) > captureLimit {
				return ev, errors.New("invalid or excessive guest output")
			}
			last = entry.ID
			output = append(output, entry.Output...)
		}
		if page.After != last || len(page.Logs) == 0 && page.HasMore || page.State != client.StateExited || page.Error != "" {
			return ev, errors.New("invalid output page")
		}
		cursor = last
		if bytes.Contains(output, []byte("DEBUGLET_DEMO_OK "+nonce+"\n")) {
			ev.OutputMarkerSeen = ptr(true)
			break
		}
		if !page.HasMore {
			if e := deps.poll(ctx); e != nil {
				return ev, e
			}
		}
	}
	ev.Phase = "cleanup"
	stopCtx, endStop := context.WithTimeout(ctx, 5*time.Second)
	stopErr := session.StopExecutor(stopCtx)
	endStop()
	if stopErr != nil {
		return ev, stopErr
	}
	if e := session.CloseTarget(ctx); e != nil {
		return ev, e
	}
	registryCtx, endRegistry := context.WithTimeout(ctx, 20500*time.Millisecond)
	defer endRegistry()
	for {
		if e := registryCtx.Err(); e != nil {
			return ev, e
		}
		var current []client.Node
		if e := decodeCommand(execIn(registryCtx, "nodes"), &current); e != nil {
			return ev, e
		}
		eligible := false
		for _, node := range current {
			eligible = eligible || node.ID == opts.Manifest.ExecutorID && node.Ready
		}
		ev.Cleanup.RegistryIneligible = ptr(!eligible)
		if !eligible {
			return ev, nil
		}
		if e := deps.poll(registryCtx); e != nil {
			return ev, e
		}
	}
}
func validReceipt(r RunReceipt, executor string) bool {
	if r.ExecutorID != executor || r.ID != "" && !canonicalUUID(r.ID) || r.TransactionID != "" && !lowerHex(r.TransactionID, 32) {
		return false
	}
	switch r.State {
	case "submission_failed", "submission_unknown":
		return r.TransactionID != "" && r.ID == ""
	case "submitted", "RunStateUnspecified", "RunStateInitializing", "RunStateStarted", "RunStateUploading", "RunStateUploaded", client.StateExited:
		return r.ID != "" && r.TransactionID != ""
	default:
		return false
	}
}
func canonicalUUID(s string) bool {
	u, err := uuid.Parse(s)
	return err == nil && u != uuid.Nil && u.String() == s
}
func lowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, b := range s {
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return false
		}
	}
	return true
}
func decodeCommand(r commandResult, out any) error {
	if r.Err != nil {
		return errors.Join(errors.New("installed CLI command failed"), r.Err)
	}
	if !r.Started || len(r.Stdout) == 0 || len(r.Stdout) > captureLimit || bytes.Equal(bytes.TrimSpace(r.Stdout), []byte("null")) {
		return errors.New("installed CLI document unavailable")
	}
	if err := strictCLIDocument(r.Stdout, out); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(r.Stdout))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("invalid installed CLI document")
	}
	return nil
}
func pollContext(ctx context.Context) error {
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func safeFailure(phase string, err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return phase + ": interrupted"
	case errors.Is(err, context.DeadlineExceeded):
		return phase + ": deadline exceeded"
	case errors.Is(err, errInvalidInput):
		return phase + ": invalid local input or installation"
	default:
		return phase + ": compatibility check failed"
	}
}
func ptr[T any](v T) *T { return &v }

// candidateIdentities checks the identities the dispatcher reports beside its
// configured version. The HTTP contract must be the one this source tree
// publishes, and the build and the executor control protocol must both be
// named: an installed candidate that cannot say what it speaks is not a
// candidate this check can report on.
func candidateIdentities(server client.ServerVersion) bool {
	return server.APIVersion == apispec.Version && len(server.APIVersions) > 0 &&
		server.BinaryVersion != "" && server.ProtocolVersion != ""
}

type versionDocument struct {
	Module, Version, Revision string
	Modified                  bool
	Server                    *client.ServerVersion
}
type statusDocument struct {
	ID, State, Error string
	ExecutorID       string `json:"executor_id"`
}

// Installed CLI serialization is fixed. Check exact names/duplicates before
// Go's permissive case-insensitive struct matching can override observations.
func strictCLIDocument(data []byte, out any) error {
	if err := artifact.CheckUniqueJSON(data); err != nil {
		return errors.New("invalid CLI JSON structure")
	}
	switch out.(type) {
	case *versionDocument:
		fields, err := strictFields(data, []string{"module", "version", "revision", "modified", "server"}, nil, nil)
		if err != nil {
			return err
		}
		// The server object reports the dispatcher's separate identities. A
		// later CLI may add keys; this check pins what the candidate under
		// test emits, so an unannounced change is an observation, not a
		// silently ignored field.
		_, err = strictFields(fields["server"], []string{
			"version", "api_version", "api_versions", "binary_version", "binary_revision", "protocol_version",
		}, nil, nil)
		return err
	case *[]client.Node:
		var nodes []json.RawMessage
		if json.Unmarshal(data, &nodes) != nil || nodes == nil {
			return errors.New("invalid nodes JSON")
		}
		for _, node := range nodes {
			if _, err := strictFields(node, []string{"id", "ready", "last_seen", "version", "tesla_delay_sec", "tesla_anchor_timestamp_ns", "tesla_anchor_key", "price_per_bw", "currency"}, nil, map[string]bool{"tesla_anchor_key": true}); err != nil {
				return err
			}
		}
	case *statusDocument:
		_, err := strictFields(data, []string{"id", "state", "error", "executor_id"}, nil, nil)
		return err
	case *client.LogPage:
		fields, err := strictFields(data, []string{"state", "error", "after", "logs", "has_more"}, nil, map[string]bool{"logs": true})
		if err != nil {
			return err
		}
		var entries []json.RawMessage
		if json.Unmarshal(fields["logs"], &entries) != nil {
			return errors.New("invalid logs JSON")
		}
		for _, entry := range entries {
			if _, err := strictFields(entry, []string{"id", "timestamp", "output"}, nil, map[string]bool{"output": true}); err != nil {
				return err
			}
		}
	default:
		return errors.New("unsupported CLI document")
	}
	return nil
}

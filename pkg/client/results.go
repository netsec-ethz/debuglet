// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/wire"
)

type Result = wire.Result

// Export reads one result snapshot without waiting for execution or output to
// finish. An unknown outcome or incomplete output remains a successful export.
func (c *Client) Export(ctx context.Context, id string) (Result, error) {
	if err := validateJobID(id); err != nil {
		return Result{}, err
	}
	route := routeDebuglet + "/" + id + "/result"
	data, err := c.doWithLimit(ctx, http.MethodGet, route, nil, nil, http.StatusOK, wire.MaxResultBytes)
	if err != nil {
		return Result{}, err
	}
	doc, err := ReadResult(bytes.NewReader(data))
	if err != nil {
		return Result{}, c.protocolErr(http.MethodGet, route, err.Error())
	}
	if doc.RunID != id {
		return Result{}, c.protocolErr(http.MethodGet, route, "result belongs to another run")
	}
	return doc, nil
}

// ReadResult reads a saved export without a dispatcher or credentials. It
// validates format, bounds and consistency, not the authenticity of its author
// or the truth of measurements. No network requests are made.
func ReadResult(r io.Reader) (Result, error) {
	data, exceeded, err := readBounded(r, wire.MaxResultBytes)
	if err != nil {
		return Result{}, fmt.Errorf("read result: %w", err)
	}
	if exceeded {
		return Result{}, errors.New("result exceeds 32 MiB")
	}
	var doc Result
	if err := json.Unmarshal(data, &doc); err != nil {
		return Result{}, errors.New("malformed result JSON")
	}
	if err := validateResult(doc); err != nil {
		return Result{}, err
	}
	return doc, nil
}

func validateResult(doc Result) error {
	bad := func() error { return errors.New("inconsistent result document") }
	if doc.Format != wire.ResultFormat || doc.Version != wire.ResultVersion && doc.Version != wire.ResultVersion10 {
		return errors.New("unsupported result format or version")
	}
	if !resultUUID(doc.RunID) || strings.TrimSpace(doc.ExecutorID) == "" || strings.TrimSpace(doc.Outcome.State) == "" || doc.Timing.ObservedAt.IsZero() {
		return bad()
	}
	if doc.Attempt != nil && !resultBinding(*doc.Attempt) {
		return bad()
	}
	if t := doc.Timing; (t.ScheduledStart == nil) != (t.ReservedUntil == nil) || t.ScheduledStart != nil && (!t.ReservedUntil.After(*t.ScheduledStart) || t.ScheduledStart.IsZero()) {
		return bad()
	}
	// Formats 1.0 and 1.1 record none of these facts. They stay null so that a
	// later minor version can fill them without changing what an older file means.
	if doc.Outcome.ExitCode != nil || doc.Timing.StartedAt != nil || doc.Timing.FinishedAt != nil || doc.Timing.ClockUncertaintyNS != nil {
		return bad()
	}
	attribution := "unknown"
	if p := doc.Provenance; p != nil {
		if doc.Attempt == nil || p.RunID != doc.RunID || p.ExecutorID != doc.ExecutorID || p.Attempt != *doc.Attempt || p.AdmittedAt.IsZero() || !resultSHA256(p.WorkloadSHA256) || p.Arguments == nil || p.HostPolicy != "unknown" {
			return bad()
		}
		if p.AdmittedPolicy.FloorBW < 0 || p.AdmittedPolicy.CeilBW < p.AdmittedPolicy.FloorBW || p.AdmittedPolicy.TimeoutMS <= 0 {
			return bad()
		}
		attribution = "unenrolled_session"
		if p.CertificateSHA256 != nil {
			if !resultSHA256(*p.CertificateSHA256) {
				return bad()
			}
			attribution = "enrolled_at_admission"
		}
		for _, value := range []*string{p.ExecutorSoftware, p.DispatcherSoftware, p.DispatcherRevision} {
			if value != nil && strings.TrimSpace(*value) == "" {
				return bad()
			}
		}
		// Format 1.0 predates vantage_point; a 1.0 file carrying one would
		// change what an existing 1.0 file means.
		if v := p.VantagePoint; v != nil && (doc.Version == wire.ResultVersion10 || !validVantagePoint(*v)) {
			return bad()
		}
	}
	if doc.Verification.Attribution != attribution || doc.Verification.PacketEvidence != "unverified" || doc.Verification.MeasurementTruth != "unverified" {
		return bad()
	}
	var last int64
	for _, entry := range doc.Output.Entries {
		if entry.ID <= last {
			return bad()
		}
		if _, err := time.Parse(time.RFC3339Nano, entry.Timestamp); err != nil {
			return bad()
		}
		last = entry.ID
	}
	if doc.Output.Status.State == "" {
		return bad()
	}
	if err := validateOutput(LogPage{After: last, Logs: doc.Output.Entries, Output: doc.Output.Status}); err != nil {
		return bad()
	}
	if state := doc.Output.Status.State; state == "complete" || state == "truncated" {
		if *doc.Output.Status.FinalCursor != last {
			return bad()
		}
	}
	return nil
}

// A value and its source are recorded together or not at all, and a source is
// one of the defined labels; no label asserts verification.
func validVantagePoint(v wire.VantagePoint) bool {
	if !validIPMetadata(v.IPMetadata) {
		return false
	}
	source := func(value *string) bool {
		return value != nil && (*value == wire.SourceOperator || *value == wire.SourceExecutorReported || *value == wire.SourceDispatcherObserved)
	}
	d := v.Display
	for _, field := range []wire.LabelledString{v.SourceIP, v.PublicHost, d.DisplayName, d.City, d.Country, d.Network} {
		if (field.Value == nil) != (field.Source == nil) || field.Value != nil && (strings.TrimSpace(*field.Value) == "" || !source(field.Source)) {
			return false
		}
	}
	// Added within schema 1: an earlier 1.1 file omits it, which reads as null.
	if ia := v.SCIONISDAS; ia.Value == nil {
		if ia.Source != nil || ia.ObservedAt != nil || ia.Stale != nil {
			return false
		}
	} else if canonical, ok := wire.CanonicalISDAS(*ia.Value); !ok || canonical != *ia.Value || !source(ia.Source) || ia.ObservedAt == nil || ia.ObservedAt.IsZero() || ia.Stale == nil {
		return false
	}
	// Added within schema 1 with the executor probes; omitted reads as null.
	if !validReport(v.Clock, source, validClock) || !validReport(v.Platform, source, func(wire.HostPlatform) bool { return true }) {
		return false
	}
	c := v.Capabilities
	if c.Value == nil {
		return v.SchemaVersion == 1 && c.Source == nil && c.ObservedAt == nil && c.Stale == nil
	}
	if !source(c.Source) || c.ObservedAt == nil || c.ObservedAt.IsZero() || c.Stale == nil || c.Value.SchemaVersion != 1 || c.Value.Protocols == nil {
		return false
	}
	switch c.Value.EnforcementMode {
	case "", "ebpf", "fallback":
	default:
		return false
	}
	switch c.Value.EnforcementReason {
	case "":
	case "configured", "no_interface", "not_permitted", "unsupported", "attach_failed":
		if c.Value.EnforcementMode != "fallback" {
			return false
		}
	default:
		return false
	}
	if p := c.Value.ICMP; p != nil {
		switch {
		case p.State == "available" && p.Reason == "":
		case p.State == "unavailable" && slices.Contains([]string{"disabled", "not_permitted", "ping_socket_only", "unsupported"}, p.Reason):
		default:
			return false
		}
	}
	return v.SchemaVersion == 1
}

// validReport requires an expiring report and its labels together or not at
// all, and a valid value.
func validReport[T any](r wire.LabelledReport[T], source func(*string) bool, valid func(T) bool) bool {
	if r.Value == nil {
		return r.Source == nil && r.ObservedAt == nil && r.Stale == nil
	}
	return source(r.Source) && r.ObservedAt != nil && !r.ObservedAt.IsZero() && r.Stale != nil && valid(*r.Value)
}

func validClock(c wire.ClockReport) bool {
	switch c.State {
	case "synced", "unsynced", "unknown":
	default:
		return false
	}
	switch {
	case c.Readiness == "degraded" && (c.Reason == "unsynced" || c.Reason == "error_exceeds_bound"):
	case (c.Readiness == "ready" || c.Readiness == "unknown") && c.Reason == "":
	default:
		return false
	}
	for _, ns := range []*int64{c.EstimatedErrorNS, c.MaxErrorNS} {
		if ns != nil && *ns < 0 {
			return false
		}
	}
	return c.ErrorBoundNS > 0
}

func resultUUID(value string) bool { return isCanonicalUUID(value) && !isNilUUID(value) }
func resultBinding(binding ControlBinding) bool {
	return resultUUID(binding.DispatcherIncarnation) && resultUUID(binding.SessionID)
}
func resultSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && strings.ToLower(value) == value
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

// GetDebugletResult exports the retained record without contacting an executor
// or substituting current node observations for admission facts.
func (h *Handler) GetDebugletResult(c echo.Context) error {
	id, err := parseDebugletID(c.Param("id"))
	if err != nil {
		return err
	}
	if err := h.authorizeDebuglet(c, id); err != nil {
		return err
	}
	ctx := c.Request().Context()
	fail := func(err error) error {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to export result", err)
	}
	tooLarge := func() error {
		return apiError(http.StatusRequestEntityTooLarge, CodePayloadTooLarge, "result exceeds export limits; use paginated logs")
	}
	tx, err := h.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fail(err)
	}
	defer tx.Rollback()
	q := database.New(tx)
	run, err := q.GetDebugletByUUID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return debugletNotFound()
	}
	if err != nil {
		return fail(err)
	}
	doc := wire.Result{
		Format: wire.ResultFormat, Version: wire.ResultVersion,
		RunID: id.String(), ExecutorID: run.ExecutorID,
		Outcome:      wire.ResultOutcome{State: run.State.String(), Error: run.Error.String},
		Timing:       wire.ResultTiming{ObservedAt: time.Now().UTC()},
		Output:       wire.ResultOutput{Status: wire.OutputStatus{State: "unknown"}, Entries: []wire.LogEntry[[]byte]{}},
		Verification: wire.ResultVerification{Attribution: "unknown", PacketEvidence: "unverified", MeasurementTruth: "unverified"},
	}
	if run.DispatcherIncarnation != "" && run.SessionID != "" {
		doc.Attempt = &wire.ControlBinding{DispatcherIncarnation: run.DispatcherIncarnation, SessionID: run.SessionID}
	}
	if !run.StartTime.IsZero() && !run.EndTime.IsZero() {
		start, end := run.StartTime.UTC(), run.EndTime.UTC()
		doc.Timing.ScheduledStart, doc.Timing.ReservedUntil = &start, &end
	}
	provenanceLength, err := q.GetDebugletProvenanceSize(ctx, run.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fail(err)
	}
	provenanceSize := provenanceLength.Int64
	if err == nil && !provenanceLength.Valid {
		return fail(errors.New("invalid provenance length"))
	}
	if provenanceSize > wire.MaxResultBytes {
		return tooLarge()
	}
	size, err := q.GetResultOutputSize(ctx, run.ID)
	if err != nil {
		return fail(err)
	}
	// Bound allocations before loading payloads. The final encoded bound below
	// also accounts for per-entry fields and JSON escaping.
	if size.Bytes > wire.MaxResultBytes*3/4 || size.Frames > 65536 || provenanceSize > wire.MaxResultBytes-size.Bytes*4/3 {
		return tooLarge()
	}
	if provenanceSize > 0 {
		encoded, err := q.GetDebugletProvenance(ctx, id)
		if err != nil {
			return fail(err)
		}
		if err := json.Unmarshal([]byte(encoded), &doc.Provenance); err != nil {
			return fail(err)
		}
		if doc.Provenance == nil || doc.Provenance.RunID != doc.RunID || doc.Provenance.ExecutorID != doc.ExecutorID || doc.Attempt == nil || doc.Provenance.Attempt != *doc.Attempt {
			return fail(errors.New("inconsistent admission provenance"))
		}
		doc.Verification.Attribution = "unenrolled_session"
		if doc.Provenance.CertificateSHA256 != nil {
			doc.Verification.Attribution = "enrolled_at_admission"
		}
	}
	stored, err := q.GetDebugletOutput(ctx, id)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fail(err)
	}
	if err == nil && (stored.OutputVersion > 0 || stored.Status == "truncated") {
		doc.Output.Status.State, doc.Output.Status.LossReason = stored.Status, stored.Reason
		if stored.FinalCursor.Valid {
			doc.Output.Status.FinalCursor = &stored.FinalCursor.Int64
		}
	}
	logs, err := q.GetResultLogs(ctx, run.ID)
	if err != nil {
		return fail(err)
	}
	for _, entry := range logs {
		doc.Output.Entries = append(doc.Output.Entries, wire.LogEntry[[]byte]{ID: entry.ID, Timestamp: entry.Timestamp.UTC().Format(time.RFC3339Nano), Output: entry.Output})
	}
	if err := tx.Commit(); err != nil {
		return fail(err)
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		return fail(err)
	}
	if len(encoded) > wire.MaxResultBytes {
		return tooLarge()
	}
	return c.JSONBlob(http.StatusOK, encoded)
}

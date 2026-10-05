// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

func submittedConfiguration(r DebugletRequest) (*wire.SubmittedConfiguration, error) {
	if len(r.Label) > 120 || len(r.ProgramName) > 256 {
		return nil, errors.New("label and program_name are limited to 120 and 256 bytes")
	}
	doc := &wire.SubmittedConfiguration{Label: r.Label, ProgramName: r.ProgramName,
		RequestedStart: r.StartTimestamp, Args: append([]string{}, r.Args...), Policy: r.Policy}
	doc.Policy.Addresses = append([]string{}, r.Policy.Addresses...)
	encoded, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	if len(encoded) > 256<<10 {
		return nil, errors.New("submitted configuration exceeds 256 KiB excluding program bytes")
	}
	return doc, nil
}

func measurementFailure(err error) error {
	return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to load measurement", err)
}

func runDetail(ctx context.Context, q *database.Queries, run database.Debuglet) (wire.RunDetail, error) {
	detail := wire.RunDetail{RunID: run.Uuid.String(), ExecutorID: run.ExecutorID,
		BatchID: run.TransactionID, OrderID: run.OrderID,
		Outcome: wire.ResultOutcome{State: run.State.String(), Error: dispatcher.PublicTerminalError(run.Error.String)},
		Timing:  wire.ResultTiming{ObservedAt: time.Now().UTC()}}
	if !run.StartTime.IsZero() && !run.EndTime.IsZero() {
		start, end := run.StartTime.UTC(), run.EndTime.UTC()
		detail.Timing.ScheduledStart, detail.Timing.ReservedUntil = &start, &end
	}
	provenance, err := q.GetDebugletProvenance(ctx, run.Uuid)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return detail, err
	}
	if err == nil {
		if err := json.Unmarshal([]byte(provenance), &detail.Provenance); err != nil {
			return detail, err
		}
		if detail.Provenance == nil || detail.Provenance.RunID != detail.RunID || detail.Provenance.ExecutorID != detail.ExecutorID {
			return detail, errors.New("inconsistent admission provenance")
		}
	}
	requested, err := q.GetMeasurementRequest(ctx, run.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return detail, err
	}
	if err == nil {
		if err := json.Unmarshal([]byte(requested), &detail.Submitted); err != nil {
			return detail, err
		}
	}
	execution, err := q.GetMeasurementExecution(ctx, run.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return detail, err
	}
	if err == nil {
		observed := &wire.RunExecution{TimeSource: wire.SourceDispatcherObserved}
		if execution.StartedObservedNs.Valid {
			value := time.Unix(0, execution.StartedObservedNs.Int64).UTC()
			observed.StartedObservedAt = &value
		}
		if execution.TerminalObservedNs.Valid {
			value := time.Unix(0, execution.TerminalObservedNs.Int64).UTC()
			observed.TerminalObservedAt = &value
		}
		if execution.ExitCode.Valid {
			value := int32(execution.ExitCode.Int64)
			observed.ReportedExitCode = &value
		}
		if execution.TcpEndpoint != "" {
			observed.TCPListener = &execution.TcpEndpoint
		}
		observed.ListenerReady = observed.TCPListener != nil && observed.StartedObservedAt != nil && observed.TerminalObservedAt == nil && run.State == models.RunStateStarted && time.Now().Before(run.EndTime.Time)
		detail.Execution = observed
	}
	order, err := q.GetDebugletOrder(ctx, database.GetDebugletOrderParams{TransactionID: run.TransactionID, OrderID: run.OrderID})
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return detail, err
	}
	if err == nil {
		cost := &wire.RunCost{Currency: order.Currency, Unit: currencyUnit(order.Currency),
			Reserved: strconv.FormatInt(order.Price, 10), Settlement: orderSettlement(order.State)}
		switch cost.Settlement {
		case "credited":
			charged := cost.Reserved
			cost.Charged = &charged
		case "refunded":
			charged := "0"
			cost.Charged = &charged
		}
		detail.Cost = cost
	}
	return detail, nil
}

// GetRunDetail reads configuration without loading output. Result exports and
// paginated logs remain separate, so a large output never hides configuration.
func (h *Handler) GetRunDetail(c echo.Context) error {
	id, err := parseDebugletID(c.Param("id"))
	if err != nil {
		return err
	}
	if err := h.authorizeDebuglet(c, id); err != nil {
		return err
	}
	ctx := c.Request().Context()
	tx, err := h.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return measurementFailure(err)
	}
	defer tx.Rollback()
	q := database.New(tx)
	if err := requireRetainedPayload(ctx, q, id); err != nil {
		return err
	}
	run, err := q.GetDebugletByUUID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return debugletNotFound()
	}
	if err != nil {
		return measurementFailure(err)
	}
	length, err := q.GetDebugletProvenanceSize(ctx, run.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return measurementFailure(err)
	}
	tooLarge := func() error {
		return apiError(http.StatusRequestEntityTooLarge, CodePayloadTooLarge, "run detail exceeds 32 MiB")
	}
	if length.Int64 > wire.MaxRunDetailBytes {
		return tooLarge()
	}
	detail, err := runDetail(ctx, q, run)
	if err != nil {
		return measurementFailure(err)
	}
	if err := tx.Commit(); err != nil {
		return measurementFailure(err)
	}
	encoded, err := json.Marshal(detail)
	if err != nil {
		return measurementFailure(err)
	}
	if len(encoded) > wire.MaxRunDetailBytes {
		return tooLarge()
	}
	return c.JSONBlob(http.StatusOK, encoded)
}

func (h *Handler) GetMeasurement(c echo.Context) error {
	caller, err := requireAccount(c)
	if err != nil {
		return err
	}
	limit, err := pageNumber(c, "limit", 25, 100)
	if err != nil {
		return err
	}
	if limit == 0 {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "limit must be positive")
	}
	offset, err := pageNumber(c, "offset", 0, 1000000)
	if err != nil {
		return err
	}
	ctx := c.Request().Context()
	tx, err := h.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return measurementFailure(err)
	}
	defer tx.Rollback()
	q := database.New(tx)
	total, err := q.MeasurementRunCount(ctx, database.MeasurementRunCountParams{BatchID: c.Param("id"), UserUuid: caller.UserUUID})
	if err != nil {
		return measurementFailure(err)
	}
	if total == 0 {
		return apiError(http.StatusNotFound, CodeNotFound, "measurement not found")
	}
	runs, err := q.MeasurementRuns(ctx, database.MeasurementRunsParams{BatchID: c.Param("id"), UserUuid: caller.UserUUID, PageLimit: limit, PageOffset: offset})
	if err != nil {
		return measurementFailure(err)
	}
	doc := wire.Measurement{ID: c.Param("id"), Runs: make([]wire.MeasurementRun, 0, len(runs)), Total: total, Limit: limit, Offset: offset}
	for _, run := range runs {
		doc.Runs = append(doc.Runs, wire.MeasurementRun{RunID: run.Uuid.String(), ExecutorID: run.ExecutorID, OrderID: run.OrderID, State: run.State.String(), Label: run.Label, ProgramName: run.ProgramName})
	}
	if err := tx.Commit(); err != nil {
		return measurementFailure(err)
	}
	return c.JSON(http.StatusOK, doc)
}

func pageNumber(c echo.Context, name string, fallback, maximum int64) (int64, error) {
	text := c.QueryParam(name)
	if text == "" {
		return fallback, nil
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil || value < 0 || value > maximum {
		return 0, apiError(http.StatusBadRequest, CodeInvalidRequest, fmt.Sprintf("%s must be between 0 and %d", name, maximum))
	}
	return value, nil
}

func (h *Handler) ListMeasurements(c echo.Context) error {
	caller, err := requireAccount(c)
	if err != nil {
		return err
	}
	limit, err := pageNumber(c, "limit", 25, 100)
	if err != nil {
		return err
	}
	if limit == 0 {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "limit must be positive")
	}
	offset, err := pageNumber(c, "offset", 0, 1000000)
	if err != nil {
		return err
	}
	state, search := c.QueryParam("state"), c.QueryParam("search")
	if state != "" && state != "running" && state != "unknown" && state != "failed" && state != "succeeded" {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "unsupported measurement state filter")
	}
	if len(search) > 120 {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "measurement search exceeds 120 bytes")
	}
	ctx := c.Request().Context()
	tx, err := h.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return measurementFailure(err)
	}
	defer tx.Rollback()
	q := database.New(tx)
	rows, err := q.ListMeasurements(ctx, database.ListMeasurementsParams{UserUuid: caller.UserUUID, State: state, Search: search, PageLimit: limit, PageOffset: offset})
	if err != nil {
		return measurementFailure(err)
	}
	counts, err := q.MeasurementCounts(ctx, database.MeasurementCountsParams{UserUuid: caller.UserUUID, Search: search})
	if err != nil {
		return measurementFailure(err)
	}
	page := wire.MeasurementPage{Measurements: make([]wire.MeasurementSummary, 0, len(rows)), Counts: map[string]int64{"running": 0, "succeeded": 0, "failed": 0, "unknown": 0}, Limit: limit, Offset: offset}
	for _, count := range counts {
		page.Counts[count.State] = count.Count
		if state == "" || state == count.State {
			page.Total += count.Count
		}
	}
	for _, row := range rows {
		page.Measurements = append(page.Measurements, wire.MeasurementSummary{ID: row.ID, Label: row.Label, State: row.State, Children: row.Children, ScheduledStart: row.ScheduledStart.UTC()})
	}
	if err := tx.Commit(); err != nil {
		return measurementFailure(err)
	}
	return c.JSON(http.StatusOK, page)
}

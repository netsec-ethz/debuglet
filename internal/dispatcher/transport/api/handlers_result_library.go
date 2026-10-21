// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

func (h *Handler) registerResultLibraryRoutes(e *echo.Echo) {
	e.GET("/result-highlights", h.ListResultHighlights)
	e.POST("/result-highlights", h.PostResultHighlight)
	e.GET("/result-highlights/:id", h.GetResultHighlight)
	e.PATCH("/result-highlights/:id", h.PatchResultHighlight)
	e.DELETE("/result-highlights/:id", h.DeleteResultHighlight)
	e.POST("/measurements/:id/source", h.PostMeasurementSource)
	e.GET("/runs/:id/source", h.GetRunSource)
}

type highlightMetadata struct {
	Name       string `json:"name"`
	Note       string `json:"note,omitempty"`
	Collection string `json:"collection,omitempty"`
}

func (m *highlightMetadata) validate() error {
	m.Name = strings.TrimSpace(m.Name)
	m.Collection = strings.TrimSpace(m.Collection)
	if m.Name == "" || len(m.Name) > 120 || len(m.Note) > 2000 || len(m.Collection) > 120 {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "name must be 1–120 bytes, note at most 2000 bytes and collection at most 120 bytes")
	}
	return nil
}
func libraryFailure(err error) error {
	return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to read or save result library", err)
}
func highlightNotFound() error {
	return apiError(http.StatusNotFound, CodeNotFound, "saved result not found")
}

func highlightSummary(row database.GetResultHighlightRow, account *caller) wire.HighlightSummary {
	return wire.HighlightSummary{ID: row.ID, Name: row.Name, Note: row.Note, Collection: row.Collection, ProjectID: row.ProjectID.String,
		CreatedBy: row.CreatorID, CreatedAt: time.Unix(row.CreatedAt, 0).UTC(), CanManage: row.CanManage == 1 && (!account.API || credentialAllows(account.Scopes, http.MethodPatch, "/result-highlights/:id")), RunID: row.RunID,
		MeasurementID: row.MeasurementID, EventIndex: row.EventIndex, EventSHA256: row.EventSha256, NodeID: row.NodeID, Block: row.Block}
}

// Reads run output only after its retained byte and frame counts are bounded.
// The bookmark stores no second copy of that output.
func highlightEvent(ctx context.Context, q *database.Queries, runID uuid.UUID, index int64) (json.RawMessage, string, string, error) {
	if err := requireRetainedPayload(ctx, q, runID); err != nil {
		return nil, "", "", err
	}
	run, err := q.GetDebugletByUUID(ctx, runID)
	if err != nil {
		return nil, "", "", libraryFailure(err)
	}
	size, err := q.GetResultOutputSize(ctx, run.ID)
	if err != nil {
		return nil, "", "", libraryFailure(err)
	}
	if size.Bytes > wire.MaxResultBytes*3/4 || size.Frames > 65536 {
		return nil, "", "", apiError(http.StatusRequestEntityTooLarge, CodePayloadTooLarge, "output exceeds the result library limit; use paginated logs")
	}
	logs, err := q.GetResultLogs(ctx, run.ID)
	if err != nil {
		return nil, "", "", libraryFailure(err)
	}
	output := make([]byte, 0, size.Bytes)
	for _, entry := range logs {
		output = append(output, entry.Output...)
	}
	if !utf8.Valid(output) {
		return nil, "", "", apiError(http.StatusBadRequest, CodeInvalidRequest, "output is not valid UTF-8; save a result from a structured UTF-8 workflow")
	}
	event, node, block := retainedWorkflowEvent(output, index)
	if event == nil {
		return nil, "", "", apiError(http.StatusBadRequest, CodeInvalidRequest, "event_index does not identify a complete retained workflow event")
	}
	return event, node, block, nil
}

func (h *Handler) PostResultHighlight(c echo.Context) error {
	account, err := requireAccount(c)
	if err != nil {
		return err
	}
	var input struct {
		highlightMetadata
		RunID      string `json:"run_id"`
		EventIndex *int64 `json:"event_index"`
		ProjectID  string `json:"project_id,omitempty"`
	}
	c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, 8192)
	if err := decodeMeasurementRequest(c, &input); err != nil {
		return err
	}
	if err := input.validate(); err != nil {
		return err
	}
	if input.EventIndex == nil || *input.EventIndex < 0 || *input.EventIndex >= 1000 || len(input.ProjectID) > 256 {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "event_index must be between 0 and 999 and project_id at most 256 bytes")
	}
	id, err := parseDebugletID(input.RunID)
	if err != nil {
		return err
	}
	if _, err := h.authorizeDebugletRead(c, id); err != nil {
		return err
	}
	ctx := c.Request().Context()
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return libraryFailure(err)
	}
	defer tx.Rollback()
	q := database.New(tx)
	event, node, block, err := highlightEvent(ctx, q, id, *input.EventIndex)
	if err != nil {
		return err
	}
	var record map[string]json.RawMessage
	if err := json.Unmarshal(event, &record); err != nil {
		return libraryFailure(err)
	}
	var status string
	if err := json.Unmarshal(record["status"], &status); err != nil {
		return libraryFailure(err)
	}
	switch block {
	case "report_metric", "report_table", "report_chart", "report_text", "emit":
	default:
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "only completed report and emit events can be saved")
	}
	if status != "completed" {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "only completed report and emit events can be saved")
	}
	savedID := uuid.NewString()
	n, err := q.CreateResultHighlight(ctx, database.CreateResultHighlightParams{ID: savedID, UserUuid: account.UserUUID, RunUuid: id, ProjectID: sql.NullString{String: input.ProjectID, Valid: input.ProjectID != ""}, EventIndex: *input.EventIndex, EventSha256: communityDocumentDigest(event), NodeID: node, Block: block, Name: input.Name, Note: input.Note, Collection: input.Collection, CreatedAt: time.Now().Unix()})
	if err != nil {
		return libraryFailure(err)
	}
	if n != 1 {
		return apiError(http.StatusConflict, CodeInvalidRequest, "source is not shared in that project, access changed, or the 1024 saved-result limit was reached")
	}
	row, err := q.GetResultHighlight(ctx, database.GetResultHighlightParams{ID: savedID, UserUuid: account.UserUUID.String()})
	if err != nil {
		return libraryFailure(err)
	}
	result := wire.Highlight{HighlightSummary: highlightSummary(row, account), Event: event}
	if err := tx.Commit(); err != nil {
		return libraryFailure(err)
	}
	return c.JSON(http.StatusCreated, result)
}

func (h *Handler) ListResultHighlights(c echo.Context) error {
	account, err := requireAccount(c)
	if err != nil {
		return err
	}
	project, search, collection := c.QueryParam("project_id"), c.QueryParam("search"), c.QueryParam("collection")
	if len(project) > 256 || len(search) > 256 || len(collection) > 120 {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "library filters exceed their size limits")
	}
	if project != "" {
		if _, err := h.requireCommunityProject(c, project); err != nil {
			return err
		}
	}
	limit, offset := int64(25), int64(0)
	for name, target := range map[string]*int64{"limit": &limit, "offset": &offset} {
		if v := c.QueryParam(name); v != "" {
			*target, err = strconv.ParseInt(v, 10, 64)
			if err != nil {
				return apiError(http.StatusBadRequest, CodeInvalidRequest, "limit and offset must be integers")
			}
		}
	}
	if limit < 1 || limit > 100 || offset < 0 || offset > 1000000 {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "limit must be 1–100 and offset 0–1000000")
	}
	ctx := c.Request().Context()
	tx, err := h.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return libraryFailure(err)
	}
	defer tx.Rollback()
	q := database.New(tx)
	total, err := q.CountResultHighlights(ctx, database.CountResultHighlightsParams{UserUuid: account.UserUUID.String(), ProjectID: project, Search: search, Collection: collection})
	if err != nil {
		return libraryFailure(err)
	}
	rows, err := q.ListResultHighlights(ctx, database.ListResultHighlightsParams{UserUuid: account.UserUUID.String(), ProjectID: project, Search: search, Collection: collection, PageLimit: limit, PageOffset: offset})
	if err != nil {
		return libraryFailure(err)
	}
	page := wire.HighlightPage{Highlights: make([]wire.HighlightSummary, 0, len(rows)), Total: total, Limit: limit, Offset: offset}
	for _, row := range rows {
		page.Highlights = append(page.Highlights, highlightSummary(database.GetResultHighlightRow(row), account))
	}
	if err := tx.Commit(); err != nil {
		return libraryFailure(err)
	}
	return c.JSON(http.StatusOK, page)
}

func (h *Handler) GetResultHighlight(c echo.Context) error {
	account, err := requireAccount(c)
	if err != nil {
		return err
	}
	ctx := c.Request().Context()
	tx, err := h.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return libraryFailure(err)
	}
	defer tx.Rollback()
	q := database.New(tx)
	row, err := q.GetResultHighlight(ctx, database.GetResultHighlightParams{ID: c.Param("id"), UserUuid: account.UserUUID.String()})
	if errors.Is(err, sql.ErrNoRows) {
		return highlightNotFound()
	}
	if err != nil {
		return libraryFailure(err)
	}
	runID, err := uuid.Parse(row.RunID)
	if err != nil {
		return libraryFailure(err)
	}
	event, _, _, err := highlightEvent(ctx, q, runID, row.EventIndex)
	if err != nil {
		return err
	}
	if communityDocumentDigest(event) != row.EventSha256 {
		return apiError(http.StatusConflict, CodeInvalidRequest, "saved output no longer matches its retained occurrence")
	}
	result := wire.Highlight{HighlightSummary: highlightSummary(row, account), Event: event}
	source, err := getRunSource(ctx, tx, runID, account.UserUUID)
	if err == nil {
		result.Source = &source.SourceReference
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err := tx.Commit(); err != nil {
		return libraryFailure(err)
	}
	return c.JSON(http.StatusOK, result)
}

func (h *Handler) PatchResultHighlight(c echo.Context) error {
	account, err := requireAccount(c)
	if err != nil {
		return err
	}
	var input highlightMetadata
	c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, 8192)
	if err := decodeMeasurementRequest(c, &input); err != nil {
		return err
	}
	if err := input.validate(); err != nil {
		return err
	}
	n, err := database.New(h.db).UpdateResultHighlight(c.Request().Context(), database.UpdateResultHighlightParams{ID: c.Param("id"), UserUuid: account.UserUUID.String(), Name: input.Name, Note: input.Note, Collection: input.Collection})
	if err != nil {
		return libraryFailure(err)
	}
	if n != 1 {
		return highlightNotFound()
	}
	return h.GetResultHighlight(c)
}
func (h *Handler) DeleteResultHighlight(c echo.Context) error {
	account, err := requireAccount(c)
	if err != nil {
		return err
	}
	n, err := database.New(h.db).DeleteResultHighlight(c.Request().Context(), database.DeleteResultHighlightParams{ID: c.Param("id"), UserUuid: account.UserUUID.String()})
	if err != nil {
		return libraryFailure(err)
	}
	if n != 1 {
		return highlightNotFound()
	}
	return c.NoContent(http.StatusNoContent)
}

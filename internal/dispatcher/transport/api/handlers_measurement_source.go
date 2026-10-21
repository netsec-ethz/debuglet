// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

const maxMeasurementSourceBytes = 4 << 20

// PostMeasurementSource records the owner's source association after admission.
// Matching program digests identify the submitted modules, not compiler proof.
func (h *Handler) PostMeasurementSource(c echo.Context) error {
	account, err := requireAccount(c)
	if err != nil {
		return err
	}
	var input struct {
		Kind     string               `json:"kind"`
		Document json.RawMessage      `json:"document"`
		Programs []wire.SourceProgram `json:"programs"`
	}
	c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, maxMeasurementSourceBytes)
	if err := decodeMeasurementRequest(c, &input); err != nil {
		return err
	}
	if len(input.Programs) == 0 || len(input.Programs) > 1024 {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "source must identify each admitted run and its program")
	}
	document, _, err := validateCommunityDocument(input.Kind, input.Document, nil)
	if err != nil {
		return err
	}
	for i := range input.Programs {
		id, err := uuid.Parse(input.Programs[i].RunID)
		if err != nil || len(input.Programs[i].SHA256) != 64 || strings.Trim(input.Programs[i].SHA256, "0123456789abcdef") != "" {
			return apiError(http.StatusBadRequest, CodeInvalidRequest, "programs require valid run IDs and lowercase SHA256 digests")
		}
		input.Programs[i].RunID = id.String()
	}
	sort.Slice(input.Programs, func(i, j int) bool { return input.Programs[i].RunID < input.Programs[j].RunID })
	ctx := c.Request().Context()
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return libraryFailure(err)
	}
	defer tx.Rollback()
	var total, owned int
	err = tx.QueryRowContext(ctx, `SELECT count(*), COALESCE(sum(EXISTS (
 SELECT 1 FROM debuglet_users du JOIN users u ON u.id=du.user_id
 WHERE du.debuglet_id=d.id AND u.uuid=?)),0) FROM debuglets d WHERE d.transaction_id=?`, account.UserUUID, c.Param("id")).Scan(&total, &owned)
	if err != nil {
		return libraryFailure(err)
	}
	if total == 0 || total != owned {
		return debugletNotFound()
	}
	if len(input.Programs) != total {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "programs must identify every admitted run exactly once")
	}
	q := database.New(tx)
	for i, program := range input.Programs {
		if i > 0 && input.Programs[i-1].RunID == program.RunID {
			return apiError(http.StatusBadRequest, CodeInvalidRequest, "programs must identify every admitted run exactly once")
		}
		id := uuid.MustParse(program.RunID)
		var digest string
		err = tx.QueryRowContext(ctx, `SELECT COALESCE(json_extract(p.document,'$.workload_sha256'),'')
 FROM debuglets d LEFT JOIN debuglet_provenance p ON p.debuglet_id=d.id
 WHERE d.uuid=? AND d.transaction_id=?`, id, c.Param("id")).Scan(&digest)
		if errors.Is(err, sql.ErrNoRows) {
			return apiError(http.StatusBadRequest, CodeInvalidRequest, "program does not belong to this measurement")
		}
		if err != nil {
			return libraryFailure(err)
		}
		if err := requireRetainedPayload(ctx, q, id); err != nil {
			return err
		}
		if digest != program.SHA256 {
			return apiError(http.StatusBadRequest, CodeInvalidRequest, "program does not match retained admission provenance")
		}
	}
	programs, _ := json.Marshal(input.Programs)
	var oldKind, oldDocument, oldPrograms string
	err = tx.QueryRowContext(ctx, "SELECT kind,document,programs FROM measurement_sources WHERE measurement_id=?", c.Param("id")).Scan(&oldKind, &oldDocument, &oldPrograms)
	status := http.StatusCreated
	if err == nil {
		if oldKind != input.Kind || !bytes.Equal([]byte(oldDocument), document) || oldPrograms != string(programs) {
			return communityConflict("this measurement already has a different immutable source")
		}
		status = http.StatusOK
	} else if errors.Is(err, sql.ErrNoRows) {
		result, err := tx.ExecContext(ctx, `INSERT INTO measurement_sources(measurement_id,user_id,kind,document,document_sha256,programs)
 SELECT ?,u.id,?,?,?,? FROM users u WHERE u.uuid=?
 AND (SELECT count(*) FROM measurement_sources s WHERE s.user_id=u.id)<1024
 AND COALESCE((SELECT sum(length(CAST(s.document AS BLOB))+length(CAST(s.programs AS BLOB)))
 FROM measurement_sources s WHERE s.user_id=u.id),0)+?<=268435456`, c.Param("id"), input.Kind, string(document), communityDocumentDigest(document), string(programs), account.UserUUID, len(document)+len(programs))
		if err != nil {
			return libraryFailure(err)
		}
		n, err := result.RowsAffected()
		if err != nil {
			return libraryFailure(err)
		}
		if n != 1 {
			return communityConflict("saved source exceeds the account limit of 1024 measurements or 256 MiB")
		}
	} else {
		return libraryFailure(err)
	}
	if err := tx.Commit(); err != nil {
		return libraryFailure(err)
	}
	return c.JSON(status, wire.SourceDocument{
		SourceReference: wire.SourceReference{Kind: input.Kind, DocumentSHA256: communityDocumentDigest(document), MeasurementID: c.Param("id")},
		Document:        document, Programs: input.Programs,
	})
}

func (h *Handler) GetRunSource(c echo.Context) error {
	account, err := requireAccount(c)
	if err != nil {
		return err
	}
	id, err := parseDebugletID(c.Param("id"))
	if err != nil {
		return err
	}
	tx, err := h.db.BeginTx(c.Request().Context(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return libraryFailure(err)
	}
	defer tx.Rollback()
	source, err := getRunSource(c.Request().Context(), tx, id, account.UserUUID)
	if errors.Is(err, sql.ErrNoRows) {
		return apiError(http.StatusNotFound, CodeNotFound, "original builder source is unavailable for this run")
	}
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, source)
}

// getRunSource checks both run visibility and current membership in the same
// snapshot as its source lookup. A shared revision is never read after removal.
func getRunSource(ctx context.Context, tx *sql.Tx, runID, callerID uuid.UUID) (*wire.SourceDocument, error) {
	var measurementID string
	err := tx.QueryRowContext(ctx, `SELECT d.transaction_id FROM debuglets d WHERE d.uuid=? AND (
 EXISTS (SELECT 1 FROM debuglet_users du JOIN users u ON u.id=du.user_id WHERE du.debuglet_id=d.id AND u.uuid=?)
 OR EXISTS (SELECT 1 FROM community_measurements cm JOIN community_projects p ON p.id=cm.project_id
 JOIN community_members m ON m.community_id=p.community_id JOIN users u ON u.id=m.user_id
 WHERE cm.measurement_id=d.transaction_id AND u.uuid=?))`, runID, callerID, callerID).Scan(&measurementID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, debugletNotFound()
	}
	if err != nil {
		return nil, libraryFailure(err)
	}
	if err := requireRetainedPayload(ctx, database.New(tx), runID); err != nil {
		return nil, err
	}
	source := &wire.SourceDocument{SourceReference: wire.SourceReference{MeasurementID: measurementID}}
	var document, programs string
	err = tx.QueryRowContext(ctx, `SELECT kind,document,document_sha256,programs FROM measurement_sources WHERE measurement_id=?`, measurementID).
		Scan(&source.Kind, &document, &source.DocumentSHA256, &programs)
	if err == nil {
		if err := json.Unmarshal([]byte(programs), &source.Programs); err != nil {
			return nil, libraryFailure(err)
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		err = tx.QueryRowContext(ctx, `SELECT r.kind,r.document,r.experiment_id,r.revision
 FROM community_measurements cm JOIN community_experiment_revisions r
 ON r.experiment_id=cm.experiment_id AND r.revision=cm.experiment_revision
 JOIN community_projects p ON p.id=cm.project_id JOIN community_members m ON m.community_id=p.community_id
 JOIN users u ON u.id=m.user_id WHERE cm.measurement_id=? AND u.uuid=?
 ORDER BY cm.shared_at,cm.project_id LIMIT 1`, measurementID, callerID).
			Scan(&source.Kind, &document, &source.CommunityExperimentID, &source.Revision)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		if err != nil {
			return nil, libraryFailure(err)
		}
		source.DocumentSHA256 = communityDocumentDigest([]byte(document))
		source.Programs = []wire.SourceProgram{}
		rows, err := tx.QueryContext(ctx, `SELECT d.uuid,json_extract(p.document,'$.workload_sha256')
 FROM debuglets d JOIN debuglet_provenance p ON p.debuglet_id=d.id
 WHERE d.transaction_id=? AND NOT EXISTS (SELECT 1 FROM payload_tombstones t WHERE t.debuglet_id=d.id)
 ORDER BY d.uuid LIMIT 1024`, measurementID)
		if err != nil {
			return nil, libraryFailure(err)
		}
		defer rows.Close()
		for rows.Next() {
			var program wire.SourceProgram
			if err := rows.Scan(&program.RunID, &program.SHA256); err != nil {
				return nil, libraryFailure(err)
			}
			source.Programs = append(source.Programs, program)
		}
		if err := rows.Err(); err != nil {
			return nil, libraryFailure(err)
		}
	} else {
		return nil, libraryFailure(err)
	}
	source.Document = json.RawMessage(document)
	return source, nil
}

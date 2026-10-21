// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// Package measurementsource retains the builder source associated with admitted
// runs. Ownership, provenance, retention and quotas are checked in the same
// transaction as the write; reads check sharing in the source lookup snapshot.
package measurementsource

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/studio"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

// Input identifies the source and every admitted program it describes.
type Input struct {
	Kind     string               `json:"kind"`
	Document json.RawMessage      `json:"document"`
	Programs []wire.SourceProgram `json:"programs"`
}

// Store attaches immutable source to an owner's admitted measurement.
type Store struct{ DB *sql.DB }

// Save returns the canonical source and whether this call created it. Repeating
// an identical attachment is allowed; a different source cannot replace it.
func (s Store) Save(ctx context.Context, ownerID uuid.UUID, measurementID string, input Input) (wire.SourceDocument, bool, error) {
	// Normalize a private copy, leaving the caller's program order untouched.
	input.Programs = append([]wire.SourceProgram(nil), input.Programs...)
	if len(input.Programs) == 0 || len(input.Programs) > 1024 {
		return wire.SourceDocument{}, false, invalid("source must identify each admitted run and its program")
	}
	document, _, err := studio.ValidateDocument(input.Kind, input.Document, nil)
	if err != nil {
		return wire.SourceDocument{}, false, invalid(err.Error())
	}
	for i := range input.Programs {
		id, err := uuid.Parse(input.Programs[i].RunID)
		if err != nil || len(input.Programs[i].SHA256) != 64 || strings.Trim(input.Programs[i].SHA256, "0123456789abcdef") != "" {
			return wire.SourceDocument{}, false, invalid("programs require valid run IDs and lowercase SHA256 digests")
		}
		input.Programs[i].RunID = id.String()
	}
	sort.Slice(input.Programs, func(i, j int) bool { return input.Programs[i].RunID < input.Programs[j].RunID })
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return wire.SourceDocument{}, false, err
	}
	defer tx.Rollback()
	var total, owned int
	err = tx.QueryRowContext(ctx, `SELECT count(*), COALESCE(sum(EXISTS (
 SELECT 1 FROM debuglet_users du JOIN users u ON u.id=du.user_id
 WHERE du.debuglet_id=d.id AND u.uuid=?)),0) FROM debuglets d WHERE d.transaction_id=?`, ownerID, measurementID).Scan(&total, &owned)
	if err != nil {
		return wire.SourceDocument{}, false, err
	}
	if total == 0 || total != owned {
		return wire.SourceDocument{}, false, ErrNotFound
	}
	if len(input.Programs) != total {
		return wire.SourceDocument{}, false, invalid("programs must identify every admitted run exactly once")
	}
	q := database.New(tx)
	for i, program := range input.Programs {
		if i > 0 && input.Programs[i-1].RunID == program.RunID {
			return wire.SourceDocument{}, false, invalid("programs must identify every admitted run exactly once")
		}
		id := uuid.MustParse(program.RunID)
		var digest string
		err = tx.QueryRowContext(ctx, `SELECT COALESCE(json_extract(p.document,'$.workload_sha256'),'')
 FROM debuglets d LEFT JOIN debuglet_provenance p ON p.debuglet_id=d.id
 WHERE d.uuid=? AND d.transaction_id=?`, id, measurementID).Scan(&digest)
		if errors.Is(err, sql.ErrNoRows) {
			return wire.SourceDocument{}, false, invalid("program does not belong to this measurement")
		}
		if err != nil {
			return wire.SourceDocument{}, false, err
		}
		if err := requireRetainedPayload(ctx, q, id); err != nil {
			return wire.SourceDocument{}, false, err
		}
		if digest != program.SHA256 {
			return wire.SourceDocument{}, false, invalid("program does not match retained admission provenance")
		}
	}
	programs, _ := json.Marshal(input.Programs)
	var oldKind, oldDocument, oldPrograms string
	err = tx.QueryRowContext(ctx, "SELECT kind,document,programs FROM measurement_sources WHERE measurement_id=?", measurementID).Scan(&oldKind, &oldDocument, &oldPrograms)
	created := true
	if err == nil {
		if oldKind != input.Kind || !bytes.Equal([]byte(oldDocument), document) || oldPrograms != string(programs) {
			return wire.SourceDocument{}, false, conflict("this measurement already has a different immutable source")
		}
		created = false
	} else if errors.Is(err, sql.ErrNoRows) {
		result, err := tx.ExecContext(ctx, `INSERT INTO measurement_sources(measurement_id,user_id,kind,document,document_sha256,programs)
 SELECT ?,u.id,?,?,?,? FROM users u WHERE u.uuid=?
 AND (SELECT count(*) FROM measurement_sources s WHERE s.user_id=u.id)<1024
 AND COALESCE((SELECT sum(length(CAST(s.document AS BLOB))+length(CAST(s.programs AS BLOB)))
 FROM measurement_sources s WHERE s.user_id=u.id),0)+?<=268435456`, measurementID, input.Kind, string(document), studio.DocumentDigest(document), string(programs), ownerID, len(document)+len(programs))
		if err != nil {
			return wire.SourceDocument{}, false, err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return wire.SourceDocument{}, false, err
		}
		if n != 1 {
			return wire.SourceDocument{}, false, conflict("saved source exceeds the account limit of 1024 measurements or 256 MiB")
		}
	} else {
		return wire.SourceDocument{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return wire.SourceDocument{}, false, err
	}
	return wire.SourceDocument{
		SourceReference: wire.SourceReference{Kind: input.Kind, DocumentSHA256: studio.DocumentDigest(document), MeasurementID: measurementID},
		Document:        document, Programs: input.Programs,
	}, created, nil
}

// Read checks both run visibility and current membership in the same
// snapshot as its source lookup. A shared revision is never read after removal.
func Read(ctx context.Context, tx *sql.Tx, runID, callerID uuid.UUID) (*wire.SourceDocument, error) {
	var measurementID string
	err := tx.QueryRowContext(ctx, `SELECT d.transaction_id FROM debuglets d WHERE d.uuid=? AND (
 EXISTS (SELECT 1 FROM debuglet_users du JOIN users u ON u.id=du.user_id WHERE du.debuglet_id=d.id AND u.uuid=?)
 OR EXISTS (SELECT 1 FROM community_measurements cm JOIN community_projects p ON p.id=cm.project_id
 JOIN community_members m ON m.community_id=p.community_id JOIN users u ON u.id=m.user_id
 WHERE cm.measurement_id=d.transaction_id AND u.uuid=?))`, runID, callerID, callerID).Scan(&measurementID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
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
			return nil, err
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
			return nil, err
		}
		source.DocumentSHA256 = studio.DocumentDigest([]byte(document))
		source.Programs = []wire.SourceProgram{}
		rows, err := tx.QueryContext(ctx, `SELECT d.uuid,json_extract(p.document,'$.workload_sha256')
 FROM debuglets d JOIN debuglet_provenance p ON p.debuglet_id=d.id
 WHERE d.transaction_id=? AND NOT EXISTS (SELECT 1 FROM payload_tombstones t WHERE t.debuglet_id=d.id)
 ORDER BY d.uuid LIMIT 1024`, measurementID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var program wire.SourceProgram
			if err := rows.Scan(&program.RunID, &program.SHA256); err != nil {
				return nil, err
			}
			source.Programs = append(source.Programs, program)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}
	source.Document = json.RawMessage(document)
	return source, nil
}

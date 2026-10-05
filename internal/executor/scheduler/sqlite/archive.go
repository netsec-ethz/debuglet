// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/database"
)

// ArchivedRun describes retained evidence and a separate local operator decision.
// An archive never establishes a remote outcome or a safe retry.
type ArchivedRun struct {
	RunID             uuid.UUID              `json:"run_id"`
	OriginalBinding   controlsession.Binding `json:"original_binding"`
	ExecutionRetained bool                   `json:"execution_retained"`
	OutputRetained    bool                   `json:"output_retained"`
	TerminalRetained  bool                   `json:"terminal_retained"`
	StartedAt         *time.Time             `json:"started_at"`
	ArchivedAt        *time.Time             `json:"archived_at"`
	Reason            string                 `json:"reason"`
}

// InspectArchive reads one run's metadata without loading its program or output.
func InspectArchive(ctx context.Context, db database.DBTX, id uuid.UUID) (ArchivedRun, error) {
	r := ArchivedRun{RunID: id}
	if id == uuid.Nil {
		return r, errors.New("a nonzero run UUID is required")
	}
	q := database.New(db)
	row, err := q.GetDebugletIdentity(ctx, id)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return r, err
	}
	if err == nil {
		r.ExecutionRetained = true
		r.OriginalBinding = controlsession.Binding{Incarnation: row.DispatcherIncarnation, SessionID: row.SessionID}
		if !row.StartedAt.IsZero() {
			r.StartedAt = &row.StartedAt.Time
		}
	}
	exit, err := q.GetDebugletExit(ctx, id.String())
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return r, err
	}
	if err == nil {
		r.TerminalRetained = true
		binding := controlsession.Binding{Incarnation: exit.DispatcherIncarnation, SessionID: exit.SessionID}
		if r.ExecutionRetained && r.OriginalBinding != binding {
			return r, errors.New("execution and terminal evidence disagree on the original binding")
		}
		r.OriginalBinding = binding
	}
	output, err := q.GetOutputRun(ctx, id.String())
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return r, err
	}
	if err == nil {
		r.OutputRetained = true
		binding := controlsession.Binding{Incarnation: output.DispatcherIncarnation, SessionID: output.SessionID}
		if (r.ExecutionRetained || r.TerminalRetained) && r.OriginalBinding != binding {
			return r, errors.New("output evidence disagrees on the original binding")
		}
		r.OriginalBinding = binding
	}
	var at int64
	err = db.QueryRowContext(ctx, "SELECT recorded_at_ns, reason FROM operator_dispositions WHERE run_id = ?", id.String()).Scan(&at, &r.Reason)
	if err == nil {
		t := time.Unix(0, at).UTC()
		r.ArchivedAt = &t
	} else if !errors.Is(err, sql.ErrNoRows) {
		return r, err
	}
	if !r.ExecutionRetained && !r.TerminalRetained && !r.OutputRetained && r.ArchivedAt == nil {
		return r, fmt.Errorf("run %s has no retained execution, terminal or output evidence", id)
	}
	return r, nil
}

// ArchiveRun requires the caller to hold exclusive database ownership after
// joined shutdown. Only a separate disposition is written; evidence stays put.
func ArchiveRun(ctx context.Context, db *sql.DB, id uuid.UUID, reason string) (ArchivedRun, error) {
	if strings.TrimSpace(reason) != reason || reason == "" || len(reason) > 200 || strings.ContainsFunc(reason, unicode.IsControl) {
		return ArchivedRun{}, errors.New("reason must contain 1 to 200 printable bytes without surrounding whitespace")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return ArchivedRun{}, err
	}
	defer tx.Rollback()
	r, err := InspectArchive(ctx, tx, id)
	if err != nil {
		return r, err
	}
	if r.ArchivedAt != nil {
		if r.Reason != reason {
			return r, errors.New("this run already has a different operator disposition")
		}
		return r, nil
	}
	at := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, "INSERT INTO operator_dispositions (run_id, recorded_at_ns, reason) VALUES (?, ?, ?)", id.String(), at.UnixNano(), reason); err != nil {
		return r, err
	}
	if err := tx.Commit(); err != nil {
		return r, err
	}
	r.ArchivedAt, r.Reason = &at, reason
	return r, nil
}

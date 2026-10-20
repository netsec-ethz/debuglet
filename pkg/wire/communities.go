// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wire

import (
	"encoding/json"
	"time"
)

const MaxCommunityExperimentBytes = 24 << 20

// Community groups individually authenticated members and their shared work.
type Community struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Role        string    `json:"role"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
}

type CommunityMember struct {
	UserID   string    `json:"user_id"`
	Name     string    `json:"name"`
	Role     string    `json:"role"`
	JoinedAt time.Time `json:"joined_at"`
}

type CommunityProject struct {
	ID          string    `json:"id"`
	CommunityID string    `json:"community_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
}

// CommunityExperiment retains a versioned source document and optional compiled bundle.
// Lists omit Document and Bundle; a specific revision remains available after edits.
type CommunityExperiment struct {
	ID          string          `json:"id"`
	ProjectID   string          `json:"project_id"`
	Name        string          `json:"name"`
	Kind        string          `json:"kind"`
	Description string          `json:"description,omitempty"`
	Collection  string          `json:"collection,omitempty"`
	Revision    int64           `json:"revision"`
	CreatedBy   string          `json:"created_by"`
	UpdatedAt   time.Time       `json:"updated_at"`
	Document    json.RawMessage `json:"document,omitempty"`
	Bundle      json.RawMessage `json:"bundle,omitempty"`
}

type CommunityMeasurement struct {
	MeasurementID      string    `json:"measurement_id"`
	ProjectID          string    `json:"project_id"`
	SharedBy           string    `json:"shared_by"`
	SharedAt           time.Time `json:"shared_at"`
	ExperimentID       string    `json:"experiment_id,omitempty"`
	ExperimentRevision *int64    `json:"experiment_revision,omitempty"`
}

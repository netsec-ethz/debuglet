// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wire

import (
	"encoding/json"
	"time"
)

// A highlight bookmarks one retained output occurrence. It does not duplicate
// the payload or change the source run's retention and sharing permissions.
type HighlightSummary struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Note          string    `json:"note"`
	Collection    string    `json:"collection"`
	ProjectID     string    `json:"project_id,omitempty"`
	CreatedBy     string    `json:"created_by"`
	CreatedAt     time.Time `json:"created_at"`
	CanManage     bool      `json:"can_manage"`
	RunID         string    `json:"run_id"`
	MeasurementID string    `json:"measurement_id"`
	EventIndex    int64     `json:"event_index"`
	EventSHA256   string    `json:"event_sha256"`
	NodeID        string    `json:"node_id"`
	Block         string    `json:"block"`
}

type Highlight struct {
	HighlightSummary
	Event  json.RawMessage  `json:"event"`
	Source *SourceReference `json:"source,omitempty"`
}

type HighlightPage struct {
	Highlights []HighlightSummary `json:"highlights"`
	Total      int64              `json:"total"`
	Limit      int64              `json:"limit"`
	Offset     int64              `json:"offset"`
}

// SourceReference identifies the immutable source supplied for a measurement.
// It does not attest that arbitrary program bytes were compiled from it.
type SourceReference struct {
	Kind                  string `json:"kind"`
	DocumentSHA256        string `json:"document_sha256"`
	MeasurementID         string `json:"measurement_id"`
	CommunityExperimentID string `json:"community_experiment_id,omitempty"`
	Revision              int64  `json:"revision,omitempty"`
}

type SourceProgram struct {
	RunID  string `json:"run_id"`
	SHA256 string `json:"sha256"`
}

type SourceDocument struct {
	SourceReference
	Document json.RawMessage `json:"document"`
	Programs []SourceProgram `json:"programs"`
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/buildinfo"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

func (d *Dispatcher) recordProvenance(ctx context.Context, q *database.Queries, rowID int64, id uuid.UUID, spec models.DebugletSpec, selected *submissionOwner) error {
	hash := sha256.Sum256(spec.Wasm)
	binding := selected.owner.Binding()
	version := buildinfo.Version
	if version == "" {
		version = d.version
	}
	p := wire.ResultProvenance{
		RunID: id.String(), ExecutorID: spec.ExecutorID,
		Attempt:    wire.ControlBinding{DispatcherIncarnation: binding.Incarnation, SessionID: binding.SessionID},
		AdmittedAt: time.Now().UTC(), WorkloadSHA256: hex.EncodeToString(hash[:]),
		Arguments: append([]string{}, spec.Args...),
		AdmittedPolicy: wire.Policy{
			FloorBW: int64(spec.Policy.FloorBW), CeilBW: int64(spec.Policy.CeilBW),
			TimeoutMS: spec.Policy.Timeout.Milliseconds(), Addresses: append([]string{}, spec.Policy.Addresses...),
			RequireICMP: spec.Policy.RequireICMP, ListenUDP: spec.Policy.ListenUDP,
			ListenTCP: spec.Policy.ListenTCP, ListenSCION: spec.Policy.ListenSCION,
		},
		HostPolicy: "unknown", ExecutorSoftware: resultKnownString(selected.entry.Version),
		DispatcherSoftware: resultKnownString(version), DispatcherRevision: resultKnownString(buildinfo.Revision),
		CertificateSHA256: resultKnownString(selected.owner.CredentialFingerprint()),
	}
	document, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return q.CreateDebugletProvenance(ctx, database.CreateDebugletProvenanceParams{DebugletID: rowID, Document: string(document)})
}

func resultKnownString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

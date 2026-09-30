// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"encoding/json"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

func recordMeasurementRequest(ctx context.Context, q *database.Queries, id int64, requested *wire.SubmittedConfiguration) error {
	if requested == nil {
		return nil
	}
	document, err := json.Marshal(requested)
	if err != nil {
		return err
	}
	return q.InsertMeasurementRequest(ctx, database.InsertMeasurementRequestParams{DebugletID: id, Document: string(document)})
}

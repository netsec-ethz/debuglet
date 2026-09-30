// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"context"
	"errors"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

type RetryLink = wire.RetryLink

// RetryTEST explicitly requests one new attempt. Retain requestID and the same
// prepared request to recover it after a lost response. No request is retried
// automatically, and the old run is never resumed or modified.
func (c *Client) RetryTEST(ctx context.Context, parentID, requestID string, batch *PreparedBatch) (Submission, error) {
	if !resultUUID(parentID) || !resultUUID(requestID) {
		return Submission{}, errors.New("client: retry requires canonical nonzero parent and request UUIDs")
	}
	if batch == nil || batch.count != 1 {
		return Submission{}, errors.New("client: retry requires exactly one prepared request")
	}
	return c.submitTEST(ctx, batch, &wire.RetryLink{ParentRunID: parentID, RequestID: requestID})
}

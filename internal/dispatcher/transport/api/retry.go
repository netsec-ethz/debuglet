// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

func retryScope(c *caller) string {
	if owner, ok := c.owner(); ok {
		return owner.String()
	}
	return "local"
}

func (h *Handler) authorizeRetry(c echo.Context, link *wire.RetryLink, count int) error {
	if count != 1 {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "retry requires exactly one debuglet")
	}
	parent, err := parseDebugletID(link.ParentRunID)
	if err != nil {
		return err
	}
	if _, err := parseDebugletID(link.RequestID); err != nil {
		return err
	}
	if err := h.authorizeDebuglet(c, parent); err != nil {
		return err
	}
	established, _ := requireCaller(c)
	if established.unrestricted() {
		if _, err := database.New(h.db).GetDebugletByUUID(c.Request().Context(), parent); errors.Is(err, sql.ErrNoRows) {
			return debugletNotFound()
		} else if err != nil {
			return retryStorageError(err)
		}
	}
	return nil
}

// Ordinary submissions retain their existing intent hash. Retry intents bind
// the lineage as well, so omitting it from the submit cannot discard the link.
func submissionHash(requests []DebugletRequest, link *wire.RetryLink) string {
	if link == nil {
		return hashDebugletRequest(requests)
	}
	return "retry:" + retryDigest(struct {
		Debuglets []DebugletRequest `json:"debuglets"`
		Retry     *wire.RetryLink   `json:"retry"`
	}{requests, link})
}

func retryDigest(value any) string {
	data, _ := json.Marshal(value) // These concrete DTOs contain only JSON values.
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func retryStorageError(err error) error {
	return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to store or recover retry request", err)
}
func retryConflict() error {
	return apiError(http.StatusConflict, CodeIntentMismatch, "retry request ID already belongs to a different request")
}

// These are the public payment facts not present in the transaction row. In
// particular no second copy of an auth key or caller credential is stored.
type retryPaymentMetadata struct {
	CoinType        string `json:"coin_type,omitempty"`
	RegistryAddress string `json:"registry_address,omitempty"`
	ReceiverAddress string `json:"receiver_address,omitempty"`
}

func storeRetryIntent(ctx context.Context, q *database.Queries, caller *caller, req PaymentIntentRequest, transactionID string, response IntentResponse) error {
	var metadata retryPaymentMetadata
	if intent, ok := response.Intent.(SuiIntent); ok {
		metadata = retryPaymentMetadata{intent.CoinType, intent.RegistryAddress, intent.ReceiverAddress}
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return retryStorageError(err)
	}
	if len(encoded) > 4096 {
		return retryStorageError(errors.New("retry payment metadata exceeds limit"))
	}
	if err := q.CreateRetryRequest(ctx, database.CreateRetryRequestParams{
		CallerScope: retryScope(caller), RequestID: req.Retry.RequestID, ParentRunID: req.Retry.ParentRunID,
		TransactionID: transactionID, RequestHash: retryDigest(req), IntentMetadata: string(encoded),
	}); err != nil {
		return retryStorageError(err)
	}
	return nil
}

func (h *Handler) readRetryIntent(ctx context.Context, q *database.Queries, caller *caller, req PaymentIntentRequest) (*IntentResponse, error) {
	stored, err := q.GetRetryRequest(ctx, database.GetRetryRequestParams{CallerScope: retryScope(caller), RequestID: req.Retry.RequestID})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, retryStorageError(err)
	}
	if stored.ParentRunID != req.Retry.ParentRunID || stored.RequestHash != retryDigest(req) {
		return nil, retryConflict()
	}
	tx, err := q.GetTransactionByID(ctx, stored.TransactionID)
	if err != nil {
		return nil, retryStorageError(err)
	}
	response := &IntentResponse{Method: req.PaymentMethod, Retry: &wire.RetryReceipt{RetryLink: *req.Retry}}
	if req.PaymentMethod == "TEST" {
		response.Intent = DummyIntent{TransactionID: tx.ID, AuthKey: tx.AuthKey}
	} else {
		var metadata retryPaymentMetadata
		if len(stored.IntentMetadata) > 4096 {
			return nil, retryStorageError(errors.New("invalid retry payment metadata"))
		}
		if err := json.Unmarshal([]byte(stored.IntentMetadata), &metadata); err != nil {
			return nil, retryStorageError(err)
		}
		response.Intent = SuiIntent{TransactionId: tx.ID, AuthKey: tx.AuthKey, Price: tx.Price, ExpiresAtS: tx.ExpiresAt.Unix(), CoinType: metadata.CoinType, RegistryAddress: metadata.RegistryAddress, ReceiverAddress: metadata.ReceiverAddress}
	}
	rows, err := q.GetAdmittedRuns(ctx, tx.ID)
	if err != nil {
		return nil, retryStorageError(err)
	}
	if len(rows) > 1 {
		return nil, retryStorageError(errors.New("retry intent has multiple runs"))
	}
	if len(rows) == 1 {
		response.Retry.RunID = rows[0].Uuid.String()
	}
	return response, nil
}

func (h *Handler) retrySubmission(ctx context.Context, caller *caller, req SubmitDebugletsRequest) (uuid.UUIDs, error) {
	q := database.New(h.db)
	stored, err := q.GetRetryRequest(ctx, database.GetRetryRequestParams{CallerScope: retryScope(caller), RequestID: req.Retry.RequestID})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, retryConflict()
	}
	if err != nil {
		return nil, retryStorageError(err)
	}
	if stored.ParentRunID != req.Retry.ParentRunID || stored.TransactionID != req.TransactionId {
		return nil, retryConflict()
	}
	rows, err := q.GetAdmittedRuns(ctx, req.TransactionId)
	if err != nil {
		return nil, retryStorageError(err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	if len(rows) != 1 || rows[0].OrderID != req.Debuglets[0].OrderID {
		return nil, retryConflict()
	}
	return uuid.UUIDs{rows[0].Uuid}, nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	apispec "github.com/netsec-ethz/debuglet/api"
	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/pkg/tagspec"
	"github.com/netsec-ethz/debuglet/pkg/wire"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// Server-assisted verification (docs/verification.md#http-api). Both routes
// are public and share the attribution rate limit.
const (
	routeAttributionVerify = "/attribution/verify"
	routeReceiptKeys       = "/attribution/receipt-keys"
	// maxVerifyBody bounds the body of POST /attribution/verify.
	maxVerifyBody = 64 << 10
)

type (
	AttributionVerifyRequest  = wire.AttributionVerifyRequest
	AttributionVerifyResponse = wire.AttributionVerifyResponse
	AttributionReceiptKeys    = wire.AttributionReceiptKeys
)

// receiptState holds the receipt signer, opened on first use: the key is
// read, or created, and recorded the first time a route needs it.
type receiptState struct {
	mu     sync.Mutex
	signer *dispatcher.ReceiptSigner
}

func (h *Handler) receiptSigner(ctx context.Context) (*dispatcher.ReceiptSigner, error) {
	h.receipts.mu.Lock()
	defer h.receipts.mu.Unlock()
	if h.receipts.signer != nil {
		return h.receipts.signer, nil
	}
	if h.dispatcher == nil {
		return nil, dispatcher.ErrNoReceiptKey
	}
	signer, err := h.dispatcher.OpenReceiptSigner(ctx, h.metrics.stateDirectory)
	if err != nil {
		return nil, err
	}
	h.logger.Info("Signing verification receipts", zap.String("keyID", signer.KeyID()))
	h.receipts.signer = signer
	return signer, nil
}

// POST /attribution/verify
//
// Verdicts for up to 256 packets in at most 16 groups, with a signed receipt.
func (h *Handler) PostAttributionVerify(c echo.Context) error {
	if err := h.attributionLimiter.allow(c); err != nil {
		return err
	}
	tooLarge := apiError(http.StatusRequestEntityTooLarge, CodePayloadTooLarge, "request body exceeds "+strconv.Itoa(maxVerifyBody)+" bytes")
	if c.Request().ContentLength > maxVerifyBody {
		return tooLarge
	}
	body, err := io.ReadAll(io.LimitReader(c.Request().Body, maxVerifyBody+1))
	if err != nil {
		return bindError(err)
	}
	if len(body) > maxVerifyBody {
		return tooLarge
	}
	var req AttributionVerifyRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.More() {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "invalid request body")
	}
	if len(req.Packets) == 0 || len(req.Packets) > dispatcher.MaxVerifyPackets {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "packets must list 1 to 256 packets")
	}
	packets := make([]dispatcher.VerifyPacket, len(req.Packets))
	for i, p := range req.Packets {
		if len(p.Data) == 0 || len(p.Data) > tagspec.MaxInput || p.CapturedAt.IsZero() {
			return apiError(http.StatusBadRequest, CodeInvalidRequest,
				"packet "+strconv.Itoa(i)+": data must hold 1 to 64 bytes and captured_at an RFC 3339 time")
		}
		packets[i] = dispatcher.VerifyPacket{Data: p.Data, CapturedAt: p.CapturedAt}
	}
	ctx := c.Request().Context()
	signer, err := h.receiptSigner(ctx)
	if err != nil {
		return apiErrorFrom(http.StatusServiceUnavailable, CodeUnavailable, "verification receipts are unavailable", err)
	}
	groups, err := h.dispatcher.VerifyAttribution(ctx, packets)
	if errors.Is(err, dispatcher.ErrTooManyVerifyGroups) {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, err.Error())
	}
	if err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to verify the packets", err)
	}

	resp := AttributionVerifyResponse{Groups: make([]wire.AttributionVerifyGroup, 0, len(groups))}
	payload := wire.AttributionReceiptPayload{
		APIVersion: apispec.Version, Dispatcher: h.receiptDispatcher(c),
		Groups: make([]wire.AttributionReceiptGroup, 0, len(groups)), PacketsDigest: wire.PacketsDigest(req.Packets),
		QueryAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	spent := 0
	for _, g := range groups {
		group := wire.AttributionVerifyGroup{
			Source: g.Source, Epoch: g.Epoch, ChainID: g.ChainID, ExecutorID: g.ExecutorID, RunID: g.RunID,
			Verdict: g.Verdict, Reason: g.Reason, Method: g.Method, Packets: g.Packets,
		}
		if g.Budget != nil {
			group.Budget = &wire.AttributionVerifyBudget{Limit: g.Budget.Limit, Remaining: g.Budget.Remaining, ResetsAt: g.Budget.ResetsAt}
		}
		if g.Method == dispatcher.VerifyMethodServer {
			spent++
		}
		resp.Groups = append(resp.Groups, group)
		payload.Groups = append(payload.Groups, wire.AttributionReceiptGroup{
			ChainID: g.ChainID, Epoch: g.Epoch, ExecutorID: g.ExecutorID, Method: g.Method, Packets: g.Packets,
			Reason: g.Reason, RunID: g.RunID, Source: g.Source, Verdict: g.Verdict,
		})
	}
	canonical, err := wire.CanonicalReceiptPayload(payload)
	if err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to sign the receipt", err)
	}
	resp.Receipt = wire.AttributionReceipt{KeyID: signer.KeyID(), Payload: canonical, Signature: signer.Sign(canonical)}
	// The packets are not kept; the digest identifies them for abuse
	// handling (docs/verification.md#privacy).
	h.logger.Info("Answered a verification request", zap.String("packetsDigest", payload.PacketsDigest),
		zap.Int("packets", len(packets)), zap.Int("groups", len(groups)), zap.Int("executorAnswers", spent), zap.String("receiptKeyID", signer.KeyID()))
	return c.JSON(http.StatusOK, resp)
}

// receiptDispatcher names this dispatcher in a receipt: its configured public
// URL, or else the origin the request was addressed to.
func (h *Handler) receiptDispatcher(c echo.Context) string {
	if h.authPublicURL != "" {
		return h.authPublicURL
	}
	scheme := "http"
	if c.Request().TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + c.Request().Host
}

// GET /attribution/receipt-keys
//
// Every key that verifies this dispatcher's receipts, with its validity.
func (h *Handler) GetAttributionReceiptKeys(c echo.Context) error {
	if err := h.attributionLimiter.allow(c); err != nil {
		return err
	}
	ctx := c.Request().Context()
	if _, err := h.receiptSigner(ctx); err != nil {
		return apiErrorFrom(http.StatusServiceUnavailable, CodeUnavailable, "verification receipts are unavailable", err)
	}
	keys, err := h.dispatcher.ReceiptKeys(ctx)
	if err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to read the receipt keys", err)
	}
	resp := AttributionReceiptKeys{Keys: make([]wire.AttributionReceiptKey, 0, len(keys))}
	for _, k := range keys {
		resp.Keys = append(resp.Keys, wire.AttributionReceiptKey{KeyID: k.KeyID, PublicKey: k.PublicKey, ValidFrom: k.ValidFrom, ValidTo: k.ValidTo})
	}
	return c.JSON(http.StatusOK, resp)
}

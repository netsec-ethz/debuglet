// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package payments

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments/sui"

	"go.uber.org/zap"
)

// Kinds and states of outbound transfers (chain_transfers). A transfer is
// reserved before the chain is called, sent once the chain accepted it and
// confirmed once a lookup found it executed with the intended credit. failed
// means no coins moved; unknown means the outcome is not known and only
// reconciliation resolves it.
const (
	transferPayout = "payout"
	transferRefund = "refund"

	transferReserved  = "reserved"
	transferSent      = "sent"
	transferConfirmed = "confirmed"
	transferFailed    = "failed"
	transferUnknown   = "unknown"
)

// staleReservation is how long a reserved transfer may wait for its chain
// call. An older reserved row was left by a stop between the reservation and
// the call, and reconciliation looks it up.
const staleReservation = 10 * time.Minute

// executeTimeout bounds one submission of a transfer. A submission that does
// not answer in time has an unknown outcome, which is how its error is
// recorded.
const executeTimeout = 2 * time.Minute

// chainReadTimeout bounds one chain read: the preparation of a transfer and
// each reconciliation lookup. A lookup that does not answer in time leaves the
// transfer unknown; it never means that the money was not sent.
var chainReadTimeout = 30 * time.Second

var (
	// errAlreadySettled is returned by a transfer decision that finds the
	// decision already taken. Nothing is reserved and nothing is sent.
	errAlreadySettled = errors.New("already settled")
	// errPayoutNotReserved means the balance could not be reserved: another
	// payout of the same executor and currency is still open, or the balance
	// changed since it was read.
	errPayoutNotReserved = errors.New("payout not reserved: an earlier payout is still open or the balance changed")
)

// reservedTransfer is a transfer row in state reserved with its signed
// transaction, ready to be submitted.
type reservedTransfer struct {
	row      database.ChainTransfer
	prepared *sui.PreparedTransfer
}

// sendTransfer runs the transfer lifecycle: the chain backend builds and signs
// the transfer; one SQL transaction applies decide (the local decision the
// transfer pays for) and reserves the transfer row with the signed
// transaction; then the transfer is submitted and its outcome recorded. An
// error means the decision was not taken and nothing was sent. Once the
// decision is committed, the error is nil and state is the outcome recorded on
// the transfer row (sent, failed or unknown), or empty when nothing was to be
// transferred.
func (p *PaymentHandler) sendTransfer(ctx context.Context, transfer database.ChainTransfer, decide func(*database.Queries) error) (state string, err error) {
	reserved, err := p.prepareAndReserve(ctx, transfer, decide)
	if err != nil || reserved == nil {
		return "", err
	}
	return p.executeReserved(ctx, reserved), nil
}

// prepareAndReserve prepares the transfer, then commits decide together with
// the reserved transfer row. A transfer of amount zero moves nothing: decide is
// committed alone and nil is returned without a reservation.
func (p *PaymentHandler) prepareAndReserve(ctx context.Context, transfer database.ChainTransfer, decide func(*database.Queries) error) (*reservedTransfer, error) {
	var prepared *sui.PreparedTransfer
	if transfer.Amount > 0 {
		readCtx, cancel := context.WithTimeout(ctx, chainReadTimeout)
		var err error
		prepared, err = p.sui.PrepareTransfer(readCtx, uint64(transfer.Amount), sui.GetCoinType(transfer.Currency, p.cfg.Sui.Network), transfer.Receiver)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("prepare %s transfer: %w", transfer.Kind, err)
		}
	}

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()
	queries := database.New(p.db).WithTx(tx)
	if err := decide(queries); err != nil {
		return nil, err
	}
	if prepared != nil {
		now := models.NewUTCTime(time.Now())
		transfer.State, transfer.Digest, transfer.CreatedAt, transfer.UpdatedAt = transferReserved, prepared.Digest, now, now
		transfer.SignedTransaction, transfer.Signature = append([]byte{}, prepared.Bytes()...), prepared.Signature()
		transfer.ID, err = queries.InsertChainTransfer(ctx, database.InsertChainTransferParams{
			Kind: transfer.Kind, ExecutorID: transfer.ExecutorID, TransactionID: transfer.TransactionID, OrderID: transfer.OrderID,
			Amount: transfer.Amount, Currency: transfer.Currency, Receiver: transfer.Receiver, State: transfer.State,
			Digest: transfer.Digest, SignedTransaction: transfer.SignedTransaction, Signature: transfer.Signature,
			CreatedAt: transfer.CreatedAt, UpdatedAt: transfer.UpdatedAt,
		})
		if err != nil {
			return nil, fmt.Errorf("reserve %s transfer: %w", transfer.Kind, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit %s decision: %w", transfer.Kind, err)
	}
	if prepared == nil {
		return nil, nil
	}
	return &reservedTransfer{row: transfer, prepared: prepared}, nil
}

// executeReserved submits a reserved transfer and records the outcome. The
// outcome is recorded even when ctx ended during the call; if it cannot be
// recorded, the row stays reserved and reconciliation resolves it. It returns
// the outcome's state.
func (p *PaymentHandler) executeReserved(ctx context.Context, reserved *reservedTransfer) string {
	state, detail := executionOutcome(p.submit(ctx, reserved.prepared))
	p.recordTransfer(context.WithoutCancel(ctx), reserved.row, state, reserved.prepared.Digest, detail)
	return state
}

// submit runs ExecuteTransfer bounded by executeTimeout.
func (p *PaymentHandler) submit(ctx context.Context, prepared *sui.PreparedTransfer) error {
	ctx, cancel := context.WithTimeout(ctx, executeTimeout)
	defer cancel()
	return p.sui.ExecuteTransfer(ctx, prepared)
}

// executionOutcome maps the result of ExecuteTransfer to the state it leaves:
// accepted is sent; not broadcast or executed with failure status is failed;
// anything else may have been submitted and is unknown.
func executionOutcome(err error) (state string, detail string) {
	switch {
	case err == nil:
		return transferSent, ""
	case errors.Is(err, sui.ErrNotBroadcast), errors.Is(err, sui.ErrTransferFailed):
		return transferFailed, err.Error()
	default:
		return transferUnknown, err.Error()
	}
}

// recordTransfer moves the transfer from its current state to state with the
// digest the chain backend reported. A payout that becomes failed returns its
// amount to the executor's balance in the same SQL transaction. The write is
// conditional on the state the caller read, so an outcome recorded
// concurrently is not overwritten and a balance is released once.
func (p *PaymentHandler) recordTransfer(ctx context.Context, t database.ChainTransfer, state string, digest string, detail string) {
	logger := p.logger.With(zap.Int64("transfer", t.ID), zap.String("kind", t.Kind), zap.String("digest", digest))
	if digest != t.Digest {
		logger.Warn("Transfer digest differs from the reserved digest", zap.String("reserved", t.Digest))
	}
	err := func() error {
		tx, err := p.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		queries := database.New(p.db).WithTx(tx)
		changed, err := queries.UpdateChainTransfer(ctx, database.UpdateChainTransferParams{
			State: state, Digest: digest, Detail: detail, UpdatedAt: models.NewUTCTime(time.Now()), ID: t.ID, FromState: t.State,
		})
		if err != nil {
			return err
		}
		if changed == 0 {
			logger.Debug("Transfer outcome was recorded concurrently", zap.String("from", t.State))
			return nil
		}
		if state == transferFailed && t.Kind == transferPayout {
			if err := queries.ReleasePayout(ctx, database.ReleasePayoutParams{Amount: t.Amount, ExecutorID: t.ExecutorID, Currency: t.Currency}); err != nil {
				return err
			}
		}
		return tx.Commit()
	}()
	switch {
	case err != nil:
		logger.Error("Failed to record transfer outcome", zap.String("state", state), zap.String("error", err.Error()))
	case state == t.State:
		logger.Debug("Transfer is still open", zap.String("state", state), zap.String("detail", detail))
	case state == transferFailed || state == transferUnknown:
		logger.Warn("Transfer did not complete", zap.String("state", state), zap.String("detail", detail))
	default:
		logger.Info("Recorded transfer", zap.String("state", state))
	}
}

// ReconcileTransfers looks up at most limit open transfers by digest: sent and
// unknown transfers and reserved transfers older than staleReservation. A
// transfer is confirmed only when the chain executed it successfully and the
// receiver's credit was verified; executed with failure status it is failed;
// a transfer the chain does not know is submitted again with its stored signed
// transaction, which has the same digest and cannot execute twice. Anything
// inconclusive leaves the transfer unknown with the last check in its detail.
func (p *PaymentHandler) ReconcileTransfers(ctx context.Context, limit int) error {
	if p.chainDisabled() {
		return fmt.Errorf("reconcile transfers: %w", ErrPaymentsDisabled)
	}
	open, err := database.New(p.db).ListUnresolvedChainTransfers(ctx, database.ListUnresolvedChainTransfersParams{
		ReservedBefore: models.NewUTCTime(time.Now().Add(-staleReservation)), RowLimit: int64(limit),
	})
	if err != nil {
		return fmt.Errorf("list open transfers: %w", err)
	}
	for _, t := range open {
		if ctx.Err() != nil {
			break
		}
		p.reconcileTransfer(ctx, t)
	}
	return nil
}

// reconcileTransfer looks one transfer up within chainReadTimeout and records
// what the lookup found. The outcome is recorded even when ctx ended.
func (p *PaymentHandler) reconcileTransfer(ctx context.Context, t database.ChainTransfer) {
	lookupCtx, cancel := context.WithTimeout(ctx, chainReadTimeout)
	outcome, verified, err := p.sui.LookupTransfer(lookupCtx, t.Digest, &sui.TransferExpectation{
		Receiver: t.Receiver, Amount: uint64(t.Amount), CoinType: sui.GetCoinType(t.Currency, p.cfg.Sui.Network),
	})
	timedOut := errors.Is(lookupCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil
	cancel()
	record := context.WithoutCancel(ctx)
	switch {
	case err != nil && timedOut:
		p.recordTransfer(record, t, transferUnknown, t.Digest, "last check: lookup timed out")
	case err != nil:
		p.recordTransfer(record, t, transferUnknown, t.Digest, "last check: lookup inconclusive: "+err.Error())
	case outcome == sui.TransferConfirmed && verified:
		p.recordTransfer(record, t, transferConfirmed, t.Digest, "")
	case outcome == sui.TransferConfirmed:
		p.recordTransfer(record, t, transferUnknown, t.Digest, "last check: executed successfully, but the node returned no balance changes, so the receiver's credit could not be verified")
	case outcome == sui.TransferFailed:
		p.recordTransfer(record, t, transferFailed, t.Digest, "executed with failure status")
	case outcome == sui.TransferNotFound && t.State != transferSent:
		prepared, err := sui.RestorePreparedTransfer(t.Digest, t.SignedTransaction, t.Signature)
		if err != nil {
			p.recordTransfer(record, t, transferUnknown, t.Digest, "last check: not found, and the stored transaction cannot be submitted again: "+err.Error())
			return
		}
		state, detail := executionOutcome(p.submit(ctx, prepared))
		p.recordTransfer(record, t, state, prepared.Digest, detail)
	case outcome == sui.TransferNotFound:
		p.recordTransfer(record, t, transferUnknown, t.Digest, "last check: not found after the chain accepted it")
	default:
		p.recordTransfer(record, t, transferUnknown, t.Digest, fmt.Sprintf("last check: unexpected lookup outcome %q", outcome))
	}
}

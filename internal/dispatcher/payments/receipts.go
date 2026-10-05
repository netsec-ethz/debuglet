// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package payments

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments/sui"
)

// ApplyPaymentReceipt is the sui.TransactionFulfiller of the chain listener.
// In one SQL transaction it validates a chain payment receipt against the
// transaction its nonce names, marks an outstanding transaction paid when the
// receipt pays it exactly, and records the receipt with its disposition. A
// receipt that was recorded before is not applied again: an applied one is
// reported as duplicate, any other with its recorded disposition. A receipt
// to another address whose nonce names no local transaction is not ours and
// is not recorded (empty disposition). A database error is returned with
// nothing recorded, so the caller can process the receipt again. Chain mode
// must be enabled.
func (p *PaymentHandler) ApplyPaymentReceipt(ctx context.Context, r sui.PaymentReceipt) (sui.ReceiptDisposition, error) {
	if p.chainDisabled() {
		return "", fmt.Errorf("apply payment receipt: %w", ErrPaymentsDisabled)
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("begin payment receipt: %w", err)
	}
	defer tx.Rollback()
	queries := database.New(tx)

	stored, err := queries.GetPaymentReceipt(ctx, database.GetPaymentReceiptParams{TxDigest: r.Digest, Nonce: r.Nonce})
	if err == nil {
		if disposition := sui.ReceiptDisposition(stored.Disposition); disposition != sui.ReceiptApplied {
			return disposition, nil
		}
		return sui.ReceiptDuplicate, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("read payment receipt: %w", err)
	}

	disposition, detail, err := p.settleReceipt(ctx, queries, r)
	if err != nil || disposition == "" {
		return "", err
	}
	var checkpoint sql.NullInt64
	if r.Checkpoint != 0 && r.Checkpoint <= math.MaxInt64 {
		checkpoint = sql.NullInt64{Int64: int64(r.Checkpoint), Valid: true}
	}
	if err := queries.InsertPaymentReceipt(ctx, database.InsertPaymentReceiptParams{
		TxDigest:    r.Digest,
		Nonce:       r.Nonce,
		Disposition: string(disposition),
		Amount:      strconv.FormatUint(r.Amount, 10),
		CoinType:    r.CoinType,
		Receiver:    r.Receiver,
		Checkpoint:  checkpoint,
		ObservedAt:  models.NewUTCTime(time.Now()),
		Detail:      detail,
	}); err != nil {
		return "", fmt.Errorf("record payment receipt: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit payment receipt: %w", err)
	}
	return disposition, nil
}

// settleReceipt decides a receipt that has not been recorded and, when it pays
// its transaction, marks the transaction paid through queries. detail names
// the field that did not match.
func (p *PaymentHandler) settleReceipt(ctx context.Context, queries *database.Queries, r sui.PaymentReceipt) (sui.ReceiptDisposition, string, error) {
	toUs := sameSuiAddress(r.Receiver, p.cfg.Sui.Address)
	transaction, err := queries.GetTransactionByID(ctx, r.Nonce)
	if errors.Is(err, sql.ErrNoRows) {
		if !toUs {
			return "", "", nil
		}
		return sui.ReceiptUnknownIntent, "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("read transaction: %w", err)
	}
	switch {
	case !isChainCurrency(transaction.Method):
		return sui.ReceiptMismatch, "method", nil
	case !sameCoinType(r.CoinType, sui.GetCoinType(transaction.Currency, p.cfg.Sui.Network)):
		return sui.ReceiptMismatch, "coin type", nil
	case !toUs:
		return sui.ReceiptMismatch, "receiver", nil
	case r.Amount > math.MaxInt64 || int64(r.Amount) != transaction.Price:
		return sui.ReceiptMismatch, "amount", nil
	case r.Timestamp.After(transaction.ExpiresAt.Time):
		return sui.ReceiptExpired, "", nil
	}

	paid, err := queries.MarkTransactionPaid(ctx, database.MarkTransactionPaidParams{
		Paid: int64(models.Paid), ID: transaction.ID, Outstanding: int64(models.Outstanding),
	})
	if err != nil {
		return "", "", fmt.Errorf("mark transaction paid: %w", err)
	}
	if paid == 1 {
		return sui.ReceiptApplied, "", nil
	}
	// The same receipt was answered above from its own row, so an applied
	// receipt for this nonce is a second payment by another chain transaction.
	recorded, err := queries.ListPaymentReceiptsByNonce(ctx, r.Nonce)
	if err != nil {
		return "", "", fmt.Errorf("read payment receipts: %w", err)
	}
	for _, other := range recorded {
		if other.Disposition == string(sui.ReceiptApplied) {
			return sui.ReceiptMismatch, "already paid by " + other.TxDigest, nil
		}
	}
	return sui.ReceiptMismatch, "transaction not outstanding", nil
}

// sameSuiAddress compares two Sui addresses in any letter case, with or
// without 0x and leading zeros.
func sameSuiAddress(a, b string) bool {
	na, nb := normalizeSuiAddress(a), normalizeSuiAddress(b)
	return na != "" && na == nb
}

// sameCoinType compares two coin types whose package addresses may be written
// in either form sameSuiAddress accepts. An empty type matches nothing.
func sameCoinType(a, b string) bool {
	addrA, restA, okA := strings.Cut(a, "::")
	addrB, restB, okB := strings.Cut(b, "::")
	return okA && okB && strings.EqualFold(restA, restB) && sameSuiAddress(addrA, addrB)
}

func normalizeSuiAddress(a string) string {
	a = strings.ToLower(a)
	a = strings.TrimPrefix(a, "0x")
	if a == "" || len(a) > 64 || strings.Trim(a, "0123456789abcdef") != "" {
		return ""
	}
	return strings.Repeat("0", 64-len(a)) + a
}

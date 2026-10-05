// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

package sui

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"

	"github.com/block-vision/sui-go-sdk/common/grpcconn"
	suiModels "github.com/block-vision/sui-go-sdk/models"
	"github.com/block-vision/sui-go-sdk/mystenbcs"
	v2 "github.com/block-vision/sui-go-sdk/pb/sui/rpc/v2"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

const catchUpPageSize = 50

// ReceiptDisposition is what a chain payment receipt was recorded as.
type ReceiptDisposition string

const (
	// ReceiptApplied marks the receipt that paid its transaction.
	ReceiptApplied ReceiptDisposition = "applied"
	// ReceiptDuplicate is returned for a receipt that was already applied;
	// its effect is not repeated.
	ReceiptDuplicate ReceiptDisposition = "duplicate"
	// ReceiptMismatch marks a receipt that names one of our transactions but
	// does not pay it: wrong method, coin type, receiver or amount, or a
	// transaction that is no longer outstanding.
	ReceiptMismatch ReceiptDisposition = "mismatch"
	// ReceiptUnknownIntent marks a receipt to our address whose nonce names
	// no local transaction. It is left for operator reconciliation.
	ReceiptUnknownIntent ReceiptDisposition = "unknown_intent"
	// ReceiptExpired marks a receipt timestamped after its transaction expired.
	ReceiptExpired ReceiptDisposition = "expired"
)

// PaymentReceipt is a decoded payment kit receipt event.
type PaymentReceipt struct {
	Digest     string // chain transaction digest
	Nonce      string // our transaction id
	Amount     uint64 // base units of CoinType
	CoinType   string
	Receiver   string
	Timestamp  time.Time
	Checkpoint uint64 // 0 when the source does not report it
}

// TransactionFulfiller records payment receipts.
type TransactionFulfiller interface {
	// ApplyPaymentReceipt records r and applies its effect at most once. An
	// empty disposition with a nil error means the receipt is not addressed to
	// this dispatcher and nothing was recorded. After an error nothing was
	// recorded and the receipt must be processed again.
	ApplyPaymentReceipt(ctx context.Context, r PaymentReceipt) (ReceiptDisposition, error)
}

type Listener struct {
	grpcEndpoint      string
	graphqlURL        string
	eventType         string
	cursorKey         string
	receiverAddress   string
	paymentKitPackage string
	paymentRegistryId string
	logger            *zap.Logger
	client            *grpcconn.SuiGrpcClient
	httpClient        *http.Client
	db                *sql.DB
	fulfiller         TransactionFulfiller
}

func NewListener(cfg *config.DispatcherConfig, db *sql.DB, logger *zap.Logger, tf TransactionFulfiller) *Listener {
	grpcEndpoint := cfg.Sui.GRPCEndpoint
	paymentKitPackage := cfg.Sui.PaymentKitPackage
	client := grpcconn.NewSuiGrpcClient(
		grpcEndpoint,
		grpcconn.WithDialOptions(grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, ""))),
	)
	return &Listener{
		grpcEndpoint:      grpcEndpoint,
		graphqlURL:        cfg.Sui.GraphQLURL,
		eventType:         paymentKitPackage + "::payment_kit::PaymentReceipt",
		cursorKey:         "sui_event_cursor:" + paymentKitPackage,
		receiverAddress:   strings.ToLower(cfg.Sui.Address),
		paymentKitPackage: cfg.Sui.PaymentKitPackage,
		paymentRegistryId: cfg.Sui.PaymentRegistryId,
		db:                db,
		logger:            logger,
		client:            client,
		httpClient:        &http.Client{Timeout: 30 * time.Second},
		fulfiller:         tf,
	}
}

// Start processes payment receipts until ctx ends. The stored cursor names
// the last checkpoint whose receipts are all recorded; it advances only after
// that, so an interrupted range is read again and its receipts are recognized
// as already recorded. A stored cursor that cannot be parsed is an error.
func (l *Listener) Start(ctx context.Context) error {
	cursor, err := l.loadCursor(ctx)
	if err != nil {
		return err
	}

	l.logger.Info("sui event listener started", zap.String("event_type", l.eventType))

	backoff := 2 * time.Second
	for {
		cursor, err = l.catchUp(ctx, cursor)
		if err != nil {
			// The stream would advance the cursor past the unprocessed range.
			l.logger.Error("sui catch-up error", zap.Error(err))
		} else {
			err = l.subscribeGRPC(ctx, &cursor)
		}
		if ctx.Err() != nil {
			return nil
		}
		l.logger.Warn("sui receipt processing interrupted, retrying", zap.Error(err), zap.Duration("backoff", backoff))

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

// loadCursor returns the stored cursor, or nil when none is stored.
func (l *Listener) loadCursor(ctx context.Context) (*uint64, error) {
	raw, err := database.New(l.db).GetTransactionState(ctx, l.cursorKey)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load sui cursor %q: %w", l.cursorKey, err)
	}
	seq, err := strconv.ParseUint(raw.Value, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("stored sui cursor %q is invalid: %w", l.cursorKey, err)
	}
	return &seq, nil
}

func (l *Listener) storeCursor(ctx context.Context, seq uint64) error {
	_, err := database.New(l.db).UpdateTransactionState(ctx, database.UpdateTransactionStateParams{Key: l.cursorKey, Value: strconv.FormatUint(seq, 10)})
	if err != nil {
		return fmt.Errorf("persist sui cursor: %w", err)
	}
	return nil
}

func (l *Listener) catchUp(ctx context.Context, cursor *uint64) (*uint64, error) {
	ledger, err := l.client.LedgerService(ctx)
	if err != nil {
		return cursor, fmt.Errorf("ledger service: %w", err)
	}

	info, err := ledger.GetServiceInfo(ctx, &v2.GetServiceInfoRequest{})
	if err != nil {
		return cursor, fmt.Errorf("get service info: %w", err)
	}
	return l.catchUpTo(ctx, cursor, info.GetCheckpointHeight())
}

// catchUpTo brings the stored cursor to tip. Without a stored cursor it
// stores tip, so a restart keeps the same starting point.
func (l *Listener) catchUpTo(ctx context.Context, cursor *uint64, tip uint64) (*uint64, error) {
	if cursor == nil {
		if err := l.storeCursor(ctx, tip); err != nil {
			return nil, err
		}
		l.logger.Info("no stored sui cursor, starting at chain tip", zap.Uint64("checkpoint", tip))
		return &tip, nil
	}
	if *cursor >= tip {
		return cursor, nil
	}

	if err := l.catchUpRange(ctx, *cursor, tip); err != nil {
		return cursor, err
	}
	return &tip, nil
}

// catchUpRange records every receipt event after checkpoint after and then
// stores tip as the cursor. It returns on the first event that could not be
// recorded, leaving the stored cursor where it was.
func (l *Listener) catchUpRange(ctx context.Context, after, tip uint64) error {
	l.logger.Info("sui catch-up: querying PaymentReceipt events via GraphQL",
		zap.Uint64("after_checkpoint", after), zap.Uint64("to", tip))

	var (
		pageCursor *string
		numEvents  int
	)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		page, err := l.queryPaymentReceiptEvents(ctx, after, pageCursor)
		if err != nil {
			return fmt.Errorf("query payment receipt events: %w", err)
		}

		for _, node := range page.Events.Nodes {
			contents, err := base64.StdEncoding.DecodeString(node.Contents.Bcs)
			if err != nil {
				return fmt.Errorf("payment receipt in transaction %s: decode base64: %w", node.Transaction.Digest, err)
			}
			// The GraphQL query does not report the event's checkpoint.
			if _, err := l.processPaymentReceipt(ctx, contents, node.Transaction.Digest, 0); err != nil {
				return err
			}
			numEvents++
		}

		if !page.Events.PageInfo.HasNextPage {
			break
		}
		endCursor := page.Events.PageInfo.EndCursor
		pageCursor = &endCursor
	}

	if err := l.storeCursor(ctx, tip); err != nil {
		return err
	}
	l.logger.Info("sui catch-up: done", zap.Int("events_processed", numEvents), zap.Uint64("checkpoint", tip))
	return nil
}

const paymentReceiptEventsQuery = `
query PaymentReceiptEvents($type: String!, $afterCheckpoint: UInt53, $first: Int!, $after: String) {
  events(first: $first, after: $after, filter: { type: $type, afterCheckpoint: $afterCheckpoint }) {
    pageInfo { hasNextPage endCursor }
    nodes {
      transaction { digest }
      contents { bcs }
    }
  }
}`

type paymentReceiptEventNode struct {
	Transaction struct {
		Digest string `json:"digest"`
	} `json:"transaction"`
	Contents struct {
		Bcs string `json:"bcs"`
	} `json:"contents"`
}

type paymentReceiptEventsResponse struct {
	Events struct {
		PageInfo struct {
			HasNextPage bool   `json:"hasNextPage"`
			EndCursor   string `json:"endCursor"`
		} `json:"pageInfo"`
		Nodes []paymentReceiptEventNode `json:"nodes"`
	} `json:"events"`
}

func (l *Listener) queryPaymentReceiptEvents(ctx context.Context, afterCheckpoint uint64, after *string) (*paymentReceiptEventsResponse, error) {
	var resp paymentReceiptEventsResponse
	err := l.graphQLQuery(ctx, paymentReceiptEventsQuery, map[string]any{
		"type":            l.eventType,
		"afterCheckpoint": afterCheckpoint,
		"first":           catchUpPageSize,
		"after":           after,
	}, &resp)
	return &resp, err
}

func (l *Listener) graphQLQuery(ctx context.Context, query string, variables map[string]any, out any) error {
	body, err := json.Marshal(map[string]any{"query": query, "variables": variables})
	if err != nil {
		return fmt.Errorf("marshal graphql request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.graphqlURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build graphql request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := l.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("do graphql request: %w", err)
	}
	defer resp.Body.Close()

	var envelope struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return fmt.Errorf("decode graphql response: %w", err)
	}
	if len(envelope.Errors) > 0 {
		return fmt.Errorf("graphql error: %s", envelope.Errors[0].Message)
	}

	return json.Unmarshal(envelope.Data, out)
}

func (l *Listener) subscribeGRPC(ctx context.Context, cursor **uint64) error {
	l.logger.Info("connecting to sui grpc", zap.String("endpoint", l.grpcEndpoint))

	client := grpcconn.NewSuiGrpcClient(
		l.grpcEndpoint,
		grpcconn.WithDialOptions(grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, ""))),
	)
	defer client.Close()

	service, err := client.SubscriptionService(ctx)
	if err != nil {
		return fmt.Errorf("failed to get subscription service: %v", err)
	}

	req := &v2.SubscribeCheckpointsRequest{
		ReadMask: &fieldmaskpb.FieldMask{
			Paths: []string{"*"}, // Get all fields
		},
	}
	stream, err := service.SubscribeCheckpoints(ctx, req)
	if err != nil {
		return fmt.Errorf("SubscribeCheckpoints failed to start: %v", err)
	}

	for {
		resp, err := stream.Recv()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("recv checkpoint: %w", err)
		}

		seq, err := l.streamCheckpoint(ctx, *cursor, resp.GetCheckpoint())
		if err != nil {
			return err
		}
		*cursor = &seq
	}
}

// streamCheckpoint handles one streamed checkpoint after the stored cursor.
// The stream starts at the live checkpoint, so checkpoints between the cursor
// and it are caught up first; the cursor never passes an unread checkpoint.
func (l *Listener) streamCheckpoint(ctx context.Context, cursor *uint64, cp *v2.Checkpoint) (uint64, error) {
	seq := cp.GetSequenceNumber()
	if cursor != nil && seq > *cursor+1 {
		if err := l.catchUpRange(ctx, *cursor, seq-1); err != nil {
			return 0, err
		}
	}
	if err := l.processCheckpoint(ctx, cp); err != nil {
		return 0, err
	}
	return seq, nil
}

// processCheckpoint records every receipt event of one streamed checkpoint
// and then stores its sequence number as the cursor.
func (l *Listener) processCheckpoint(ctx context.Context, cp *v2.Checkpoint) error {
	seq := cp.GetSequenceNumber()
	for _, tx := range cp.GetTransactions() {
		for _, ev := range tx.GetEvents().GetEvents() {
			if ev.GetEventType() != l.eventType {
				continue
			}
			if _, err := l.processPaymentReceipt(ctx, ev.GetContents().GetValue(), tx.GetDigest(), seq); err != nil {
				return err
			}
		}
	}
	return l.storeCursor(ctx, seq)
}

// processPaymentReceipt decodes one receipt event and records it. An event
// that cannot be decoded is an error, like a failed write: skipping it would
// lose the payment once the cursor moves past it.
func (l *Listener) processPaymentReceipt(ctx context.Context, contents []byte, txDigest string, checkpoint uint64) (ReceiptDisposition, error) {
	if txDigest == "" {
		return "", errors.New("payment receipt event without transaction digest")
	}
	ev, err := decodePaymentReceiptEvent(contents)
	if err != nil {
		return "", fmt.Errorf("payment receipt in transaction %s: decode: %w", txDigest, err)
	}
	receipt := PaymentReceipt{
		Digest:     txDigest,
		Nonce:      ev.Nonce,
		Amount:     ev.PaymentAmount,
		CoinType:   ev.CoinType,
		Receiver:   fmt.Sprintf("0x%x", ev.Receiver[:]),
		Timestamp:  time.UnixMilli(int64(ev.TimestampMs)).UTC(),
		Checkpoint: checkpoint,
	}
	disposition, err := l.fulfiller.ApplyPaymentReceipt(ctx, receipt)
	if err != nil {
		return "", fmt.Errorf("record payment receipt %s/%s: %w", txDigest, ev.Nonce, err)
	}
	if disposition != "" {
		l.logger.Info("payment receipt recorded",
			zap.String("tx", txDigest), zap.String("nonce", ev.Nonce), zap.String("disposition", string(disposition)))
	}
	return disposition, nil
}

type paymentType struct {
	Ephemeral any
	Registry  *suiModels.SuiAddressBytes
}

func (*paymentType) IsBcsEnum() {}

type paymentReceipt struct {
	PaymentType   *paymentType
	Nonce         string
	PaymentAmount uint64
	Receiver      suiModels.SuiAddressBytes
	CoinType      string
	TimestampMs   uint64
}

// decodePaymentReceiptEvent decodes the BCS contents of a payment kit
// PaymentReceipt event. The layout is fixed by the Move struct, so bytes left
// over mean the event was not decoded as what it is.
func decodePaymentReceiptEvent(data []byte) (paymentReceipt, error) {
	var ev paymentReceipt
	n, err := mystenbcs.Unmarshal(data, &ev)
	if err != nil {
		return ev, err
	}
	if n != len(data) {
		return ev, fmt.Errorf("%d unexpected trailing bytes", len(data)-n)
	}
	if ev.TimestampMs > math.MaxInt64 {
		return ev, fmt.Errorf("timestamp %d ms out of range", ev.TimestampMs)
	}
	return ev, nil
}

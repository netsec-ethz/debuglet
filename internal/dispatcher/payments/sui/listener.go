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
	EventSeq   uint64 // position of the event among the transaction's events
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

// catchUpTo brings the stored cursor towards the full node's tip, but only
// as far as the GraphQL indexer has proven to have ingested: events of later
// checkpoints may not be visible there yet. Without a stored cursor it stores
// that bound, so a restart keeps the same starting point.
func (l *Listener) catchUpTo(ctx context.Context, cursor *uint64, tip uint64) (*uint64, error) {
	indexed, err := l.indexedCheckpoint(ctx)
	if err != nil {
		return cursor, err
	}
	bound := min(tip, indexed)
	if cursor == nil {
		if err := l.storeCursor(ctx, bound); err != nil {
			return nil, err
		}
		l.logger.Info("no stored sui cursor, starting at chain tip", zap.Uint64("checkpoint", bound))
		return &bound, nil
	}
	if *cursor >= bound {
		return cursor, nil
	}

	if err := l.catchUpRange(ctx, *cursor, bound); err != nil {
		return cursor, err
	}
	return &bound, nil
}

// catchUpRange records every receipt event of the checkpoints (after, to] and
// then stores to as the cursor. The caller has established that the indexer
// covers to. It returns on the first event that could not be recorded,
// leaving the stored cursor where it was.
func (l *Listener) catchUpRange(ctx context.Context, after, to uint64) error {
	l.logger.Info("sui catch-up: querying PaymentReceipt events via GraphQL",
		zap.Uint64("after_checkpoint", after), zap.Uint64("to", to))

	var (
		pageCursor *string
		numEvents  int
	)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		page, err := l.queryPaymentReceiptEvents(ctx, after, to+1, pageCursor)
		if err != nil {
			return fmt.Errorf("query payment receipt events: %w", err)
		}

		for _, node := range page.Events.Nodes {
			contents, err := base64.StdEncoding.DecodeString(node.Contents.Bcs)
			if err != nil {
				return fmt.Errorf("payment receipt in transaction %s: decode base64: %w", node.Transaction.Digest, err)
			}
			// The GraphQL query does not report the event's checkpoint.
			if _, err := l.processPaymentReceipt(ctx, contents, node.Transaction.Digest, node.SequenceNumber, 0); err != nil {
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

	if err := l.storeCursor(ctx, to); err != nil {
		return err
	}
	l.logger.Info("sui catch-up: done", zap.Int("events_processed", numEvents), zap.Uint64("checkpoint", to))
	return nil
}

// indexedCheckpointQuery asks for the last checkpoint whose events the
// indexer serves.
const indexedCheckpointQuery = `
query IndexedCheckpoint {
  serviceConfig {
    availableRange(type: "Query", field: "events") { last { sequenceNumber } }
  }
}`

// indexedCheckpoint returns the last checkpoint the GraphQL indexer has
// ingested events for.
func (l *Listener) indexedCheckpoint(ctx context.Context) (uint64, error) {
	var resp struct {
		ServiceConfig struct {
			AvailableRange struct {
				Last *struct {
					SequenceNumber uint64 `json:"sequenceNumber"`
				} `json:"last"`
			} `json:"availableRange"`
		} `json:"serviceConfig"`
	}
	if err := l.graphQLQuery(ctx, indexedCheckpointQuery, nil, &resp); err != nil {
		return 0, fmt.Errorf("query indexed checkpoint: %w", err)
	}
	last := resp.ServiceConfig.AvailableRange.Last
	if last == nil {
		return 0, errors.New("query indexed checkpoint: no checkpoint reported")
	}
	return last.SequenceNumber, nil
}

const paymentReceiptEventsQuery = `
query PaymentReceiptEvents($type: String!, $afterCheckpoint: UInt53, $beforeCheckpoint: UInt53, $first: Int!, $after: String) {
  events(first: $first, after: $after, filter: { type: $type, afterCheckpoint: $afterCheckpoint, beforeCheckpoint: $beforeCheckpoint }) {
    pageInfo { hasNextPage endCursor }
    nodes {
      transaction { digest }
      sequenceNumber
      contents { bcs }
    }
  }
}`

type paymentReceiptEventNode struct {
	Transaction struct {
		Digest string `json:"digest"`
	} `json:"transaction"`
	SequenceNumber uint64 `json:"sequenceNumber"`
	Contents       struct {
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

func (l *Listener) queryPaymentReceiptEvents(ctx context.Context, afterCheckpoint, beforeCheckpoint uint64, after *string) (*paymentReceiptEventsResponse, error) {
	var resp paymentReceiptEventsResponse
	err := l.graphQLQuery(ctx, paymentReceiptEventsQuery, map[string]any{
		"type":             l.eventType,
		"afterCheckpoint":  afterCheckpoint,
		"beforeCheckpoint": beforeCheckpoint,
		"first":            catchUpPageSize,
		"after":            after,
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

	state := streamState{cursor: *cursor}
	for {
		resp, err := stream.Recv()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("recv checkpoint: %w", err)
		}

		if err := l.streamCheckpoint(ctx, &state, resp.GetCheckpoint()); err != nil {
			return err
		}
		*cursor = state.cursor
	}
}

// streamState is what one subscription has covered: the stored cursor and
// the run of consecutive streamed checkpoints whose receipts are recorded.
type streamState struct {
	cursor   *uint64
	runStart uint64
	last     uint64
	running  bool
}

// streamCheckpoint records the receipts of one streamed checkpoint and
// advances the stored cursor only over checkpoints that are recorded: the
// stream starts at the live checkpoint, so the checkpoints between the cursor
// and the start of the streamed run are caught up through the indexer first,
// as far as it has ingested them. Until it covers them all, the cursor stays
// at the proven bound and the streamed receipts are recorded without moving
// it; reading them again later finds them recorded.
func (l *Listener) streamCheckpoint(ctx context.Context, st *streamState, cp *v2.Checkpoint) error {
	seq := cp.GetSequenceNumber()
	if !st.running || seq != st.last+1 {
		st.runStart, st.running = seq, true
	}
	st.last = seq
	if st.cursor != nil && *st.cursor+1 < st.runStart {
		indexed, err := l.indexedCheckpoint(ctx)
		if err != nil {
			return err
		}
		if bound := min(indexed, st.runStart-1); bound > *st.cursor {
			if err := l.catchUpRange(ctx, *st.cursor, bound); err != nil {
				return err
			}
			st.cursor = &bound
		}
	}
	if err := l.recordCheckpoint(ctx, cp); err != nil {
		return err
	}
	if st.cursor != nil && (*st.cursor+1 < st.runStart || *st.cursor >= seq) {
		return nil
	}
	if err := l.storeCursor(ctx, seq); err != nil {
		return err
	}
	st.cursor = &seq
	return nil
}

// recordCheckpoint records every receipt event of one streamed checkpoint.
func (l *Listener) recordCheckpoint(ctx context.Context, cp *v2.Checkpoint) error {
	seq := cp.GetSequenceNumber()
	for _, tx := range cp.GetTransactions() {
		for i, ev := range tx.GetEvents().GetEvents() {
			if ev.GetEventType() != l.eventType {
				continue
			}
			if _, err := l.processPaymentReceipt(ctx, ev.GetContents().GetValue(), tx.GetDigest(), uint64(i), seq); err != nil {
				return err
			}
		}
	}
	return nil
}

// processPaymentReceipt decodes one receipt event and records it. An event
// that cannot be decoded is an error, like a failed write: skipping it would
// lose the payment once the cursor moves past it.
func (l *Listener) processPaymentReceipt(ctx context.Context, contents []byte, txDigest string, eventSeq, checkpoint uint64) (ReceiptDisposition, error) {
	if txDigest == "" {
		return "", errors.New("payment receipt event without transaction digest")
	}
	ev, err := decodePaymentReceiptEvent(contents)
	if err != nil {
		return "", fmt.Errorf("payment receipt in transaction %s: decode: %w", txDigest, err)
	}
	receipt := PaymentReceipt{
		Digest:     txDigest,
		EventSeq:   eventSeq,
		Nonce:      ev.Nonce,
		Amount:     ev.PaymentAmount,
		CoinType:   ev.CoinType,
		Receiver:   fmt.Sprintf("0x%x", ev.Receiver[:]),
		Timestamp:  time.UnixMilli(int64(ev.TimestampMs)).UTC(),
		Checkpoint: checkpoint,
	}
	disposition, err := l.fulfiller.ApplyPaymentReceipt(ctx, receipt)
	if err != nil {
		return "", fmt.Errorf("record payment receipt %s event %d: %w", txDigest, eventSeq, err)
	}
	if disposition != "" {
		l.logger.Info("payment receipt recorded",
			zap.String("tx", txDigest), zap.Uint64("event", eventSeq), zap.String("nonce", ev.Nonce), zap.String("disposition", string(disposition)))
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

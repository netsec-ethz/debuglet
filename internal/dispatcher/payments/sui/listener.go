// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sui

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"debuglet/internal/dispatcher/config"
	"debuglet/internal/dispatcher/database/ddb"

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

type TransactionFulfiller interface {
	CompleteTransaction(transactionId string, ctx context.Context)
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
	cfg               *config.DispatcherConfig
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
		cfg:               cfg,
	}
}

func (l *Listener) Start(ctx context.Context) error {
	queries := ddb.New(l.db)
	raw, err := queries.GetTransactionState(ctx, l.cursorKey)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("load sui cursor: %w", err)
	}

	var cursor *uint64
	if raw.Value != "" {
		seq, err := strconv.ParseUint(raw.Value, 10, 64)
		if err != nil {
			l.logger.Warn("invalid stored sui cursor, resetting to start", zap.Error(err))
		} else {
			cursor = &seq
		}
	}

	l.logger.Info("sui event listener started", zap.String("event_type", l.eventType))

	backoff := 2 * time.Second
	for {
		cursor, err = l.catchUp(ctx, cursor)
		if err != nil {
			l.logger.Error("sui catch-up error", zap.Error(err))
		}

		err = l.subscribeGRPC(ctx, &cursor)
		if ctx.Err() != nil {
			return nil
		}
		l.logger.Warn("sui grpc stream ended, reconnecting", zap.Error(err), zap.Duration("backoff", backoff))

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
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
	tip := info.GetCheckpointHeight()

	if cursor == nil {
		l.logger.Info("no stored sui cursor, starting at chain tip", zap.Uint64("checkpoint", tip))
		return &tip, nil
	}
	if *cursor >= tip {
		return cursor, nil
	}

	l.logger.Info("sui catch-up: querying PaymentReceipt events via GraphQL",
		zap.Uint64("after_checkpoint", *cursor), zap.Uint64("to", tip))

	var (
		pageCursor *string
		numEvents  int
	)
	for {
		if ctx.Err() != nil {
			return cursor, ctx.Err()
		}

		page, err := l.queryPaymentReceiptEvents(ctx, *cursor, pageCursor)
		if err != nil {
			return cursor, fmt.Errorf("query payment receipt events: %w", err)
		}

		for _, node := range page.Events.Nodes {
			contents, err := base64.StdEncoding.DecodeString(node.Contents.Bcs)
			if err != nil {
				l.logger.Warn("PaymentReceipt: failed to decode base64 contents", zap.Error(err))
				continue
			}
			l.processPaymentReceipt(ctx, contents, node.Transaction.Digest)
			numEvents++
		}

		if !page.Events.PageInfo.HasNextPage {
			break
		}
		endCursor := page.Events.PageInfo.EndCursor
		pageCursor = &endCursor
	}

	l.logger.Info("sui catch-up: done", zap.Int("events_processed", numEvents), zap.Uint64("checkpoint", tip))

	cursor = &tip

	queries := ddb.New(l.db)
	_, err = queries.UpdateTransactionState(ctx, ddb.UpdateTransactionStateParams{Key: l.cursorKey, Value: strconv.FormatUint(tip, 10)})
	if err != nil {
		l.logger.Error("failed to persist sui cursor", zap.Error(err))
	}

	return cursor, nil
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

		cp := resp.GetCheckpoint()
		for _, tx := range cp.GetTransactions() {
			txDigest := tx.GetDigest()
			for _, ev := range tx.GetEvents().GetEvents() {
				if ev.GetEventType() != l.eventType {
					continue
				}
				l.processEventGRPC(ctx, ev, txDigest)
			}
		}

		seq := cp.GetSequenceNumber()
		*cursor = &seq

		queries := ddb.New(l.db)
		_, err = queries.UpdateTransactionState(ctx, ddb.UpdateTransactionStateParams{Key: l.cursorKey, Value: strconv.FormatUint(seq, 10)})
		if err != nil {
			l.logger.Error("failed to persist sui cursor", zap.Error(err))
		}
	}
}
func (l *Listener) processEventGRPC(ctx context.Context, ev *v2.Event, txDigest string) {
	l.processPaymentReceipt(ctx, ev.GetContents().GetValue(), txDigest)
}

func (l *Listener) processPaymentReceipt(ctx context.Context, contents []byte, txDigest string) {
	receipt, err := decodePaymentReceiptEvent(contents)
	if err != nil {
		l.logger.Warn("PaymentReceipt: failed to decode BCS contents",
			zap.String("tx", txDigest),
			zap.Error(err),
		)
		return
	}

	amount := int64(receipt.PaymentAmount)
	receiver := fmt.Sprintf("0x%x", receipt.Receiver)
	// TODO refund failed purchases
	queries := ddb.New(l.db)
	transaction, err := queries.GetTransactionByID(ctx, receipt.Nonce)
	if err != nil {
		l.logger.Warn("failed to get transaction", zap.String("id", receipt.Nonce), zap.Error(err))
		return
	}

	if transaction.Method != "SUI" && transaction.Method != "USDC" {
		l.logger.Warn("Wrong method for transaction", zap.String("found", transaction.Method))
	}
	switch transaction.Currency {
	case "SUI":
		if !strings.EqualFold(receipt.CoinType, "0x2::sui::SUI") && !strings.EqualFold(receipt.CoinType, "0000000000000000000000000000000000000000000000000000000000000002::sui::SUI") {
			l.logger.Warn("wrong coin type", zap.String("expected", "0x2::sui::SUI"), zap.String("found", receipt.CoinType))
			return
		}
	case "USDC":
		if !strings.EqualFold("0x"+receipt.CoinType, GetCoinType(transaction.Currency, l.cfg.Sui.Network)) {
			l.logger.Warn("wrong coin type", zap.String("expected", GetCoinType(transaction.Currency, l.cfg.Sui.Network)), zap.String("found", receipt.CoinType))
			return
		}
	}

	if amount != transaction.Price {
		l.logger.Warn("payment didn't match price", zap.Int64("expected", transaction.Price), zap.Int64("actual", amount))
		return
	}
	if receiver != l.receiverAddress {
		l.logger.Warn("payment to wrong address", zap.String("expected", l.receiverAddress), zap.String("actual", receiver))
		return
	}
	if receipt.Timestamp.After(transaction.ExpiresAt.Time) {
		l.logger.Warn("transaction expired", zap.Time("exp_time", transaction.ExpiresAt.Time), zap.Time("executed_at", receipt.Timestamp))
		return
	}
	l.fulfiller.CompleteTransaction(transaction.ID, ctx)
	//_, err = queries.UpdateTransactionStatus(ctx, ddb.UpdateTransactionStatusParams{ID: transaction.ID, Status: int64(models.Paid)})
	if err != nil {
		l.logger.Error("failed to mark transaction as paid", zap.String("id", transaction.ID), zap.Error(err))
		return
	}
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
	Timestamp     time.Time
}

func decodePaymentReceiptEvent(data []byte) (paymentReceipt, error) {
	var ev paymentReceipt
	if _, err := mystenbcs.Unmarshal(data, &ev); err != nil {
		return ev, err
	}
	return ev, nil
}

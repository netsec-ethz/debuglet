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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"debuglet/internal/dispatcher/db"

	"github.com/block-vision/sui-go-sdk/common/grpcconn"
	"github.com/block-vision/sui-go-sdk/models"
	"github.com/block-vision/sui-go-sdk/mystenbcs"
	v2 "github.com/block-vision/sui-go-sdk/pb/sui/rpc/v2"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

// catchUpPageSize is the maximum page size the Sui GraphQL RPC accepts for the
// events connection (requesting more errors with "Page size is too large").
const catchUpPageSize = 50

// Payment Kit package ID on Sui testnet. Source: @mysten/payment-kit constants.mjs.
const paymentKitPackageTestnet = "0x7e069abe383e80d32f2aec17b3793da82aabc8c2edf84abbf68dd7b719e71497"

const debugletRegistryTestnet = "0x856d588d43b547c0e1866ff26d61af5ce3531f9c8c3ee2fba4b0553e5a3ee830"

type Listener struct {
	grpcEndpoint    string
	graphqlURL      string
	eventType       string
	cursorKey       string
	receiverAddress string
	db              *db.UserDB
	logger          *zap.Logger
	client          *grpcconn.SuiGrpcClient
	httpClient      *http.Client
	tdb             *db.TransactionDB
}

func NewListener(grpcEndpoint, graphqlURL, receiverAddress string, userDB *db.UserDB, tdb *db.TransactionDB, logger *zap.Logger) *Listener {
	client := grpcconn.NewSuiGrpcClient(
		grpcEndpoint,
		grpcconn.WithDialOptions(grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, ""))),
	)
	return &Listener{
		grpcEndpoint:    grpcEndpoint,
		graphqlURL:      graphqlURL,
		eventType:       paymentKitPackageTestnet + "::payment_kit::PaymentReceipt",
		cursorKey:       "sui_event_cursor:" + paymentKitPackageTestnet,
		receiverAddress: strings.ToLower(receiverAddress),
		db:              userDB,
		tdb:             tdb,
		logger:          logger,
		client:          client,
		httpClient:      &http.Client{Timeout: 30 * time.Second},
	}
}

func (l *Listener) Start(ctx context.Context) error {
	raw, err := l.db.GetState(l.cursorKey)
	if err != nil {
		return fmt.Errorf("load sui cursor: %w", err)
	}

	var cursor *uint64
	if raw != "" {
		seq, err := strconv.ParseUint(raw, 10, 64)
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

// catchUp fetches and processes any checkpoints between the last recorded cursor and the
// current chain tip via gRPC, crediting balances for matching PaymentReceipt events. The
// gRPC ledger API has no server-side event-type filter, so every checkpoint in the range
// must be fetched and scanned client-side.
//
// If cursor is nil (no prior progress recorded, e.g. first deploy), catch-up is skipped
// entirely and the cursor is initialized to the current tip: replaying the full checkpoint
// history from genesis over gRPC would mean scanning millions of checkpoints one at a time.
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
			l.processPaymentReceipt(contents, node.Transaction.Digest, node.Sender.Address)
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
	if err := l.db.SetState(l.cursorKey, strconv.FormatUint(tip, 10)); err != nil {
		l.logger.Error("failed to persist sui cursor", zap.Error(err))
	}

	return cursor, nil
}

const paymentReceiptEventsQuery = `
query PaymentReceiptEvents($type: String!, $afterCheckpoint: UInt53, $first: Int!, $after: String) {
  events(first: $first, after: $after, filter: { type: $type, afterCheckpoint: $afterCheckpoint }) {
    pageInfo { hasNextPage endCursor }
    nodes {
      sender { address }
      transaction { digest }
      contents { bcs }
    }
  }
}`

type paymentReceiptEventNode struct {
	Sender struct {
		Address string `json:"address"`
	} `json:"sender"`
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

// graphQLQuery executes a GraphQL request against the Sui GraphQL RPC and decodes the "data"
// field of the response into out.
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
			sender := tx.GetTransaction().GetSender()
			for _, ev := range tx.GetEvents().GetEvents() {
				if ev.GetEventType() != l.eventType {
					continue
				}
				l.processEventGRPC(ev, txDigest, sender)
			}
		}

		seq := cp.GetSequenceNumber()
		*cursor = &seq
		if err := l.db.SetState(l.cursorKey, strconv.FormatUint(seq, 10)); err != nil {
			l.logger.Error("failed to persist sui cursor", zap.Error(err))
		}
	}
}
func (l *Listener) processEventGRPC(ev *v2.Event, txDigest, sender string) {
	l.processPaymentReceipt(ev.GetContents().GetValue(), txDigest, sender)
}

func (l *Listener) processPaymentReceipt(contents []byte, txDigest, sender string) {
	nonce, receiver, amount, err := decodePaymentReceiptEvent(contents)
	l.logger.Info("Event received", zap.String("nonce", nonce), zap.String("receiver", receiver), zap.Int64("amount", amount))
	if err != nil {
		l.logger.Warn("PaymentReceipt: failed to decode BCS contents",
			zap.String("tx", txDigest),
			zap.Error(err),
		)
		return
	}

	// TODO refund failed purchases
	transaction, err := l.tdb.GetTransaction(nonce)
	if err != nil {
		l.logger.Warn("didn't find transactionId", zap.String("id", nonce))
		return
	}

	if transaction.Method != "SUI" {
		l.logger.Warn("Wrong method for transaction", zap.String("found", transaction.Method))
	}

	//TODO verify coin type matches SUI
	if amount != transaction.Price {
		l.logger.Warn("payment didn't match price", zap.Int64("expected", transaction.Price), zap.Int64("actual", amount))
		return
	}
	if receiver != l.receiverAddress {
		l.logger.Warn("payment to wrong address", zap.String("expected", l.receiverAddress), zap.String("actual", receiver))
		return
	}

	l.tdb.SetPayed(transaction.TransactionId)

}

/*
	func (l *Listener) processEventGRPC(ev *v2.Event, txDigest, sender string) {
		nonce, receiver, amount, err := decodePaymentReceiptEvent(ev.GetContents().GetValue())
		l.logger.Info("Event received", zap.String("nonce", nonce), zap.String("receiver", receiver), zap.Int64("amount", amount))
		if err != nil {
			l.logger.Warn("PaymentReceipt: failed to decode BCS contents",
				zap.String("tx", txDigest),
				zap.Error(err),
			)
			return
		}

		if !strings.EqualFold(receiver, l.receiverAddress) {
			l.logger.Info("receiver didnt't match", zap.String("expected", l.receiverAddress))
			return
		}
		if !strings.HasPrefix(nonce, noncePrefix) {
			l.logger.Info("prefix mismatch")
			return
		}

		if amount <= 0 {
			l.logger.Warn("PaymentReceipt: non-positive amount, no balance credited",
				zap.String("tx", txDigest),
				zap.String("sender", sender),
				zap.Int64("mist", amount),
			)
			return
		}

		if err := l.db.UpdateBalance(sender, amount); err != nil {
			l.logger.Error("failed to credit balance from PaymentReceipt",
				zap.String("tx", txDigest),
				zap.String("sender", sender),
				zap.String("nonce", nonce),
				zap.Int64("balance_delta", amount),
				zap.Error(err),
			)
			return
		}

		l.logger.Info("credited balance from PaymentReceipt",
			zap.String("tx", txDigest),
			zap.String("sender", sender),
			zap.String("nonce", nonce),
			zap.Int64("balance_delta", amount),
		)
	}
*/
type paymentType struct {
	Ephemeral any
	Registry  *models.SuiAddressBytes
}

func (*paymentType) IsBcsEnum() {}

type paymentReceiptFields struct {
	PaymentType   *paymentType
	Nonce         string
	PaymentAmount uint64
	Receiver      models.SuiAddressBytes
	CoinType      string
	TimestampMs   uint64
}

func decodePaymentReceiptEvent(data []byte) (nonce, receiver string, amount int64, err error) {
	var ev paymentReceiptFields
	if _, err := mystenbcs.Unmarshal(data, &ev); err != nil {
		return "", "", 0, fmt.Errorf("BCS decode PaymentReceipt: %w", err)
	}
	return ev.Nonce, fmt.Sprintf("0x%x", ev.Receiver), int64(ev.PaymentAmount), nil
}

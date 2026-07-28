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
	"context"
	"fmt"
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

// Payment Kit package ID on Sui testnet. Source: @mysten/payment-kit constants.mjs.
const paymentKitPackageTestnet = "0x7e069abe383e80d32f2aec17b3793da82aabc8c2edf84abbf68dd7b719e71497"

const noncePrefix = "debuglet"

type Listener struct {
	rpcURL          string
	grpcEndpoint    string
	eventType       string
	cursorKey       string
	receiverAddress string
	db              *db.UserDB
	logger          *zap.Logger
	client          *grpcconn.SuiGrpcClient
}

func NewListener(rpcURL, grpcEndpoint, receiverAddress string, userDB *db.UserDB, logger *zap.Logger) *Listener {
	client := grpcconn.NewSuiGrpcClient(
		grpcEndpoint,
		grpcconn.WithDialOptions(grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, ""))),
	)
	return &Listener{
		rpcURL:          rpcURL,
		grpcEndpoint:    grpcEndpoint,
		eventType:       paymentKitPackageTestnet + "::payment_kit::PaymentReceipt",
		cursorKey:       "sui_event_cursor:" + paymentKitPackageTestnet,
		receiverAddress: strings.ToLower(receiverAddress),
		db:              userDB,
		logger:          logger,
		client:          client,
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

	l.logger.Info("sui catch-up: scanning checkpoints",
		zap.Uint64("from", *cursor+1), zap.Uint64("to", tip))

	readMask := &fieldmaskpb.FieldMask{
		Paths: []string{"transactions.digest", "transactions.transaction.sender", "transactions.events"},
	}

	for seq := *cursor + 1; seq <= tip; seq++ {
		if ctx.Err() != nil {
			return cursor, ctx.Err()
		}

		resp, err := ledger.GetCheckpoint(ctx, &v2.GetCheckpointRequest{
			CheckpointId: &v2.GetCheckpointRequest_SequenceNumber{SequenceNumber: seq},
			ReadMask:     readMask,
		})
		if err != nil {
			return cursor, fmt.Errorf("get checkpoint %d: %w", seq, err)
		}

		for _, tx := range resp.GetCheckpoint().GetTransactions() {
			txDigest := tx.GetDigest()
			sender := tx.GetTransaction().GetSender()
			for _, ev := range tx.GetEvents().GetEvents() {
				if ev.GetEventType() != l.eventType {
					continue
				}
				l.processEventGRPC(ev, txDigest, sender)
			}
		}

		seq := seq
		cursor = &seq
		if err := l.db.SetState(l.cursorKey, strconv.FormatUint(seq, 10)); err != nil {
			l.logger.Error("failed to persist sui cursor", zap.Error(err))
		}
	}

	return cursor, nil
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

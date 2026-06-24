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
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"debuglet/internal/dispatcher/db"
	suirpcv2 "debuglet/internal/dispatcher/sui/proto/sui/rpc/v2"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

// Payment Kit package ID on Sui testnet. Source: @mysten/payment-kit constants.mjs.
const paymentKitPackageTestnet = "0x7e069abe383e80d32f2aec17b3793da82aabc8c2edf84abbf68dd7b719e71497"

// noncePrefix is the required prefix for nonces this service will accept.
const noncePrefix = "debuglet"

// uint64Str handles Sui JSON's u64 encoding, which may be a number or a quoted string.
type uint64Str uint64

func (f *uint64Str) UnmarshalJSON(data []byte) error {
	var n uint64
	if err := json.Unmarshal(data, &n); err == nil {
		*f = uint64Str(n)
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("uint64Str: %w", err)
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return fmt.Errorf("uint64Str parse %q: %w", s, err)
	}
	*f = uint64Str(n)
	return nil
}

type eventCursor struct {
	TxDigest string `json:"txDigest"`
	EventSeq string `json:"eventSeq"`
}

type paymentReceiptFields struct {
	Nonce         string         `json:"nonce"`
	PaymentAmount uint64Str      `json:"payment_amount"`
	Receiver      string         `json:"receiver"`
	CoinType      string         `json:"coin_type"`
	TimestampMs   uint64Str      `json:"timestamp_ms"`
	PaymentType   map[string]any `json:"payment_type"`
}

type suiEvent struct {
	ID struct {
		TxDigest string `json:"txDigest"`
		EventSeq string `json:"eventSeq"`
	} `json:"id"`
	Sender     string               `json:"sender"`
	ParsedJSON paymentReceiptFields `json:"parsedJson"`
}

type queryResult struct {
	Data        []suiEvent   `json:"data"`
	NextCursor  *eventCursor `json:"nextCursor"`
	HasNextPage bool         `json:"hasNextPage"`
}

type rpcResponse struct {
	Result *queryResult `json:"result"`
	Error  *struct {
		Message string `json:"message"`
	} `json:"error"`
}

type Listener struct {
	rpcURL          string
	grpcEndpoint    string // host:port
	eventType       string
	cursorKey       string // keyed by package ID so a redeploy starts fresh automatically
	receiverAddress string // only process payments sent to this address
	db              *db.UserDB
	logger          *zap.Logger
}

func NewListener(rpcURL, grpcEndpoint, receiverAddress string, userDB *db.UserDB, logger *zap.Logger) *Listener {
	return &Listener{
		rpcURL:          rpcURL,
		grpcEndpoint:    grpcEndpoint,
		eventType:       paymentKitPackageTestnet + "::payment_kit::PaymentReceipt",
		cursorKey:       "sui_event_cursor:" + paymentKitPackageTestnet,
		receiverAddress: strings.ToLower(receiverAddress),
		db:              userDB,
		logger:          logger,
	}
}

func (l *Listener) Start(ctx context.Context) error {
	raw, err := l.db.GetState(l.cursorKey)
	if err != nil {
		return fmt.Errorf("load sui cursor: %w", err)
	}

	var cursor *eventCursor
	if raw != "" {
		cursor = &eventCursor{}
		if err := json.Unmarshal([]byte(raw), cursor); err != nil {
			l.logger.Warn("invalid stored sui cursor, resetting to start", zap.Error(err))
			cursor = nil
		}
	}

	l.logger.Info("sui event listener started", zap.String("event_type", l.eventType))

	backoff := 2 * time.Second
	for {
		// Catch up on any events missed since the last cursor.
		cursor, err = l.pollAll(cursor)
		if err != nil {
			l.logger.Error("sui catch-up poll error", zap.Error(err))
		}

		// Stream new events via gRPC until the connection drops or ctx is cancelled.
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

// subscribeGRPC opens a gRPC connection to the Sui node, subscribes to the checkpoint stream,
// and processes PaymentReceipt events until the stream ends or ctx is cancelled.
// It updates *cursor after each matched event for resumption on reconnect.
func (l *Listener) subscribeGRPC(ctx context.Context, cursor **eventCursor) error {
	l.logger.Info("connecting to sui grpc", zap.String("endpoint", l.grpcEndpoint))

	conn, err := grpc.NewClient(l.grpcEndpoint,
		grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, "")),
	)
	if err != nil {
		return fmt.Errorf("grpc dial: %w", err)
	}
	defer conn.Close()

	client := suirpcv2.NewSubscriptionServiceClient(conn)
	stream, err := client.SubscribeCheckpoints(ctx, &suirpcv2.SubscribeCheckpointsRequest{
		ReadMask: &fieldmaskpb.FieldMask{
			Paths: []string{"transactions"},
		},
	})
	if err != nil {
		return fmt.Errorf("subscribe checkpoints: %w", err)
	}

	for {
		resp, err := stream.Recv()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("recv checkpoint: %w", err)
		}

		for _, tx := range resp.GetCheckpoint().GetTransactions() {
			txDigest := tx.GetDigest()
			sender := tx.GetTransaction().GetSender()
			for j, ev := range tx.GetEvents().GetEvents() {
				if ev.GetEventType() != l.eventType {
					continue
				}
				l.processEventGRPC(ev, txDigest, sender)
				// Update cursor so a reconnect resumes after this event.
				*cursor = &eventCursor{TxDigest: txDigest, EventSeq: strconv.Itoa(j)}
				raw, _ := json.Marshal(*cursor)
				if err := l.db.SetState(l.cursorKey, string(raw)); err != nil {
					l.logger.Error("failed to persist sui cursor", zap.Error(err))
				}
			}
		}
	}
}

// processEventGRPC credits balance from a PaymentReceipt event received via gRPC.
func (l *Listener) processEventGRPC(ev *suirpcv2.Event, txDigest, sender string) {
	nonce, receiver, amount, err := decodePaymentReceiptEvent(ev.GetContents().GetValue())
	l.logger.Info("Event received", zap.String("nonce", nonce), zap.String("receiver", receiver,), zap.Int64("amount", amount))
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

// decodePaymentReceiptEvent decodes the BCS bytes of a PaymentReceipt Move event.
// Struct layout: { payment_type: PaymentType, nonce: String, payment_amount: u64,
//
//	receiver: address (32 bytes), coin_type: String, timestamp_ms: u64 }
//
// PaymentType enum: variant 0 = Ephemeral, variant 1 = Registry (+ 32-byte address).
func decodePaymentReceiptEvent(data []byte) (nonce, receiver string, amount int64, err error) {
	pos := 0

	// PaymentType enum variant index.
	variant, n := bcsULEB128(data[pos:])
	pos += n
	if variant == 1 {
		// Registry variant carries a 32-byte registry address.
		pos += 32
	}

	// nonce: String
	strLen, n := bcsULEB128(data[pos:])
	pos += n
	if pos+int(strLen) > len(data) {
		return "", "", 0, fmt.Errorf("BCS nonce out of bounds (len=%d, pos=%d)", len(data), pos)
	}
	nonce = string(data[pos : pos+int(strLen)])
	pos += int(strLen)

	// payment_amount: u64
	if pos+8 > len(data) {
		return "", "", 0, fmt.Errorf("BCS too short for payment_amount (len=%d, pos=%d)", len(data), pos)
	}
	amount = int64(binary.LittleEndian.Uint64(data[pos : pos+8]))
	pos += 8

	// receiver: address (32 bytes)
	if pos+32 > len(data) {
		return "", "", 0, fmt.Errorf("BCS too short for receiver (len=%d, pos=%d)", len(data), pos)
	}
	receiver = fmt.Sprintf("0x%x", data[pos:pos+32])
	return
}

// bcsULEB128 reads a variable-length unsigned integer from BCS-encoded bytes.
func bcsULEB128(data []byte) (uint64, int) {
	var result uint64
	var shift uint
	for i, b := range data {
		result |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return result, i + 1
		}
		shift += 7
	}
	return result, len(data)
}

// pollAll drains all available pages of new events starting from cursor (JSON-RPC catch-up).
func (l *Listener) pollAll(cursor *eventCursor) (*eventCursor, error) {
	for {
		result, err := l.fetchPage(cursor)
		if err != nil {
			return cursor, err
		}

		for _, ev := range result.Data {
			l.processEvent(ev)
		}

		cursor = result.NextCursor
		if cursor != nil {
			raw, _ := json.Marshal(cursor)
			if err := l.db.SetState(l.cursorKey, string(raw)); err != nil {
				l.logger.Error("failed to persist sui cursor", zap.Error(err))
			}
		}

		if !result.HasNextPage {
			return cursor, nil
		}
	}
}

func (l *Listener) fetchPage(cursor *eventCursor) (*queryResult, error) {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "suix_queryEvents",
		"params": []any{
			map[string]any{"MoveEventType": l.eventType},
			cursor,
			50,
			false,
		},
	})
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(l.rpcURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("rpc request: %w", err)
	}
	defer resp.Body.Close()

	var rpc rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpc); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if rpc.Error != nil {
		return nil, fmt.Errorf("rpc error: %s", rpc.Error.Message)
	}
	if rpc.Result == nil {
		return nil, fmt.Errorf("nil result in rpc response")
	}
	return rpc.Result, nil
}

func (l *Listener) processEvent(ev suiEvent) {
	if !strings.EqualFold(ev.ParsedJSON.Receiver, l.receiverAddress) {
		return
	}
	if !strings.HasPrefix(ev.ParsedJSON.Nonce, noncePrefix) {
		return
	}

	amount := int64(ev.ParsedJSON.PaymentAmount)
	sender := ev.Sender

	if amount <= 0 {
		l.logger.Warn("PaymentReceipt: non-positive amount, no balance credited",
			zap.String("tx", ev.ID.TxDigest),
			zap.String("sender", sender),
			zap.Int64("mist", amount),
		)
		return
	}

	if err := l.db.UpdateBalance(sender, amount); err != nil {
		l.logger.Error("failed to credit balance from PaymentReceipt",
			zap.String("tx", ev.ID.TxDigest),
			zap.String("sender", sender),
			zap.String("nonce", ev.ParsedJSON.Nonce),
			zap.Int64("balance_delta", amount),
			zap.Error(err),
		)
		return
	}

	l.logger.Info("credited balance from PaymentReceipt",
		zap.String("tx", ev.ID.TxDigest),
		zap.String("sender", sender),
		zap.String("nonce", ev.ParsedJSON.Nonce),
		zap.Int64("balance_delta", amount),
	)
}

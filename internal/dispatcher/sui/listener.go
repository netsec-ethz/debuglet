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
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"debuglet/internal/dispatcher/db"

	"go.uber.org/zap"
)

const mistPerSui = 1_000_000_000

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

type purchaseFields struct {
	Username string     `json:"username"`
	Amount   uint64Str  `json:"amount"`
}

type suiEvent struct {
	ID struct {
		TxDigest string `json:"txDigest"`
		EventSeq string `json:"eventSeq"`
	} `json:"id"`
	ParsedJSON purchaseFields `json:"parsedJson"`
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
	rpcURL       string
	eventType    string
	db           *db.UserDB
	logger       *zap.Logger
	pollInterval time.Duration
}

func NewListener(rpcURL, packageID string, userDB *db.UserDB, logger *zap.Logger, pollInterval time.Duration) *Listener {
	return &Listener{
		rpcURL:       rpcURL,
		eventType:    fmt.Sprintf("%s::contracts::DebugletPurchase", packageID),
		db:           userDB,
		logger:       logger,
		pollInterval: pollInterval,
	}
}

func (l *Listener) Start(ctx context.Context) error {
	raw, err := l.db.GetState("sui_event_cursor")
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

	ticker := time.NewTicker(l.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			cursor, err = l.pollAll(cursor)
			if err != nil {
				l.logger.Error("sui poll error", zap.Error(err))
			}
		}
	}
}

// pollAll drains all available pages of new events starting from cursor.
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
			if err := l.db.SetState("sui_event_cursor", string(raw)); err != nil {
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
	amount := uint64(ev.ParsedJSON.Amount)
	balance := int64(100*amount / mistPerSui)
	username := ev.ParsedJSON.Username

	if balance <= 0 {
		l.logger.Warn("DebugletPurchase below 1 SUI threshold, no balance credited",
			zap.String("tx", ev.ID.TxDigest),
			zap.String("username", username),
			zap.Uint64("mist", amount),
		)
		return
	}

	if err := l.db.AddBalance(username, balance); err != nil {
		l.logger.Error("failed to credit balance from DebugletPurchase",
			zap.String("tx", ev.ID.TxDigest),
			zap.String("username", username),
			zap.Int64("balance_delta", balance),
			zap.Error(err),
		)
		return
	}

	l.logger.Info("credited balance from DebugletPurchase",
		zap.String("tx", ev.ID.TxDigest),
		zap.String("username", username),
		zap.Uint64("mist", amount),
		zap.Int64("balance_delta", balance),
	)
}

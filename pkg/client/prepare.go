package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

const (
	// maxEnvelopeBytes bounds each whole encoded request envelope. Prepare
	// measures the intent; submission is measured after its metadata is known.
	maxEnvelopeBytes = 32 << 20
	// maxTimeoutMS keeps time.Duration(TimeoutMS)*time.Millisecond within
	// int64 on the server.
	maxTimeoutMS = math.MaxInt64 / int64(time.Millisecond)

	intentPrefix = `{"debuglets":`
	intentSuffix = `,"payment_method":"TEST","refund_address":""}`
)

// Prepare validates requests and freezes them into one immutable serialized
// batch used for both submission steps.
func Prepare(requests []Request) (*PreparedBatch, error) {
	if len(requests) == 0 {
		return nil, errors.New("client: empty batch")
	}
	seen := make(map[int64]int, len(requests))
	for i, r := range requests {
		if len(r.Wasm) == 0 {
			return nil, fmt.Errorf("client: request %d: empty wasm", i)
		}
		if strings.TrimSpace(r.ExecutorID) == "" {
			return nil, fmt.Errorf("client: request %d: blank executor id", i)
		}
		if previous, duplicate := seen[r.OrderID]; duplicate {
			return nil, fmt.Errorf("client: request %d: duplicate order id %d (already used by request %d)", i, r.OrderID, previous)
		}
		seen[r.OrderID] = i
		p := r.Policy
		if p.TimeoutMS <= 0 {
			return nil, fmt.Errorf("client: request %d: timeout_ms must be positive", i)
		}
		if p.TimeoutMS > maxTimeoutMS {
			return nil, fmt.Errorf("client: request %d: timeout_ms %d exceeds maximum %d", i, p.TimeoutMS, maxTimeoutMS)
		}
		if p.FloorBW < 0 {
			return nil, fmt.Errorf("client: request %d: floor_bw must not be negative", i)
		}
		if p.CeilBW < p.FloorBW {
			return nil, fmt.Errorf("client: request %d: ceil_bw must be at least floor_bw", i)
		}
	}
	// One serialization: encoding/json base64-encodes Wasm, omits nil start
	// times and empty args, and copies every value so that later mutation of
	// the caller's slices, arrays or pointers cannot change what is sent.
	debuglets, err := json.Marshal(requests)
	if err != nil {
		return nil, fmt.Errorf("client: encoding batch: %w", err)
	}
	if size := intentEnvelopeSize(debuglets); size > maxEnvelopeBytes {
		return nil, fmt.Errorf("client: encoded request envelope is %d bytes, exceeds the 32 MiB limit", size)
	}
	return &PreparedBatch{debuglets: debuglets, count: len(requests)}, nil
}

// intentEnvelopeSize is the exact size of the payment intent request body.
func intentEnvelopeSize(debuglets []byte) int {
	return len(intentPrefix) + len(debuglets) + len(intentSuffix)
}

// intentEnvelope builds the payment intent request body around the frozen
// debuglets array.
func intentEnvelope(debuglets []byte) []byte {
	body := make([]byte, 0, intentEnvelopeSize(debuglets))
	body = append(body, intentPrefix...)
	body = append(body, debuglets...)
	body = append(body, intentSuffix...)
	return body
}

// submitEnvelope builds the submission request body around the same frozen
// debuglets array, so the server's hash of the decoded values matches.
func submitEnvelope(debuglets []byte, transactionID, authKey string) ([]byte, error) {
	tx, err := json.Marshal(transactionID)
	if err != nil {
		return nil, fmt.Errorf("client: encoding transaction id: %w", err)
	}
	key, err := json.Marshal(authKey)
	if err != nil {
		return nil, fmt.Errorf("client: encoding auth key: %w", err)
	}
	const prefix = `{"debuglets":`
	size := len(prefix) + len(debuglets) + len(`,"transaction_id":`) + len(tx) + len(`,"auth_key":`) + len(key) + 1
	if size > maxEnvelopeBytes {
		return nil, fmt.Errorf("client: encoded submit envelope is %d bytes, exceeds the 32 MiB limit", size)
	}
	body := make([]byte, 0, size)
	body = append(body, prefix...)
	body = append(body, debuglets...)
	body = append(body, `,"transaction_id":`...)
	body = append(body, tx...)
	body = append(body, `,"auth_key":`...)
	body = append(body, key...)
	body = append(body, '}')
	return body, nil
}

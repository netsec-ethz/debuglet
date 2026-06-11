package dispatcher

import (
	"context"
	"time"
)

type ExecutorServer interface {
	UploadDebuglet(ctx context.Context, debugletID string, d DebugletSpec) error
	AbortDebuglet(ctx context.Context, executorID, debugletID, reason string) error
}

type Hello struct {
	ExecutorID           string
	Version              string
	SourceIP             string
	TeslaDelay           time.Duration
	TeslaAnchorTimestamp time.Time
	TeslaAnchorKey       []byte
}

type Heartbeat struct {
	ExecutorID    string
	Timestamp     time.Time
	TeslaKeyEpoch int64
	TeslaKey      []byte
}

type DebugletSpec struct {
	StartTime  *time.Time
	Wasm       []byte
	Policy     DebugletPolicy
	ExecutorID string
}

type DebugletPolicy struct {
	FloorBW   int64
	CeilBW    int64
	Timeout   time.Duration
	Addresses []string
}

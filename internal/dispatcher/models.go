package dispatcher

import (
	"context"
	"time"
)

type ExecutorSender interface {
	UploadDebuglet(ctx context.Context, debugletID string, d DebugletSpec) error
}

type ControlHandler interface {
	HandleHello(ctx context.Context, h Hello) error
	HandleHeartbeat(ctx context.Context, hb Heartbeat) error
	HandleDisconnect(ctx context.Context, executorID string)
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

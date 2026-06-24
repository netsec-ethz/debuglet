package dispatcher

import (
	"context"
	"debuglet/internal/dispatcher/resource"
	"time"
)

type ExecutorServer interface {
	UploadDebuglet(ctx context.Context, debugletID string, d DebugletSpec) error
	AbortDebuglet(ctx context.Context, executorID, debugletID, reason string) error
	DestinationUpdates(ctx context.Context, executorID string, updates []LimitUpdate) error
}

type Hello struct {
	ExecutorID           string
	Version              string
	SourceIP             string
	TeslaDelay           time.Duration
	TeslaAnchorTimestamp time.Time
	TeslaAnchorKey       []byte
	PricePerBw           float64
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
	Args       []string
	Policy     DebugletPolicy
	ExecutorID string
}

type DebugletPolicy struct {
	FloorBW   resource.Bitrate
	CeilBW    resource.Bitrate
	Timeout   time.Duration
	Addresses []string
}

type LimitUpdate struct {
	Address string
	Limit   resource.Bitrate
}

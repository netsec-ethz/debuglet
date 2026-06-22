package rpc

import (
	"context"
	"debuglet/internal/executor/ratelimit/app"
	"time"
)

type ExecutorControlHandler interface {
	HandleUpload(context.Context, Spec)
	HandleAbort(ctx context.Context, debugletID, reason string)
	HandleUpdate(ctx context.Context, updates []Update)
}

type Policy struct {
	FloorBW   int64
	CeilBW    int64
	Timeout   time.Duration
	Addresses []string
}

type Spec struct {
	DebugletID string
	StartTime  *time.Time
	Args       []string
	Wasm       []byte
	Policy     Policy
}

type Hello struct {
	ExecutorID           string
	Version              string
	SourceIP             string
	TeslaDelay           time.Duration
	TeslaAnchorTimestamp time.Time
	TeslaAnchorKey       []byte
}

type Update struct {
	Address string
	Limit   app.Bitrate
}

package rpc

import "time"

type ExecutorControlHandler interface {
	HandleUpload(Spec)
	HandleAbort(debugletID, reason string)
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

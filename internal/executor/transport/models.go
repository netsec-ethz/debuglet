package transport

import "time"

type ControlHandler interface {
	HandleUpload(Upload) error
}

type DebugletPolicy struct {
	FloorBW   int64
	CeilBW    int64
	Timeout   time.Duration
	Addresses []string
}

type Upload struct {
	DebugletID string
	Wasm       []byte
	Policy     DebugletPolicy
}

type Hello struct {
	ExecutorID           string
	Version              string
	SourceIP             string
	TeslaDelay           time.Duration
	TeslaAnchorTimestamp time.Time
	TeslaAnchorKey       []byte
}

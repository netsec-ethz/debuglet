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
	SessionID string
	Wasm      []byte
	Policy    DebugletPolicy
}

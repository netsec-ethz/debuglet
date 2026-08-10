package dispatcher

import (
	"debuglet/internal/dispatcher/resource"
	pb "debuglet/protocol"
	"time"
)

type DebugletSpec struct {
	StartTime     *time.Time
	Wasm          []byte
	Args          []string
	Policy        DebugletPolicy
	ExecutorID    string
	TransactionID string
}

type DebugletPolicy struct {
	FloorBW   resource.Bitrate
	CeilBW    resource.Bitrate
	Timeout   time.Duration
	Addresses []string
}

//go:generate stringer -type=DebugletRunState
type DebugletRunState int

const (
	RunStateUnspecified DebugletRunState = iota
	RunStateInitializing
	RunStateStarted
	// Additional states managed solely on the dispatcher's side for transparency
	RunStateUploading
	RunStateExited
)

func grpcToRunState(r pb.RunState) DebugletRunState {
	switch r {
	case pb.RunState_RUN_STATE_INITIALIZING:
		return RunStateInitializing
	case pb.RunState_RUN_STATE_STARTED:
		return RunStateStarted
	default:
		return RunStateUnspecified
	}
}

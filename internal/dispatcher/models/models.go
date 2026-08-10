package models

import (
	"database/sql/driver"
	"debuglet/internal/dispatcher/resource"
	pb "debuglet/protocol"
	"errors"
	"strings"
	"time"
)

var ErrNoCapacity = errors.New("insufficient capacity")

type DebugletSpec struct {
	StartTime     *time.Time
	Wasm          []byte
	Args          []string
	Policy        DebugletPolicy
	ExecutorID    string
	TransactionID string
}

type DebugletPolicy struct {
	FloorBW     resource.Bitrate
	CeilBW      resource.Bitrate
	Timeout     time.Duration
	Addresses   []string
	RequireICMP bool
	ListenUDP   bool
	ListenTCP   bool
	ListenICMP  bool
	ListenSCION bool
}

type DebugletRunState int

const (
	RunStateUnspecified DebugletRunState = iota
	RunStateInitializing
	RunStateStarted
	// Additional states managed solely on the dispatcher's side for transparency
	RunStateUploading
	RunStateUploaded
	RunStateExited
)

func GrpcToRunState(r pb.RunState) DebugletRunState {
	switch r {
	case pb.RunState_RUN_STATE_INITIALIZING:
		return RunStateInitializing
	case pb.RunState_RUN_STATE_STARTED:
		return RunStateStarted
	default:
		return RunStateUnspecified
	}
}

func (d DebugletRunState) String() string {
	switch d {
	case RunStateUnspecified:
		return "RunStateUnspecified"
	case RunStateInitializing:
		return "RunStateInitializing"
	case RunStateStarted:
		return "RunStateStarted"
	case RunStateUploading:
		return "RunStateUploading"
	case RunStateUploaded:
		return "RunStateUploaded"
	case RunStateExited:
		return "RunStateExited"
	default:
		panic("invalid DebugletRunState")
	}
}

type CommaSeparatedList []string

func (c *CommaSeparatedList) Scan(src any) error {
	switch v := src.(type) {
	case string:
		*c = strings.Split(v, ",")
	case []byte:
		*c = strings.Split(string(v), ",")
	case nil:
		*c = nil
	default:
		return errors.New("unsupported type for CommaSeparatedList")
	}
	return nil
}

func (c CommaSeparatedList) Value() (driver.Value, error) {
	if len(c) == 0 {
		return nil, nil
	}
	return strings.Join(c, ","), nil
}

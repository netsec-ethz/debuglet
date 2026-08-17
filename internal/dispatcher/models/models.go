package models

import (
	"database/sql/driver"
	"debuglet/internal/dispatcher/resource"
	pb "debuglet/protocol"
	"errors"
	"fmt"
	"strings"
	"time"
)

type DebugletSpec struct {
	StartTime  *time.Time
	Wasm       []byte
	Args       []string
	Policy     DebugletPolicy
	ExecutorID string
	// TransactionID is required for refunding aborted debuglets
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

// CommaSeparatedList allows simple lists of strings to be stored in a single database column as a comma-separated string.
type CommaSeparatedList []string

func (c *CommaSeparatedList) Scan(src any) error {
	switch v := src.(type) {
	case string:
		if v == "" {
			*c = nil
			return nil
		}
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

// UTCTime is a wrapper around time.Time that ensures the time is always stored and retrieved in UTC.
type UTCTime struct {
	time.Time
}

func NewUTCTime(t time.Time) UTCTime {
	return UTCTime{Time: t.UTC()}
}

func (t UTCTime) Value() (driver.Value, error) {
	if t.IsZero() {
		return nil, nil
	}
	return t.Time.UTC(), nil
}

func (t *UTCTime) Scan(src any) error {
	switch v := src.(type) {
	case time.Time:
		t.Time = v.UTC()
		return nil
	case string:
		parsed, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return err
		}
		t.Time = parsed.UTC()
		return nil
	default:
		return fmt.Errorf("cannot scan %T into UTCTime", src)
	}
}

type TransactionState int

const (
	Outstanding TransactionState = iota
	Expired
	Aborted
	Paid
	Refunded
)

func (d TransactionState) String() string {
	switch d {
	case Outstanding:
		return "TransactionOutstanding"
	case Paid:
		return "TransactionPaid"
	case Expired:
		return "TransactionExpired"
	case Aborted:
		return "TransactionAborted"
	case Refunded:
		return "TransactionRefunded"
	default:
		panic("invalid TransactionState")
	}
}

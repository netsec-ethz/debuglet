package models

import (
	"math"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
)

// The ranges a policy's numbers are admitted in, in the units the contract
// states them in: bits per second and whole milliseconds. api/openapi.yaml
// documents the same bounds. They are applied by CheckPolicyNumbers, so the
// HTTP boundary and admission hold a policy to one set of ranges: a request
// that arrives over HTTP is checked before anything is converted from it, and a
// spec that reaches admission from the control protocol is checked there.
const (
	// MaxPolicyTimeoutMS is the largest run budget. Above it
	// time.Duration(timeout_ms)*time.Millisecond overflows int64 and the run
	// would silently be given a different budget than the one that was priced.
	MaxPolicyTimeoutMS = int64(math.MaxInt64) / int64(time.Millisecond)
	// MaxPolicyTimeout is the same budget as the duration it converts into.
	MaxPolicyTimeout = time.Duration(MaxPolicyTimeoutMS) * time.Millisecond
	// MaxPolicyBandwidthBPS is the largest bandwidth a single run may ask for.
	// A bandwidth is summed with the other runs of its executor and of its
	// destinations before a run is admitted, so this single-run bound is what
	// keeps those aggregates exact.
	MaxPolicyBandwidthBPS = int64(resource.MaxBitrate)
)

// PolicyBound identifies the range a policy's numbers leave. Each caller
// reports it in its own words, because the message names the field of the
// contract the caller answers on.
type PolicyBound int

const (
	PolicyBoundOK PolicyBound = iota
	PolicyBoundTimeout
	PolicyBoundFloor
	PolicyBoundCeil
	PolicyBoundCeilBelowFloor
)

// CheckPolicyNumbers reports the first admitted range the numbers of a policy
// leave, and PolicyBoundOK when all of them are admissible. Its arguments are
// the values as the contract states them, so that a caller can apply it before
// any conversion, price or aggregate is derived from a number that is not
// admitted. A budget is bounded in whole milliseconds: the executor admits
// nothing shorter than one, and the reserved window is what rejects the
// fraction of a millisecond above the largest admitted budget.
//
// A policy outside several ranges at once is reported by the first of them in
// the order below — the budget, the floor, the ceiling, and the ceiling against
// the floor — which is the field the HTTP contract has always named for such a
// request.
func CheckPolicyNumbers(floorBPS, ceilBPS, timeoutMS int64) PolicyBound {
	switch {
	case timeoutMS < 1 || timeoutMS > MaxPolicyTimeoutMS:
		return PolicyBoundTimeout
	case floorBPS < 0 || floorBPS > MaxPolicyBandwidthBPS:
		return PolicyBoundFloor
	case ceilBPS < 0 || ceilBPS > MaxPolicyBandwidthBPS:
		return PolicyBoundCeil
	case ceilBPS < floorBPS:
		return PolicyBoundCeilBelowFloor
	}
	return PolicyBoundOK
}

package controlsession

import "fmt"

// EndKind selects session retry policy independently of peer error text.
type EndKind uint8

const (
	TransportUnavailable EndKind = iota + 1
	LeaseExpired
	ParentStopped
	IncompatibleProfile
	LocalFailure
)

func (k EndKind) String() string {
	switch k {
	case TransportUnavailable:
		return "transport unavailable"
	case LeaseExpired:
		return "lease expired"
	case ParentStopped:
		return "parent stopped"
	case IncompatibleProfile:
		return "incompatible control profile"
	case LocalFailure:
		return "local failure"
	default:
		return "unknown cause"
	}
}

// EndError contains only a previously sanitized cause. Transport code must
// remove reflected credentials before retaining a peer error here.
type EndError struct {
	Kind EndKind
	Err  error
}

func (e *EndError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Err == nil {
		return fmt.Sprintf("control session ended: %s", e.Kind)
	}
	return fmt.Sprintf("control session ended: %s: %v", e.Kind, e.Err)
}

func (e *EndError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

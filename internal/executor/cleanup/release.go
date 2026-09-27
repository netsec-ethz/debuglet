package cleanup

import "errors"

// releaseError marks the part of an error that a resource release returned.
type releaseError struct{ err error }

func (e *releaseError) Error() string       { return e.err.Error() }
func (e *releaseError) Unwrap() error       { return e.err }
func (e *releaseError) CleanupError() error { return e.err }

// Join returns err with the rollback failure releaseErr attached, or err alone
// when releaseErr is nil. errors.Is still finds both in the result; Released
// finds only releaseErr.
func Join(err, releaseErr error) error {
	if releaseErr == nil {
		return err
	}
	return errors.Join(err, &releaseError{releaseErr})
}

// Released returns the release failure attached to err, or nil when there is
// none, without treating the failure that caused the rollback as a cleanup
// failure. It recognises any error in the chain with a CleanupError() error
// method, so a test fixture can stand in for a constructor's result.
func Released(err error) error {
	var released interface{ CleanupError() error }
	if errors.As(err, &released) {
		return released.CleanupError()
	}
	return nil
}

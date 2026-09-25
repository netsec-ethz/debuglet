package ebpf

import (
	"errors"
	"io"
)

// Constructor release failures are separate from unavailable BPF support or a
// failed initial key update. The caller may fall back while retaining only the
// resource failure for its eventual cleanup result.
type cleanupError struct{ err error }

func (e *cleanupError) Error() string       { return e.err.Error() }
func (e *cleanupError) Unwrap() error       { return e.err }
func (e *cleanupError) CleanupError() error { return e.err }

// CleanupError projects constructor rollback failures without treating the
// initialization error itself as a cleanup failure. It is available on every
// platform so the parent constructor can retain the same ownership contract.
func CleanupError(err error) error {
	var cleanup interface{ CleanupError() error }
	if errors.As(err, &cleanup) {
		return cleanup.CleanupError()
	}
	return nil
}

func withCleanupError(err, releaseErr error) error {
	if releaseErr == nil {
		return err
	}
	return errors.Join(err, &cleanupError{releaseErr})
}

// Generated object Close helpers return at the first error. Rollback and normal
// tagger Close must attempt each individually acquired resource instead.
func closeResources(closers ...io.Closer) error {
	var err error
	for _, closer := range closers {
		if closer != nil {
			err = errors.Join(err, closer.Close())
		}
	}
	return err
}

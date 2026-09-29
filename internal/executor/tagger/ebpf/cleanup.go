package ebpf

import (
	"errors"
	"io"
)

// Constructor release failures are separate from unavailable BPF support or a
// failed initial key update: the constructor attaches them with cleanup.Join,
// and the caller that falls back keeps only cleanup.Released for its eventual
// cleanup result.

// Generated object Close helpers return at the first error. Rollback and the
// tagger's Close must attempt each individually acquired resource instead; Close
// closes the attachment on its own first, to learn whether the program is
// detached, and the remaining resources through closeResources.
func closeResources(closers ...io.Closer) error {
	var err error
	for _, closer := range closers {
		if closer != nil {
			err = errors.Join(err, closer.Close())
		}
	}
	return err
}

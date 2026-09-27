// Package cleanup is the one place executor components classify resource
// release failures. It depends on nothing else in the executor, so a resource
// implementation and the constructor or factory that falls back from it can
// both use it without depending on each other.
//
// Two questions are answered here:
//
//   - Did a failure leave resources behind? ErrCleanupFailed and
//     ErrCleanupUnconfirmed mark a failed packet counter construction whose
//     rollback failed or could not be confirmed, so the factory refuses to fall
//     back. They are matched with errors.Is.
//   - Which part of a failure was the release? Join attaches the release
//     failure of a rollback to the error that caused it, and Released projects
//     that part back out, so a caller that does fall back can keep only the
//     release failure for its own cleanup result.
package cleanup

import "errors"

// ErrCleanupFailed means an application-owned resource release returned an error.
// The returned error also retains each underlying release error for errors.Is.
var ErrCleanupFailed = errors.New("packet counter cleanup failed")

// ErrCleanupUnconfirmed means the BPF loader failed and did not expose the result
// of its internally owned rollback. It does not assert that cleanup failed.
var ErrCleanupUnconfirmed = errors.New("packet counter cleanup unconfirmed")

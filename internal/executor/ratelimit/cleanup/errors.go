// Package cleanup identifies packet-counter disposal failures without introducing
// a dependency between the counter implementations and their factory.
package cleanup

import "errors"

// ErrCleanupFailed means an application-owned resource release returned an error.
// The returned error also retains each underlying release error for errors.Is.
var ErrCleanupFailed = errors.New("packet counter cleanup failed")

// ErrCleanupUnconfirmed means the BPF loader failed and did not expose the result
// of its internally owned rollback. It does not assert that cleanup failed.
var ErrCleanupUnconfirmed = errors.New("packet counter cleanup unconfirmed")

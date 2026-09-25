//go:build !linux && !darwin

package sqlite

import "io/fs"

// A platform without these cannot be told who owns a file or how many names it
// has, so the operations that depend on knowing report that rather than
// guessing.
const (
	openWithoutFollowing = 0
	openWithoutWaiting   = 0
)

func fileOwner(fs.FileInfo) (uid, gid int, ok bool) { return 0, 0, false }

func fileNames(fs.FileInfo) (names uint64, ok bool) { return 0, false }

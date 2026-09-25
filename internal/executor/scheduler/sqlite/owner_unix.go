//go:build linux || darwin

package sqlite

import (
	"io/fs"
	"syscall"
)

// openWithoutFollowing keeps an open from resolving a symbolic link at the
// last component, so a name replaced in a directory this command does not own
// cannot redirect what the open reaches.
const openWithoutFollowing = syscall.O_NOFOLLOW

// openWithoutWaiting keeps an open from waiting until somebody opens the other
// end, so a named pipe left in place of a file this command opens cannot stop
// it indefinitely.
const openWithoutWaiting = syscall.O_NONBLOCK

// fileOwner reports the account a file belongs to.
func fileOwner(info fs.FileInfo) (uid, gid int, ok bool) {
	stat, isStat := info.Sys().(*syscall.Stat_t)
	if !isStat {
		return 0, 0, false
	}
	return int(stat.Uid), int(stat.Gid), true
}

// fileNames reports how many names a file has. A file with more than one is
// reachable under a name this command never made, so ownership applied to it
// is applied to that name too.
func fileNames(info fs.FileInfo) (names uint64, ok bool) {
	stat, isStat := info.Sys().(*syscall.Stat_t)
	if !isStat {
		return 0, false
	}
	return uint64(stat.Nlink), true
}

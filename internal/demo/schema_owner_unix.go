//go:build linux || darwin

package demo

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

func schemaParentOwned(info fs.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Uid) != uint64(os.Geteuid()) {
		return errors.New("fresh database parent must be owned by the current user: this state directory belongs to the service account, so this installation cannot create the database in it; run dbl service uninstall --purge and install again")
	}
	return nil
}

// OpenWithoutWaiting is the open flag that keeps opening a named pipe from
// waiting until somebody opens the other end. A privileged command that opens
// what it finds in a directory another account writes needs it, or that
// account can stop the command indefinitely by leaving a pipe there.
const OpenWithoutWaiting = syscall.O_NONBLOCK

// FileNames reports how many names a file has. A regular file with more than
// one is reachable under a name this caller never created and may not be able
// to see, so ownership applied to it is applied to that name too.
func FileNames(info fs.FileInfo) (uint64, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(stat.Nlink), true
}

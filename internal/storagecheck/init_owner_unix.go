//go:build linux || darwin

package storagecheck

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

func schemaParentOwned(info fs.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Uid) != uint64(os.Geteuid()) {
		return errors.New("fresh database parent must be owned by the current user")
	}
	return nil
}

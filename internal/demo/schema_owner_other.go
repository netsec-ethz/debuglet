//go:build !linux && !darwin

package demo

import (
	"errors"
	"io/fs"
)

func schemaParentOwned(fs.FileInfo) error {
	return errors.New("fresh demo database bootstrap is unsupported on this platform")
}

// OpenWithoutWaiting has no equivalent here, and FileNames reports that the
// number of names a file has cannot be read, which refuses the operations that
// depend on knowing it.
const OpenWithoutWaiting = 0

func FileNames(fs.FileInfo) (uint64, bool) { return 0, false }

//go:build !linux && !darwin

package storagecheck

import (
	"errors"
	"io/fs"
)

func schemaParentOwned(fs.FileInfo) error {
	return errors.New("fresh database initialization is unsupported on this platform")
}

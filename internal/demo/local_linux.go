//go:build linux

package demo

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func lockLocalState(dir string) (func() error, error) {
	file, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, fmt.Errorf("local environment is already running or state cannot be locked: %w", err)
	}
	return func() error {
		return errors.Join(syscall.Flock(int(file.Fd()), syscall.LOCK_UN), file.Close())
	}, nil
}

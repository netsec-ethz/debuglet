//go:build !linux

package procinventory

import "errors"

var errUnsupported = errors.New("process inventory requires Linux procfs")

// Read is unavailable without procfs.
func Read(int) (Process, error) { return Process{}, errUnsupported }

// Descendants is unavailable without procfs.
func Descendants(int) ([]int, error) { return nil, errUnsupported }

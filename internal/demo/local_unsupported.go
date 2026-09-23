//go:build !linux

package demo

import "errors"

func lockLocalState(string) (func() error, error) {
	return nil, errors.New("local environment requires Linux")
}

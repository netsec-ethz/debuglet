//go:build !linux

package demo

import (
	"context"
	"errors"
)

type Child struct{}

func StartChild(ChildSpec) (*Child, error) { return nil, errors.New("installed demo requires Linux") }
func (*Child) PID() int                    { return 0 }
func (*Child) Done() <-chan struct{}       { ch := make(chan struct{}); close(ch); return ch }
func (*Child) Wait(context.Context) error  { return errors.New("installed demo requires Linux") }
func (*Child) Stop(context.Context) error  { return errors.New("installed demo requires Linux") }
func (*Child) CleanupComplete() bool       { return false }

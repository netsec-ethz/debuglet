//go:build !linux

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package isolation

import (
	"context"
	"errors"
	"os"
)

type Supervisor struct{}
type Process struct{}

func New(c Config) (*Supervisor, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if c.Shared() {
		return nil, errors.New("shared isolation requires Linux with delegated cgroup v2")
	}
	return nil, nil
}
func (*Supervisor) Config() Config                                            { return Config{} }
func (*Supervisor) Close() error                                              { return nil }
func (*Supervisor) Start(context.Context, *os.File, string) (*Process, error) { return nil, ErrWorker }
func (*Process) Compiled()                                                    {}
func (*Process) RunLimits() error                                             { return ErrWorker }
func (*Process) Done() <-chan struct{}                                        { return nil }
func (*Process) Close() error                                                 { return nil }

func (*Process) BudgetExceeded() bool { return false }

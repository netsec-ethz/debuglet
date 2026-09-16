// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build !linux

package ebpf

import (
	"debuglet/internal/executor/debuglet/socket/netutil"
	"debuglet/internal/executor/ratelimit/app"
	"errors"
	"net"

	"github.com/google/uuid"
)

var ErrNotAvailable = errors.New("ebpf: not available on this platform")

type BpfCount struct{}

func NewBPFCount(*net.Interface) (*BpfCount, error)                    { return nil, ErrNotAvailable }
func (*BpfCount) Close() error                                         { return ErrNotAvailable }
func (*BpfCount) Attach(net.Conn, uuid.UUID, string) (net.Conn, error) { return nil, ErrNotAvailable }
func (*BpfCount) SetLimit(string, uuid.UUID, app.Bitrate) error        { return ErrNotAvailable }
func (*BpfCount) DeleteLimit(netutil.IPv6, uuid.UUID) error            { return ErrNotAvailable }
func (*BpfCount) SetExecLimit(uuid.UUID, app.Bitrate) error            { return ErrNotAvailable }
func (*BpfCount) DeleteExecLimit(uuid.UUID) error                      { return ErrNotAvailable }
func (*BpfCount) Detach(string, uuid.UUID, netutil.IPv6) error         { return ErrNotAvailable }
func (*BpfCount) Type() string                                         { return "ebpf" }

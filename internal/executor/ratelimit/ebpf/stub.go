//go:build !linux

package ebpf

import (
	"debuglet/internal/executor/ratelimit/app"
	"errors"
	"net"
	"net/netip"

	"github.com/google/uuid"
)

var ErrNotAvailable = errors.New("ebpf: not available on this platform")

type BpfCount struct{}

func NewBPFCount(*net.Interface) (*BpfCount, error)                 { return nil, ErrNotAvailable }
func (*BpfCount) Close() error                                      { return ErrNotAvailable }
func (*BpfCount) Attach(net.Conn, uuid.UUID) (net.Conn, error)      { return nil, ErrNotAvailable }
func (*BpfCount) SetLimit(netip.Addr, uuid.UUID, app.Bitrate) error { return ErrNotAvailable }
func (*BpfCount) DeleteLimit(netip.Addr, uuid.UUID) error           { return ErrNotAvailable }
func (*BpfCount) SetExecLimit(uuid.UUID, app.Bitrate) error         { return ErrNotAvailable }
func (*BpfCount) DeleteExecLimit(uuid.UUID) error                   { return ErrNotAvailable }
func (*BpfCount) Type() string                                      { return "ebpf" }

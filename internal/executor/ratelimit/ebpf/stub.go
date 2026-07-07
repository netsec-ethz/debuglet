//go:build !linux

package ebpf

import (
	"errors"
	"fmt"
	"net/netip"
	"syscall"

	"github.com/google/uuid"
)

type PacketCount struct{}

func NewCount(ifaceName string) (*PacketCount, error) {
	return nil, fmt.Errorf("ebpf: eBPF ratelimiting is only available on Linux")
}

func (pc *PacketCount) Close() {}

func (pc *PacketCount) Attach(conn syscall.Conn, id uuid.UUID) (uint32, error) {
	return 0, errors.New("ebpf: not available on this platform")
}

func (pc *PacketCount) Detach(socketID uint32) error {
	return nil
}

func (pc *PacketCount) SetLimit(addr netip.Addr, id uuid.UUID, limit uint64) error {
	return errors.New("ebpf: not available on this platform")
}

func (pc *PacketCount) SetExecLimit(id uuid.UUID, limit uint64) error {
	return errors.New("ebpf: not available on this platform")
}

func (pc *PacketCount) DeleteLimit(addr netip.Addr, id uuid.UUID) error {
	return nil
}

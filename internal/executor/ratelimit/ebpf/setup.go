//go:build linux

package ebpf

import (
	"debuglet/internal/executor/ratelimit/app"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/google/uuid"
)

type PacketCount struct {
	objs   countObjects
	egress link.Link
}

func NewCount(iface *net.Interface) (*PacketCount, error) {
	var objs countObjects
	if err := loadCountObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load eBPF objects: %w", err)
	}
	success := false
	defer func() {
		if !success {
			objs.Close()
		}
	}()

	egr, err := link.AttachTCX(link.TCXOptions{
		Program:   objs.HandleEgress,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to attach egress TCX: %w", err)
	}

	success = true
	return &PacketCount{
		objs:   objs,
		egress: egr,
	}, nil
}

func (pc *PacketCount) Close() {
	if pc == nil {
		return
	}
	pc.egress.Close()
	pc.objs.Close()
}

func (pc *PacketCount) Attach(conn syscall.Conn, id uuid.UUID) (uint32, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("failed to get conn: %w", err)
	}

	var fdErr error
	var socketID uint32

	err = rawConn.Control(func(fd uintptr) {
		info := countDebugletUuid{Uuid: [16]byte(id)}
		fdErr = pc.objs.DebugletSkMap.Update(uint32(fd), &info, ebpf.UpdateAny)
		socketID = uint32(fd)
	})
	if err != nil {
		return 0, fmt.Errorf("failed call control: %w", err)
	}
	if fdErr != nil {
		return 0, fmt.Errorf("failed to update socket map: %w", fdErr)
	}
	return socketID, nil
}

func (pc *PacketCount) Detach(socketID uint32) error {
	return pc.objs.DebugletSkMap.Delete(socketID)
}

func (pc *PacketCount) SetLimit(addr netip.Addr, id uuid.UUID, limit app.Bitrate) error {
	v6Bytes := addr.As16()
	key := countDebugletKey{
		Uuid: [16]byte(id),
		Ipv6: v6Bytes,
	}
	bytes := uint64(limit.Bytes())
	return pc.objs.RatesMap.Update(&key, &bytes, ebpf.UpdateAny)
}

func (pc *PacketCount) SetExecLimit(id uuid.UUID, limit app.Bitrate) error {
	key := countExecKey{Uuid: [16]byte(id)}
	bytes := uint64(limit.Bytes())
	return pc.objs.ExecRatesMap.Update(&key, &bytes, ebpf.UpdateAny)
}

func (pc *PacketCount) DeleteLimit(addr netip.Addr, id uuid.UUID) error {
	v6Bytes := addr.As16()
	key := countDebugletKey{
		Uuid: [16]byte(id),
		Ipv6: v6Bytes,
	}
	return pc.objs.RatesMap.Delete(&key)
}

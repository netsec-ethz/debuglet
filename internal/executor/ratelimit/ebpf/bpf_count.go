//go:build linux

package ebpf

import (
	"debuglet/internal/executor/ratelimit/app"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/google/uuid"
)

// BpfCount employs ratelimiting using an EBPF layer. It requires root priviliges to work.
type BpfCount struct {
	objs    countObjects
	egress  link.Link
	ingress link.Link
}

func NewBPFCount(iface *net.Interface) (*BpfCount, error) {
	var objs countObjects
	if err := loadCountObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load eBPF objects: %w", err)
	}

	egr, err := link.AttachTCX(link.TCXOptions{
		Program:   objs.HandleEgress,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("failed to attach egress TCX: %w", err)
	}

	ingr, err := link.AttachTCX(link.TCXOptions{
		Program:   objs.HandleIngress,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		egr.Close()
		objs.Close()
		return nil, fmt.Errorf("failed to attach ingress TCX: %w", err)
	}

	return &BpfCount{
		objs:    objs,
		egress:  egr,
		ingress: ingr,
	}, nil
}

func (bc *BpfCount) Close() error {
	bc.egress.Close()
	bc.ingress.Close()
	bc.objs.Close()
	return nil
}

func (bc *BpfCount) Attach(conn net.Conn, id uuid.UUID) (net.Conn, error) {
	c, ok := conn.(syscall.Conn)
	if !ok {
		return nil, errors.New("failed to extract syscall Conn")
	}
	rawConn, err := c.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("failed to get conn: %w", err)
	}

	var fdErr error
	var socketID uint32

	err = rawConn.Control(func(fd uintptr) {
		info := countDebugletUuid{Uuid: [16]byte(id)}
		fdErr = bc.objs.DebugletSkMap.Update(uint32(fd), &info, ebpf.UpdateAny)
		socketID = uint32(fd)
	})
	if err != nil {
		return nil, fmt.Errorf("failed call control: %w", err)
	}
	if fdErr != nil {
		return nil, fmt.Errorf("failed to update socket map: %w", fdErr)
	}

	return &BpfConn{count: bc, conn: conn, socketID: socketID}, nil
}

func (bc *BpfCount) SetLimit(addr netip.Addr, id uuid.UUID, limit app.Bitrate) error {
	v6Bytes := addr.As16()
	key := countDebugletKey{
		Uuid: [16]byte(id),
		Ipv6: v6Bytes,
	}
	bytes := uint64(limit.Bytes())
	return bc.objs.RatesMap.Update(&key, &bytes, ebpf.UpdateAny)
}

func (bc *BpfCount) DeleteLimit(addr netip.Addr, id uuid.UUID) error {
	v6Bytes := addr.As16()
	key := countDebugletKey{
		Uuid: [16]byte(id),
		Ipv6: v6Bytes,
	}
	return bc.objs.RatesMap.Delete(&key)
}

func (bc *BpfCount) SetExecLimit(id uuid.UUID, limit app.Bitrate) error {
	key := countExecKey{Uuid: [16]byte(id)}
	bytes := uint64(limit.Bytes())
	return bc.objs.ExecRatesMap.Update(&key, &bytes, ebpf.UpdateAny)
}

func (bc *BpfCount) DeleteExecLimit(id uuid.UUID) error {
	key := countExecKey{Uuid: [16]byte(id)}
	return bc.objs.ExecRatesMap.Delete(&key)
}

func (f *BpfCount) Type() string { return "ebpf" }

//go:build linux

package ebpf

import (
	"debuglet/internal/executor/debuglet/socket/netutil"
	"debuglet/internal/executor/ratelimit/app"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/google/uuid"
)

type domainKey struct {
	domain string
	id     uuid.UUID
}

// BpfCount employs ratelimiting using an EBPF layer. It requires root priviliges to work.
type BpfCount struct {
	objs    countObjects
	egress  link.Link
	ingress link.Link

	mu        sync.Mutex
	domainIPs map[domainKey]map[netutil.IPv6]int
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
		objs:      objs,
		egress:    egr,
		ingress:   ingr,
		domainIPs: make(map[domainKey]map[netutil.IPv6]int),
	}, nil
}

func (bc *BpfCount) Close() error {
	bc.egress.Close()
	bc.ingress.Close()
	bc.objs.Close()
	return nil
}

func (bc *BpfCount) Attach(conn net.Conn, id uuid.UUID, addr string) (net.Conn, error) {
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

	host, err := netutil.HostFromAddr(conn.RemoteAddr().String())
	if err != nil {
		return nil, err
	}
	remoteIP, err := netip.ParseAddr(host)
	if err != nil {
		return nil, fmt.Errorf("failed to parse remote address: %w", err)
	}
	ipv6 := netutil.ToIPv6(remoteIP)

	bc.mu.Lock()
	defer bc.mu.Unlock()
	dk := domainKey{domain: addr, id: id}
	if _, ok := bc.domainIPs[dk]; !ok {
		bc.domainIPs[dk] = make(map[netutil.IPv6]int)
	}
	bc.domainIPs[dk][ipv6]++

	return &BpfConn{count: bc, conn: conn, socketID: socketID, domain: addr, id: id, resolvedIPv6: ipv6}, nil
}

func (bc *BpfCount) SetLimit(addr string, id uuid.UUID, limit app.Bitrate) error {
	parsedIP, err := netip.ParseAddr(addr)
	if err == nil {
		return bc.setIPv6Limit(netutil.ToIPv6(parsedIP), id, limit)
	}

	bc.mu.Lock()
	defer bc.mu.Unlock()
	ips := bc.domainIPs[domainKey{domain: addr, id: id}]
	for ipv6 := range ips {
		if err := bc.setIPv6Limit(ipv6, id, limit); err != nil {
			return err
		}
	}
	return nil
}

func (bc *BpfCount) setIPv6Limit(addr netutil.IPv6, id uuid.UUID, limit app.Bitrate) error {
	v6Bytes := addr.IP.As16()
	key := countDebugletKey{
		Uuid: [16]byte(id),
		Ipv6: v6Bytes,
	}
	bytes := uint64(limit.Bytes())
	return bc.objs.RatesMap.Update(&key, &bytes, ebpf.UpdateAny)
}

func (bc *BpfCount) DeleteLimit(addr netutil.IPv6, id uuid.UUID) error {
	v6Bytes := addr.IP.As16()
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

func (bc *BpfCount) Detach(addr string, id uuid.UUID, ipv6 netutil.IPv6) error {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	dk := domainKey{domain: addr, id: id}
	ips, ok := bc.domainIPs[dk]
	if !ok {
		return nil
	}
	ips[ipv6]--
	if ips[ipv6] <= 0 {
		delete(ips, ipv6)
		if err := bc.objs.RatesMap.Delete(&countDebugletKey{
			Uuid: [16]byte(id),
			Ipv6: ipv6.IP.As16(),
		}); err != nil {
			return err
		}
	}
	if len(ips) == 0 {
		delete(bc.domainIPs, dk)
	}
	return nil
}

func (f *BpfCount) Type() string { return "ebpf" }

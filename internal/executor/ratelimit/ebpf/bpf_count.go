// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket/netutil"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/app"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/cleanup"
	"io"
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
	cleanup counterCleanup

	mu        sync.Mutex
	domainIPs map[domainKey]map[netutil.IPv6]int
}

func NewBPFCount(iface *net.Interface) (*BpfCount, error) {
	return newBPFCount(iface, counterDependencies{
		load: func() (countObjects, []counterResource, error) {
			var objects countObjects
			if err := loadCountObjects(&objects, nil); err != nil {
				// cilium/ebpf v0.21.0 LoadAndAssign retains ownership on error
				// and closes partial loads itself, without exposing close errors.
				// Do not close the partially assigned fields a second time.
				return countObjects{}, nil, err
			}
			return objects, counterObjectResources(&objects), nil
		},
		attach: func(opts link.TCXOptions) (io.Closer, error) {
			attached, err := link.AttachTCX(opts)
			if attached == nil {
				return nil, err
			}
			return attached, err
		},
	})
}

// Construction-fixed test seams model ownership transfer, not kernel behavior.
// load transfers its resources only on success. attach transfers any returned
// nonnil handle, including a handle returned alongside an error.
type counterDependencies struct {
	load   func() (countObjects, []counterResource, error)
	attach func(link.TCXOptions) (io.Closer, error)
}

func newBPFCount(iface *net.Interface, deps counterDependencies) (*BpfCount, error) {
	if iface == nil {
		return nil, errors.New("packet counter requires a network interface")
	}
	objs, resources, err := deps.load()
	if err != nil {
		err = fmt.Errorf("failed to load eBPF objects: %w", err)
		// EPERM, EACCES and EINVAL are what an unprivileged process sees,
		// depending on the kernel and the failing step, and what a kernel
		// that does not accept a program or map returns; the caller falls
		// back on them. Any other errno is not such a refusal and stays fatal
		// for the operator to look at. In every case cilium/ebpf closes the
		// objects a failed load created.
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EINVAL) {
			return nil, err
		}
		return nil, errors.Join(cleanup.ErrCleanupUnconfirmed, err)
	}
	bc := &BpfCount{
		objs: objs, cleanup: counterCleanup{resources: resources},
		domainIPs: make(map[domainKey]map[netutil.IPv6]int),
	}

	egr, err := deps.attach(link.TCXOptions{
		Program:   objs.HandleEgress,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXEgress,
	})
	bc.cleanup.add("egress TCX", egr)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("failed to attach egress TCX: %w", err), bc.Close())
	}

	ingr, err := deps.attach(link.TCXOptions{
		Program:   objs.HandleIngress,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXIngress,
	})
	bc.cleanup.add("ingress TCX", ingr)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("failed to attach ingress TCX: %w", err), bc.Close())
	}

	return bc, nil
}

func (bc *BpfCount) Close() error {
	return bc.cleanup.Close()
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

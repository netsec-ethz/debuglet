// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/bitrate"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket/netutil"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/destinations"
	"io"
	"net"
	"net/netip"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/google/uuid"
)

// BpfCount employs ratelimiting using an EBPF layer. It requires root priviliges to work.
type BpfCount struct {
	objs            countObjects
	cleanup         counterCleanup
	attachmentLinks [2]io.Closer // Observed only; cleanup owns their release.
	interfaceIndex  uint32

	mu           sync.Mutex
	destinations destinations.Resolved
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
		missingCapabilities: missingCapabilities,
	})
}

// Construction-fixed test seams model ownership transfer, not kernel behavior.
// load transfers its resources only on success. attach transfers any returned
// nonnil handle, including a handle returned alongside an error.
// missingCapabilities, when set, explains a failed load.
type counterDependencies struct {
	load                func() (countObjects, []counterResource, error)
	attach              func(link.TCXOptions) (io.Closer, error)
	missingCapabilities func() ([]string, error)
}

func newBPFCount(iface *net.Interface, deps counterDependencies) (*BpfCount, error) {
	if iface == nil {
		return nil, errors.New("packet counter requires a network interface")
	}
	objs, resources, err := deps.load()
	if err != nil {
		// A failed load attached nothing, so it is a clean rollback for the
		// caller's fallback decision whatever its cause: attach is reached
		// only after a successful load, and loading creates no TCX link and,
		// without pin options, nothing that outlives this process. What
		// cilium/ebpf may not have released are map and program descriptors,
		// which count no packet without an attachment and close with the
		// process. Only a failed attach can leave a hook in place, and that
		// rollback is observed below. The caller falls back and reports the
		// cause; when the process lacks a required capability (#414) the
		// error names it and reads as a permission failure.
		return nil, explainLoadFailure(fmt.Errorf("failed to load eBPF objects: %w", err), deps.missingCapabilities)
	}
	bc := &BpfCount{objs: objs, cleanup: counterCleanup{resources: resources}, interfaceIndex: uint32(iface.Index)}

	egr, err := deps.attach(link.TCXOptions{
		Program:   objs.HandleEgress,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXEgress,
	})
	bc.cleanup.add("egress TCX", egr)
	bc.attachmentLinks[0] = egr
	if err != nil {
		return nil, errors.Join(fmt.Errorf("failed to attach egress TCX: %w", err), bc.Close())
	}

	ingr, err := deps.attach(link.TCXOptions{
		Program:   objs.HandleIngress,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXIngress,
	})
	bc.cleanup.add("ingress TCX", ingr)
	bc.attachmentLinks[1] = ingr
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
	bc.destinations.Add(addr, id, ipv6)

	return &BpfConn{count: bc, conn: conn, socketID: socketID, domain: addr, id: id, resolvedIPv6: ipv6}, nil
}

func (bc *BpfCount) SetLimit(addr string, id uuid.UUID, limit bitrate.Bitrate) error {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	for ipv6 := range bc.destinations.Targets(addr, id) {
		if err := bc.setIPv6Limit(ipv6, id, limit); err != nil {
			return err
		}
	}
	return nil
}

func (bc *BpfCount) setIPv6Limit(addr netutil.IPv6, id uuid.UUID, limit bitrate.Bitrate) error {
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

func (bc *BpfCount) SetExecLimit(id uuid.UUID, limit bitrate.Bitrate) error {
	key := countExecKey{Uuid: [16]byte(id)}
	bytes := uint64(limit.Bytes())
	return bc.objs.ExecRatesMap.Update(&key, &bytes, ebpf.UpdateAny)
}

func (bc *BpfCount) DeleteExecLimit(id uuid.UUID) error {
	key := countExecKey{Uuid: [16]byte(id)}
	if err := bc.objs.ExecRatesMap.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

func (bc *BpfCount) Detach(addr string, id uuid.UUID, ipv6 netutil.IPv6) error {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	if remaining, ok := bc.destinations.Remove(addr, id, ipv6); !ok || remaining > 0 {
		return nil
	}
	return bc.objs.RatesMap.Delete(&countDebugletKey{
		Uuid: [16]byte(id),
		Ipv6: ipv6.IP.As16(),
	})
}

func (f *BpfCount) Type() string { return "ebpf" }

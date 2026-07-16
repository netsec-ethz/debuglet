package hostconn

import (
	"context"
	"debuglet/internal/executor/debuglet/socket"
	"debuglet/internal/executor/debuglet/socket/netutil"
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

type HostDialer struct {
	dialer       *net.Dialer
	allowedAddrs map[netip.Addr]struct{}
}

func NewDialer(allowedIPs []string) (*HostDialer, error) {
	allowed := make(map[netip.Addr]struct{})
	for _, ip := range allowedIPs {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return nil, fmt.Errorf("invalid ip %q: %w", ip, err)
		}
		// Ensure the address is in 16-byte format for consistency
		addr = netip.AddrFrom16(addr.As16())
		allowed[addr] = struct{}{}
	}

	hd := &HostDialer{
		allowedAddrs: allowed,
	}
	hd.dialer = &net.Dialer{Control: hd.Control}
	return hd, nil
}

func FromDomains(ctx context.Context, allowedAddr []string) (*HostDialer, error) {
	allowed, err := netutil.DomainsToIPv6(ctx, allowedAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve allowed addresses: %w", err)
	}
	return NewDialer(allowed)
}

func (hd *HostDialer) Control(network, address string, c syscall.RawConn) error {
	// TODO: check if its possible for address to be a domain. This function would fail in that case.
	host, err := socket.HostFromAddr(address)
	if err != nil {
		return err
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("failed to parse resolved IP: %w", err)
	}
	// Ensure the address is in 16-byte format for consistency
	addr = netip.AddrFrom16(addr.As16())

	if _, allowed := hd.allowedAddrs[addr]; !allowed {
		return fmt.Errorf("connection to IP %s is not whitelisted", addr)
	}
	return nil
}

func (hd *HostDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return hd.dialer.DialContext(ctx, network, address)
}

func (hd *HostDialer) AllowedAddrs() []string {
	allowed := make([]string, 0, len(hd.allowedAddrs))
	for addr := range hd.allowedAddrs {
		allowed = append(allowed, addr.String())
	}
	return allowed
}

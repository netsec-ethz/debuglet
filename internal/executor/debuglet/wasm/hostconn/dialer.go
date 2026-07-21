package hostconn

import (
	"context"
	"debuglet/internal/executor/debuglet/socket/netutil"
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

type HostDialer struct {
	dialer       *net.Dialer
	allowedIPv6s map[netutil.IPv6]struct{}
}

func NewDialer(allowedIPs []string) (*HostDialer, error) {
	allowed := make(map[netutil.IPv6]struct{})
	for _, ip := range allowedIPs {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return nil, fmt.Errorf("invalid ip %q: %w", ip, err)
		}
		allowed[netutil.ToIPv6(addr)] = struct{}{}
	}

	hd := &HostDialer{allowedIPv6s: allowed}
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
	host, err := netutil.HostFromAddr(address)
	if err != nil {
		return err
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("failed to parse resolved IP: %w", err)
	}
	ipv6 := netutil.ToIPv6(addr)
	if _, allowed := hd.allowedIPv6s[ipv6]; !allowed {
		return fmt.Errorf("connection to IP %s is not whitelisted", addr)
	}
	return nil
}

func (hd *HostDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return hd.dialer.DialContext(ctx, network, address)
}

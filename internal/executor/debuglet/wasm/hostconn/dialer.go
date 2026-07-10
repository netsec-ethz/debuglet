package hostconn

import (
	"context"
	"errors"
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
		allowed[addr] = struct{}{}
	}

	hd := &HostDialer{
		allowedAddrs: allowed,
	}
	hd.dialer = &net.Dialer{Control: hd.control}
	return hd, nil
}

func FromDomains(ctx context.Context, allowedAddr []string) (*HostDialer, error) {
	allowed, err := DomainsToIP6(ctx, allowedAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve allowed addresses: %w", err)
	}
	return NewDialer(allowed)
}

func (hd *HostDialer) control(network, address string, c syscall.RawConn) error {
	host, err := hostFromAddr(address)
	if err != nil {
		return err
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("failed to parse resolved IP: %w", err)
	}

	if _, allowed := hd.allowedAddrs[addr]; !allowed {
		return fmt.Errorf("connection to IP %s is not whitelisted", addr)
	}
	return nil
}

func (hd *HostDialer) Control(network, address string, c syscall.RawConn) error {
	return hd.control(network, address, c)
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

func hostFromAddr(addr string) (string, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		var addrErr *net.AddrError
		if errors.As(err, &addrErr) && addrErr.Err == "missing port in address" {
			host = addr
		} else {
			return "", fmt.Errorf("invalid address format: %w", err)
		}
	}
	return host, nil
}

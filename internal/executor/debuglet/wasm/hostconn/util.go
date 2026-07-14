package hostconn

import (
	"context"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
)

func DomainToIPv6(ctx context.Context, rawAddr string) ([]string, error) {
	addr, err := netip.ParseAddr(rawAddr)
	if err != nil {
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, rawAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid addr %s: %w", rawAddr, err)
		}
		var sip []string
		for _, ip := range ips {
			if ip4 := ip.IP.To4(); ip4 != nil {
				sip = append(sip, fmt.Sprintf("::ffff:%d.%d.%d.%d", ip4[0], ip4[1], ip4[2], ip4[3]))
			} else {
				sip = append(sip, ip.IP.String())
			}
		}
		return sip, nil
	} else {
		if addr.Is4() {
			ip4 := addr.As4()
			return []string{fmt.Sprintf("::ffff:%d.%d.%d.%d", ip4[0], ip4[1], ip4[2], ip4[3])}, nil
		} else {
			return []string{addr.String()}, nil
		}
	}
}

func DomainsToIPv6(ctx context.Context, addresses []string) ([]string, error) {
	allowed := make(map[string]struct{})
	for _, rawAddr := range addresses {
		if ips, err := DomainToIPv6(ctx, rawAddr); err != nil {
			return nil, err
		} else {
			for _, ip := range ips {
				allowed[ip] = struct{}{}
			}
		}
	}
	return slices.Collect(maps.Keys(allowed)), nil
}

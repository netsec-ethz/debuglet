package hostconn

import (
	"context"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
)

func DomainsToIP6(ctx context.Context, addresses []string) ([]string, error) {
	allowed := make(map[string]struct{})
	for _, rawAddr := range addresses {
		addr, err := netip.ParseAddr(rawAddr)
		if err != nil {
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, rawAddr)
			if err != nil {
				return nil, fmt.Errorf("invalid addr %s: %w", rawAddr, err)
			}
			for _, ip := range ips {
				if ip4 := ip.IP.To4(); ip4 != nil {
					allowed[fmt.Sprintf("::ffff:%d.%d.%d.%d", ip4[0], ip4[1], ip4[2], ip4[3])] = struct{}{}
				} else {
					allowed[ip.IP.String()] = struct{}{}
				}
			}
		} else {
			if addr.Is4() {
				ip4 := addr.As4()
				allowed[fmt.Sprintf("::ffff:%d.%d.%d.%d", ip4[0], ip4[1], ip4[2], ip4[3])] = struct{}{}
			} else {
				allowed[addr.String()] = struct{}{}
			}
		}
	}

	return slices.Collect(maps.Keys(allowed)), nil
}

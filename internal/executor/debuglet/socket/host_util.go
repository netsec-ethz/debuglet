package socket

import (
	"errors"
	"fmt"
	"net"
)

func HostFromAddr(addr string) (string, error) {
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

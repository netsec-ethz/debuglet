package ebpf

import (
	"errors"
	"net"
)

// getDefaultInterface determines the default interface used when connecting to the internet
func GetDefaultInterface() (*net.Interface, error) {
	// Opening a connection (without transferring anything yet) assigns a local address
	// which can then be used to determine the (default) interface used for internet
	// connections
	conn, err := net.Dial("udp", "1.1.1.1:80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, errors.New("failed to convert local addr into UDPAddr")
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPAddr:
				ip = v.IP
			case *net.IPNet:
				ip = v.IP
			}
			if ip != nil && ip.Equal(local.IP) {
				return &iface, nil
			}
		}
	}

	return nil, errors.New("default interface not found")
}

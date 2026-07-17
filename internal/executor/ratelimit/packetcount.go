package ratelimit

import (
	"debuglet/internal/executor/ratelimit/app"
	"debuglet/internal/executor/ratelimit/ebpf"
	"debuglet/internal/executor/ratelimit/fallback"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type PacketCount interface {
	// Attach associates a connection with the given ID for packet counting, returning an updated ratelimited connection.
	// It is important to call [net.Conn.Close] on the received connection once done to ensure correct cleanup for ratelimiting.
	Attach(conn net.Conn, id uuid.UUID) (net.Conn, error)
	// SetLimit sets a bitrate limit for a specific IP address and debuglet ID.
	SetLimit(addr netip.Addr, id uuid.UUID, limit app.Bitrate) error
	// SetExecLimit sets a bitrate limit for all traffic associated with the given debuglet ID.
	SetExecLimit(id uuid.UUID, limit app.Bitrate) error
	// DeleteLimit removes the bitrate limit for a specific IP address and debuglet ID.
	DeleteLimit(addr netip.Addr, id uuid.UUID) error
	// DeleteLimit removes the bitrate limit for all traffic associated with the given debuglet ID.
	DeleteExecLimit(id uuid.UUID) error
	Close() error
	Type() string
}

func New(iface *net.Interface, logger *zap.Logger) (PacketCount, error) {
	var err error
	if iface != nil {
		var bpf *ebpf.BpfCount
		bpf, err = ebpf.NewBPFCount(iface)
		if err == nil {
			return bpf, nil
		} else {
			logger.Warn("Failed to initialize eBPF packet count (possible permission issues), falling back to fallback packet count", zap.Error(err))
		}
	}
	fc, err2 := fallback.NewFallbackCount()
	if err2 != nil {
		return nil, fmt.Errorf("failed to initialize packet count: %w: %w", err, err2)
	}
	return fc, nil
}

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

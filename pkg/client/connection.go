package client

import (
	"context"
	"net"
	"net/http"
	"strconv"
)

// ConnectionInfo describes the control listeners announced by a local dispatcher.
// It does not grant access or infer control addresses from an HTTP URL.
type ConnectionInfo struct {
	SchemaVersion int    `json:"schema_version"`
	Mode          string `json:"mode"`
	GRPCAddress   string `json:"grpc_address"`
	YamuxAddress  string `json:"yamux_address"`
}

// Connection reads optional local-executor connection metadata. Older servers
// may return an HTTPError with status 404; their ordinary HTTP API remains usable.
func (c *Client) Connection(ctx context.Context) (ConnectionInfo, error) {
	const route = "connection"
	data, err := c.do(ctx, http.MethodGet, route, nil, nil, http.StatusOK)
	if err != nil {
		return ConnectionInfo{}, err
	}
	var info ConnectionInfo
	if err := c.decode(http.MethodGet, route, data, &info); err != nil {
		return ConnectionInfo{}, err
	}
	if info.SchemaVersion != 1 || info.Mode != "local-test" || !localControlAddress(info.GRPCAddress) || !localControlAddress(info.YamuxAddress) {
		return ConnectionInfo{}, c.protocolErr(http.MethodGet, route, "invalid local connection metadata")
	}
	return info, nil
}

func localControlAddress(address string) bool {
	host, port, err := net.SplitHostPort(address)
	n, portErr := strconv.Atoi(port)
	return err == nil && portErr == nil && n > 0 && n <= 65535 && isLiteralLoopback(host)
}

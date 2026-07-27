//go:build !linux

package hostconn

import "context"

func (h *HostConn) Drain(ctx context.Context) {}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build !linux

package hostconn

import "context"

func (h *HostConn) Drain(ctx context.Context) {}

func (h *HostConn) DrainTCP(ctx context.Context) error { return nil }

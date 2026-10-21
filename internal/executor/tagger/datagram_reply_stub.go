// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build !linux

package tagger

import "net"

func (*Tagger) WrapUDPReply(*net.UDPConn, *net.UDPAddr) (net.Conn, error) {
	return nil, ErrDatagramUntagged
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build !linux

package tagger

import "net"

// WrapDatagram tags datagrams only on Linux; elsewhere every connection stays
// untagged.
func (t *Tagger) WrapDatagram(net.Conn) (net.Conn, error) {
	return nil, ErrDatagramUntagged
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build !linux

package socket

// socketProtocol cannot read SO_PROTOCOL off Linux, where Multipath TCP
// listeners do not exist either.
func socketProtocol(int) (proto int, known bool, err error) {
	return 0, false, nil
}

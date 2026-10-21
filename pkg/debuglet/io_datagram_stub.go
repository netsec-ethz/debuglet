// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build !wasip1

package debuglet

import "time"

func receiveUDPTimeout([]byte, time.Duration) (UDPDatagram, error) { panic(offTarget) }
func replyUDPTimeout(string, []byte, time.Duration) (int, error)   { panic(offTarget) }

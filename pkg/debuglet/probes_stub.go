// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build !wasip1

package debuglet

import "time"

func inspectTLS(string, time.Duration) (TLSInfo, error)        { panic(offTarget) }
func probeHop(string, uint32, time.Duration) (HopReply, error) { panic(offTarget) }

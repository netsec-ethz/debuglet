// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build !wasip1

package debuglet

func experimentReady(metadata, result []byte, deadlineNS int64) int32 { panic(offTarget) }

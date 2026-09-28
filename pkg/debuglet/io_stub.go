// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build !wasip1

package debuglet

import "time"

func dialSocket(uint32, string, time.Duration) (*Socket, error) { panic(offTarget) }
func (*Socket) Read([]byte) (int, error)                        { panic(offTarget) }
func (*Socket) Write([]byte) (int, error)                       { panic(offTarget) }
func (*Socket) Close() error                                    { panic(offTarget) }
func (*Socket) SetReadDeadline(time.Time) error                 { panic(offTarget) }
func (*Socket) SetWriteDeadline(time.Time) error                { panic(offTarget) }

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// Package guestio defines the optional debuglet_io_v1 socket import contract.
package guestio

const Module = "debuglet_io_v1"

// Results pack a byte count or socket handle in the low 32 bits and a status
// in the high 32 bits. A nonzero status does not discard a positive count.
const (
	OK = iota
	EOF
	Timeout
	Reset
	Closed
	Refused
	Denied
	Failure
	NoProgress
	ShortWrite
	Canceled
	Unsupported
)

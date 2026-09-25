// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package app

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// Bitrate in bits/s.
//
// Can also be used to generally indicate size.
type Bitrate int64

const (
	Bit      Bitrate = 1
	Kilobit          = 1000 * Bit
	Megabit          = 1000 * Kilobit
	Gigabit          = 1000 * Megabit
	Terabit          = 1000 * Gigabit
	Petabit          = 1000 * Terabit
	Byte             = 8 * Bit
	Kilobyte         = 1000 * Byte
	Megabyte         = 1000 * Kilobyte
	Gigabyte         = 1000 * Megabyte
	Terabyte         = 1000 * Gigabyte
	Petabyte         = 1000 * Terabyte
)

var sizeRegex = regexp.MustCompile(`(?i)^(\d+(?:\.\d+)?)\s*([a-z]*)$`)

func (b Bitrate) String() string {
	bytes := b.SignedBytes()
	switch {
	case bytes >= 1<<30:
		return fmt.Sprintf("%.1fGiB", float64(bytes)/float64(1<<30))
	case bytes >= 1<<20:
		return fmt.Sprintf("%.1fMiB", float64(bytes)/float64(1<<20))
	case bytes >= 1<<10:
		return fmt.Sprintf("%.1fKiB", float64(bytes)/float64(1<<10))
	default:
		return fmt.Sprintf("%dB", bytes)
	}
}

// bitsPerByte is the conversion factor between the two units this type is
// read in: a bitrate is bits, and every buffer and token accounting around it
// is bytes.
const bitsPerByte = 8

// MaxByteCount is the largest byte count that has an exact bit count.
const MaxByteCount = math.MaxInt64 / bitsPerByte

// Bytes is the buffer size that holds b bits, rounded up to a whole byte. It
// is a size, so it is defined for a non-negative bitrate: a negative one is a
// debt, has no buffer size and reports zero. Use [Bitrate.SignedBytes] to
// convert a signed token balance.
func (b Bitrate) Bytes() int {
	if b <= 0 {
		return 0
	}
	whole := int64(b) / bitsPerByte
	if int64(b)%bitsPerByte != 0 {
		whole++
	}
	return int(whole)
}

// SignedBytes converts a signed bit count into whole bytes, rounding towards
// negative infinity. Applied to a token balance it reports only bytes that are
// fully covered and never erases part of a debt: -8 bits is one byte owed and
// -1 bit is still one byte owed, where rounding towards zero reports none of
// either and grants the next reservation early. It is exact for every int64.
func (b Bitrate) SignedBytes() int {
	whole := int64(b) / bitsPerByte
	if int64(b)%bitsPerByte != 0 && b < 0 {
		whole--
	}
	return int(whole)
}

// FromBytes converts a byte count into bits. A count beyond MaxByteCount in
// either direction has no exact bit count and saturates, rather than wrapping
// into a bitrate of the opposite sign.
func FromBytes(b int) Bitrate {
	bytes := int64(b)
	switch {
	case bytes > MaxByteCount:
		return Bitrate(math.MaxInt64)
	case bytes < -MaxByteCount:
		return Bitrate(math.MinInt64)
	}
	return Bitrate(bytes * bitsPerByte)
}

func Parse(s string) (Bitrate, error) {
	s = strings.TrimSpace(s)
	match := sizeRegex.FindStringSubmatch(s)
	if match == nil {
		return 0, fmt.Errorf("invalid size format: %s", s)
	}

	value, err := strconv.ParseFloat(match[1], 64)
	if err != nil {
		return 0, err
	}

	unit := strings.ToLower(match[2])
	var multiplier Bitrate

	switch unit {
	case "bit", "b":
		multiplier = Bit
	case "kbit", "kbps":
		multiplier = Kilobit
	case "mbit", "mbps":
		multiplier = Megabit
	case "gbit", "gbps":
		multiplier = Gigabit
	case "tbit", "tbps":
		multiplier = Terabit
	case "kb", "k":
		multiplier = Kilobyte
	case "mb", "m":
		multiplier = Megabyte
	case "gb", "g":
		multiplier = Gigabyte
	case "tb", "t":
		multiplier = Terabyte
	case "":
		multiplier = Bit
	default:
		return 0, fmt.Errorf("unknown unit: %s", unit)
	}

	return Bitrate(value * float64(multiplier)), nil
}

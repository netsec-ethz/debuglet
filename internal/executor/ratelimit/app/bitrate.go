package app

import (
	"fmt"
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
	bytes := b.Bytes()
	switch {
	case bytes >= 1<<30:
		return fmt.Sprintf("%.1fGiB", float64(bytes)/float64(1<<30))
	case bytes >= 1<<20:
		return fmt.Sprintf("%.1fMiB", float64(bytes)/float64(1<<20))
	case bytes >= 1<<10:
		return fmt.Sprintf("%.1fKiB", float64(bytes)/float64(1<<10))
	default:
		return fmt.Sprintf("%dB", uint64(bytes))
	}
}

func (b Bitrate) Bytes() int {
	// round up
	return int(b+7) / 8
}

func FromBytes(b int) Bitrate {
	return Bitrate(b * 8)
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

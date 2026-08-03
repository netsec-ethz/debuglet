package resource

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
	switch {
	case b >= Terabit:
		return fmt.Sprintf("%.2ftbit", float64(b)/float64(Terabit))
	case b >= Gigabit:
		return fmt.Sprintf("%.2fgbit", float64(b)/float64(Gigabit))
	case b >= Megabit:
		return fmt.Sprintf("%.2fmbit", float64(b)/float64(Megabit))
	case b >= Kilobit:
		return fmt.Sprintf("%.2fkbit", float64(b)/float64(Kilobit))
	default:
		return fmt.Sprintf("%dbit", b)
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

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// Package bytevalue decodes bounded byte values shared by validation and guests.
package bytevalue

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// Decode never trims text or interprets escape sequences. Hex is contiguous
// byte pairs; base64 uses the standard padded alphabet with zero padding bits.
// Encoded length is checked before allocating a decoding buffer.
func Decode(value, encoding string, maximum int) ([]byte, error) {
	var result []byte
	var err error
	switch encoding {
	case "text":
		if len(value) > maximum {
			return nil, fmt.Errorf("decoded value exceeds %d bytes", maximum)
		}
		return []byte(value), nil
	case "hex":
		if len(value) > maximum*2 {
			return nil, fmt.Errorf("decoded value exceeds %d bytes", maximum)
		}
		result, err = hex.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("value must be hexadecimal byte pairs without spaces: %w", err)
		}
	case "base64":
		if len(value) > base64.StdEncoding.EncodedLen(maximum) {
			return nil, fmt.Errorf("decoded value exceeds %d bytes", maximum)
		}
		result, err = base64.StdEncoding.Strict().DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("value must be valid padded base64: %w", err)
		}
	default:
		return nil, fmt.Errorf("encoding must be text, hex or base64")
	}
	if len(result) > maximum {
		return nil, fmt.Errorf("decoded value exceeds %d bytes", maximum)
	}
	return result, nil
}

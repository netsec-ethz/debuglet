// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
	"github.com/netsec-ethz/debuglet/pkg/workflow/internal/bytevalue"
)

func inputBytes(in map[string]any, field, encodingField string, maximum int) ([]byte, error) {
	value, ok := in[field].(string)
	if _, exists := in[field]; exists && !ok {
		return nil, fmt.Errorf("%s must be a string", field)
	}
	encoding, err := networkString(in, encodingField, "text")
	if err != nil {
		return nil, err
	}
	result, err := bytevalue.Decode(value, encoding, maximum)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	return result, nil
}

func bytePayload(in map[string]any) (map[string]any, error) {
	pattern, err := inputBytes(in, "value", "encoding", debuglet.MaxIOBytes)
	if err != nil {
		return nil, err
	}
	size, err := networkInteger(in, "size_bytes", -1, -1, debuglet.MaxIOBytes)
	if err != nil {
		return nil, err
	}
	data := pattern
	if size >= 0 {
		if size > 0 && len(pattern) == 0 {
			return nil, fmt.Errorf("value must contain a byte when size_bytes is positive")
		}
		data = make([]byte, size)
		for filled := 0; filled < size; {
			filled += copy(data[filled:], pattern)
		}
	}
	return map[string]any{"base64": base64.StdEncoding.EncodeToString(data), "hex": hex.EncodeToString(data), "bytes": float64(len(data))}, nil
}

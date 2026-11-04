// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// LogEvent prepares an explicit user event for Runtime.Record. Its timestamp is
// the guest's clock, not a claim of clock synchronization between participants.
func LogEvent(in map[string]any) (map[string]any, error) {
	if err := Check(in, map[string]string{"message": "string", "details": "any"}); err != nil {
		return nil, err
	}
	message := in["message"].(string)
	if !utf8.ValidString(message) || strings.TrimSpace(message) == "" || len(message) > 1024 {
		return nil, fmt.Errorf("message must contain 1–1024 UTF-8 bytes and not be blank")
	}
	details, err := json.Marshal(in["details"])
	if err != nil || len(details) > 8192 {
		return nil, fmt.Errorf("event details must fit in 8 KiB of JSON")
	}
	return map[string]any{"message": message, "details": in["details"], "timestamp_ms": float64(time.Now().UnixMilli())}, nil
}

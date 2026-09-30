// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"strconv"
	"strings"
	"time"
)

// PublicTerminalError is the public projection of a retained terminal string,
// including historical reports. The database retains the original private
// diagnostic until payload deletion. Empty remains success; every nonempty
// report remains a failure. Arbitrary executor or runtime text is never an
// authority to publish a stack, credential, address or module fragment.
func PublicTerminalError(message string) string {
	if message == "" {
		return ""
	}
	switch message {
	case outcomeUnknown:
		return message
	case "cancelled via API", "debuglet cancelled":
		return "debuglet cancelled"
	case "failed to batch upload all debuglets":
		return message
	case "guest socket quota exceeded", "compilation resource budget exceeded", "execution resource budget exceeded",
		"compiler worker failed", "compiler capacity unavailable", "guest worker failed":
		return message
	case "destination refused: outside the job's destination policy",
		"destination refused: denied by the operator network policy",
		"destination refused: transport unavailable",
		"destination refused: IPv6 not tagged on this executor":
		return message
	}
	if strings.Contains(message, unobservedCancellation) {
		return "cancellation requested; the executor outcome was not observed"
	}
	const exitPrefix = "debuglet exited with code "
	if value, ok := strings.CutPrefix(message, exitPrefix); ok {
		if code, err := strconv.ParseInt(value, 10, 64); err == nil && code >= -1 && code <= 1<<32-1 {
			return exitPrefix + strconv.FormatInt(code, 10)
		}
	}
	if value, ok := strings.CutPrefix(message, "timeout of "); ok {
		if value, ok = strings.CutSuffix(value, " exceeded"); ok {
			if duration, err := time.ParseDuration(value); err == nil && duration > 0 {
				return "timeout of " + duration.String() + " exceeded"
			}
		}
	}
	if strings.HasPrefix(message, "module does not compile") {
		return "module does not compile"
	}
	return "debuglet failed; operator diagnostics have the details"
}

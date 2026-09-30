// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"encoding/json"
	"strings"
	"unicode/utf8"

	"github.com/netsec-ethz/debuglet/pkg/wire"
)

// Optional field details never change the status, admission receipt or outcome
// of a failed request. Malformed details are ignored as a group.
func fieldErrorsFromError(value any, secrets []string) []wire.FieldError {
	items, ok := value.([]any)
	if !ok || len(items) == 0 || len(items) > 16 {
		return nil
	}
	fields := make([]wire.FieldError, 0, len(items))
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			return nil
		}
		field, _ := entry["field"].(string)
		code, _ := entry["code"].(string)
		message, ok := entry["message"].(string)
		if !ok || len(field) > 128 || redactSecrets(field, secrets) != field || safeCode(redactSecrets(code, secrets)) == "" {
			return nil
		}
		for _, part := range strings.Split(field, ".") {
			if safeCode(part) == "" {
				return nil
			}
		}
		message = strings.ToValidUTF8(redactSecrets(message, secrets), "�")
		if len(message) > 512 {
			message = message[:512]
			for !utf8.ValidString(message) {
				message = message[:len(message)-1]
			}
		}
		failure := wire.FieldError{Field: field, Code: code, Message: message}
		if order, present := entry["order_id"]; present {
			number, ok := order.(json.Number)
			if !ok || redactSecrets(string(number), secrets) != string(number) {
				return nil
			}
			id, err := number.Int64()
			if err != nil {
				return nil
			}
			failure.OrderID = &id
		}
		fields = append(fields, failure)
	}
	return fields
}

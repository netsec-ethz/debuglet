// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import "context"

type requiredVersionKey struct{}

// Feature-specific requests require their first compatible server version.
func requiredAPIVersion(ctx context.Context) string {
	if version, ok := ctx.Value(requiredVersionKey{}).(string); ok {
		return version
	}
	return APIVersion
}

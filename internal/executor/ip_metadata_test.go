// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import "testing"

func TestLocationOptOutReportedInHello(t *testing.T) {
	cfg := fixtureConfig()
	cfg.Metadata.LocationOptOut = true
	e := newFixtureExecutor(t, cfg, nil, newFixtureMemoryStorage(t))
	response, err := e.OnHello(t.Context(), nil)
	if err != nil || !response.GetVantagePoint().GetLocationOptOut() {
		t.Fatalf("location preference: %v %v", response, err)
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package storagecheck

import (
	"errors"
	"testing"
)

// Verification adds its durable budget after the public probe history schema;
// an operator upgrading an existing dispatcher must keep that history intact.
func TestVerificationUpgradePreservesProbeHistory(t *testing.T) {
	path := fixture(t, Dispatcher, 24)
	modify(t, path,
		`INSERT INTO probe_status VALUES ('probe', 100, 200, 0, 180, 80, 0, 'home', '0.3.0-rc.1')`,
		`INSERT INTO probe_addresses VALUES ('probe', 4, '192.0.2.1', 'control', 100, 200)`,
		`INSERT INTO probe_addresses VALUES ('probe', 6, '2001:db8::1', 'reflection', 120, 190)`)
	if err := Check(t.Context(), Dispatcher, path); !errors.Is(err, ErrOutdated) {
		t.Fatalf("schema 24 must require an explicit upgrade: %v", err)
	}
	if _, err := Upgrade(t.Context(), Dispatcher, path); err != nil {
		t.Fatal(err)
	}
	if err := Check(t.Context(), Dispatcher, path); err != nil {
		t.Fatalf("upgraded dispatcher: %v", err)
	}
	for _, query := range []string{
		`SELECT COUNT(*) FROM probe_status WHERE executor_id='probe' AND first_connected=100 AND last_connected=200 AND connected=0 AND status_since=180 AND total_uptime=80 AND is_public=0 AND host_tags='home' AND version='0.3.0-rc.1'`,
		`SELECT COUNT(*) FROM probe_addresses WHERE executor_id='probe' AND family=4 AND address='192.0.2.1' AND via='control' AND first_observed=100 AND last_observed=200`,
		`SELECT COUNT(*) FROM probe_addresses WHERE executor_id='probe' AND family=6 AND address='2001:db8::1' AND via='reflection' AND first_observed=120 AND last_observed=190`,
	} {
		if got := count(t, path, query); got != 1 {
			t.Fatalf("probe history changed during upgrade: %q = %d", query, got)
		}
	}
	for _, table := range []string{"attribution_verify_budget", "attribution_receipt_keys"} {
		if got := count(t, path, "SELECT COUNT(*) FROM "+table); got != 0 {
			t.Fatalf("new verification table %s has %d rows", table, got)
		}
	}
}

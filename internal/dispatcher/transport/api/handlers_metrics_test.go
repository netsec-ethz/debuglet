// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/observability"
	"go.uber.org/zap"
)

func TestMetricsRequireOperator(t *testing.T) {
	f := ccNewFixtureWith(t, MetricsStateDirectory(t.TempDir()))
	account, token, _ := authAccount(t, f, "metrics operator")
	for _, tc := range []struct {
		token string
		want  int
	}{{"", http.StatusUnauthorized}, {token, http.StatusForbidden}} {
		status, _, _, _ := authRequest(t, f, http.MethodGet, "/metrics", nil, map[string]string{"Authorization": "Bearer " + tc.token})
		if status != tc.want {
			t.Fatalf("metrics status=%d, want %d", status, tc.want)
		}
	}
	authGrantOperator(t, f, account.ID)
	status, _, body, response := authRequest(t, f, http.MethodGet, "/metrics", nil, map[string]string{"Authorization": "Bearer " + token})
	if status != http.StatusOK || !strings.HasPrefix(response.Header.Get("Content-Type"), "text/plain; version=0.0.4") || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("operator metrics: status=%d headers=%v body=%s", status, response.Header, body)
	}
	if !strings.Contains(string(body), `debuglet_observation_available{observation="process_rss_bytes",`) || !strings.Contains(string(body), `debuglet_observation_available{observation="output_complete",reason="unsupported"} 0`) {
		t.Fatalf("missing host or unavailable observation: %s", body)
	}
	if strings.Contains(string(body), account.ID) || strings.Contains(string(body), token) {
		t.Fatal("credentials or identifiers in metrics")
	}
	authRevokeOperator(t, f, account.ID)
	status, _, _, _ = authRequest(t, f, http.MethodGet, "/metrics", nil, map[string]string{"Authorization": "Bearer " + token})
	if status != http.StatusForbidden {
		t.Fatalf("cached report bypassed revoked operator role: %d", status)
	}
}

func TestMetricsUnavailableAndFixedLabels(t *testing.T) {
	empty := dispatcher.ControlMetrics{ObservedAt: time.Unix(100, 0), Registered: 1}
	full := empty
	full.Ready, full.Registered = 1000, 1000
	full.Runs.Admitted, full.Runs.ReportedSuccess = 10000, 10000
	host := observability.HostSnapshot{}
	series := func(body string) string {
		var names []string
		for _, line := range strings.Split(body, "\n") {
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			name, _, _ := strings.Cut(line, " ")
			names = append(names, name)
		}
		return strings.Join(names, "\n")
	}
	if series(formatMetrics(empty, host)) != series(formatMetrics(full, host)) {
		t.Fatal("run or executor count changes label cardinality")
	}
	full.Runs.Unavailable = "limit"
	out := formatMetrics(full, host)
	for _, forbidden := range []string{"debuglet_retained_runs_admitted ", "debuglet_process_rss_bytes ", "debuglet_output_complete "} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("unavailable metric emitted as a value: %s", forbidden)
		}
	}
	if !strings.Contains(out, `debuglet_observation_available{observation="retained_runs",reason="limit"} 0`) {
		t.Fatal("missing history limit signal")
	}
}

func TestMetricsHealthOmitsIncompleteValuesAndPrivateDetails(t *testing.T) {
	remaining := 50.0
	c := dispatcher.ControlMetrics{ObservedAt: time.Now(), Registered: 2, Health: dispatcher.ExecutorHealthMetrics{
		EBPF: 1, EnforcementUnknown: 1, AttributionAvailable: 1, AttributionUnknown: 1,
		ScheduleUnknown: 1, ScheduleRemainingSeconds: &remaining,
	}}
	out := formatMetrics(c, observability.HostSnapshot{})
	for _, want := range []string{
		`debuglet_executors_enforcement_mode{state="ebpf"} 1`,
		`debuglet_executors_enforcement_mode{state="unknown"} 1`,
		`debuglet_executors_attribution_state{state="unknown"} 1`,
		`debuglet_observation_available{observation="executor_schedule_remaining_seconds",reason="incomplete"} 0`,
		`debuglet_observation_available{observation="executor_disclosure_held_seconds",reason="incomplete"} 0`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %s", want)
		}
	}
	for _, absent := range []string{"\ndebuglet_executor_schedule_remaining_seconds ", "\ndebuglet_executor_disclosure_held_seconds ", "refresh_error="} {
		if strings.Contains(out, absent) {
			t.Fatalf("unexpected %s", absent)
		}
	}
	c.RegistryUnavailable = "limit"
	out = formatMetrics(c, observability.HostSnapshot{})
	if strings.Contains(out, "\ndebuglet_executors_enforcement_mode{") || !strings.Contains(out, `debuglet_observation_available{observation="executor_health",reason="limit"} 0`) {
		t.Fatalf("limited registry exported a partial health total: %s", out)
	}
}

func TestMetricsConcurrentCollectionRefusesWithoutWaiting(t *testing.T) {
	h := NewHandler(nil, nil, zap.NewNop(), LocalDevelopment(true))
	e := echo.New()
	h.RegisterRoutes(e)
	h.metrics.mu.Lock()
	defer h.metrics.mu.Unlock()
	recorder := httptest.NewRecorder()
	e.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusServiceUnavailable || recorder.Header().Get("Retry-After") != "1" {
		t.Fatalf("busy scrape: %d %s", recorder.Code, recorder.Body)
	}
}

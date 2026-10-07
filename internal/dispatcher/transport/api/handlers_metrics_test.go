// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/observability"
	"go.uber.org/zap"
)

func TestPacketDropMetricsKeepDirectionAndOmitIncompleteTotals(t *testing.T) {
	count, size := 3.0, 237.0
	c := dispatcher.ControlMetrics{Registered: 1}
	for i := range 2 {
		c.Health.DropVerdicts[i] = dispatcher.ExecutorResourceMetric{Value: &count}
		c.Health.DropSKBBytes[i] = dispatcher.ExecutorResourceMetric{Value: &size}
	}
	out := formatMetrics(c, observability.HostSnapshot{})
	for _, direction := range []string{"ingress", "egress"} {
		for _, want := range []string{`debuglet_executor_counter_drop_verdicts_max{direction="` + direction + `"} 3`, `debuglet_executor_counter_drop_skb_bytes_max{direction="` + direction + `"} 237`} {
			if !strings.Contains(out, want) {
				t.Fatalf("missing %s", want)
			}
		}
	}
	c.Health.DropVerdicts[1].Unknown = 1
	out = formatMetrics(c, observability.HostSnapshot{})
	if strings.Contains(out, `debuglet_executor_counter_drop_verdicts_max{direction="egress"}`) || !strings.Contains(out, `debuglet_observation_available{observation="executor_counter_drop_verdicts_max_egress",reason="incomplete"} 0`) {
		t.Fatal("incomplete drop total became numeric")
	}
	if !strings.Contains(out, `debuglet_observation_available{observation="enforcement_verified",reason="unsupported"} 0`) {
		t.Fatal("local drops implied verified enforcement")
	}
}

func TestSettlementMetricsUnavailableNeverBecomesZero(t *testing.T) {
	c := dispatcher.ControlMetrics{Settlement: payments.SettlementMetrics{PendingCredit: 1, PendingRefund: 2, Reserved: 3, Sent: 4, Unknown: 5, Failed: 6}}
	out := formatMetrics(c, observability.HostSnapshot{})
	for _, want := range []string{
		`debuglet_settlement_pending_orders{state="credit"} 1`,
		`debuglet_settlement_pending_orders{state="refund"} 2`,
		`debuglet_settlement_transfers{state="unknown"} 5`,
		`debuglet_settlement_transfers{state="failed"} 6`,
		`debuglet_observation_available{observation="settlement_backlog",reason=""} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %s", want)
		}
	}
	c.Settlement.Unavailable = "limit"
	out = formatMetrics(c, observability.HostSnapshot{})
	if strings.Contains(out, "\ndebuglet_settlement_") || !strings.Contains(out, `debuglet_observation_available{observation="settlement_backlog",reason="limit"} 0`) {
		t.Fatal("incomplete settlement observation exported numeric counts")
	}
}

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

// The attribution state series name the clock reasons with fixed labels and
// sum to the registered executors.
func TestMetricsAttributionStatesSumToRegistered(t *testing.T) {
	c := dispatcher.ControlMetrics{ObservedAt: time.Now(), Registered: 4, Health: dispatcher.ExecutorHealthMetrics{
		AttributionAvailable: 1, ClockUnready: 1, ClockDrift: 1, AttributionUnknown: 1}}
	out := formatMetrics(c, observability.HostSnapshot{})
	sum := 0
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "debuglet_executors_attribution_state{") {
			continue
		}
		_, value, _ := strings.Cut(line, " ")
		n, err := strconv.Atoi(value)
		if err != nil {
			t.Fatalf("value of %q: %v", line, err)
		}
		sum += n
	}
	if sum != c.Registered {
		t.Fatalf("attribution states sum to %d, want %d:\n%s", sum, c.Registered, out)
	}
	for _, want := range []string{`debuglet_executors_attribution_state{state="clock_unready"} 1`, `debuglet_executors_attribution_state{state="clock_drift"} 1`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %s", want)
		}
	}
	if !strings.Contains(formatMetrics(dispatcher.ControlMetrics{ObservedAt: time.Now(), Registered: 1}, observability.HostSnapshot{}), `debuglet_executors_attribution_state{state="clock_drift"} 0`) {
		t.Fatal("clock_drift label not fixed")
	}
}

func TestMetricsResourcesOmitPartialAggregates(t *testing.T) {
	rss, ratio := 1024.0, .05
	c := dispatcher.ControlMetrics{ObservedAt: time.Now(), Registered: 2, Health: dispatcher.ExecutorHealthMetrics{
		AttachmentPresent: 1, AttachmentUnknown: 1,
		RSS:                 dispatcher.ExecutorResourceMetric{Value: &rss, Unknown: 1},
		StateAvailableRatio: dispatcher.ExecutorResourceMetric{Value: &ratio},
	}}
	out := formatMetrics(c, observability.HostSnapshot{})
	for _, want := range []string{
		`debuglet_executors_counter_attachment{state="unknown"} 1`,
		`debuglet_executor_process_rss_bytes_max_unknown 1`,
		`debuglet_observation_available{observation="executor_process_rss_bytes_max",reason="incomplete"} 0`,
		`debuglet_executor_state_available_ratio_min 0.05`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %s", want)
		}
	}
	if strings.Contains(out, "\ndebuglet_executor_process_rss_bytes_max ") {
		t.Fatal("partial maximum appeared complete")
	}
	c.Health.RSS.Unknown = 0
	out = formatMetrics(c, observability.HostSnapshot{})
	if !strings.Contains(out, "\ndebuglet_executor_process_rss_bytes_max 1024\n") {
		t.Fatal("complete maximum missing")
	}
	c.Registered = 0
	out = formatMetrics(c, observability.HostSnapshot{})
	if strings.Contains(out, "\ndebuglet_executor_process_rss_bytes_max ") || !strings.Contains(out, `observation="executor_process_rss_bytes_max",reason="no_executors"`) {
		t.Fatal("empty registry appeared numeric")
	}
}

func TestMetricsDisclosureLagOmittedWhileAnyExecutorUnknown(t *testing.T) {
	lag := 12.5
	c := dispatcher.ControlMetrics{ObservedAt: time.Now(), Registered: 2, Health: dispatcher.ExecutorHealthMetrics{
		DisclosureLag: dispatcher.ExecutorResourceMetric{Value: &lag, Unknown: 1},
	}}
	out := formatMetrics(c, observability.HostSnapshot{})
	for _, want := range []string{
		"\ndebuglet_executors_disclosure_lag_unknown 1\n",
		`debuglet_observation_available{observation="executor_disclosure_lag_seconds",reason="incomplete"} 0`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %s", want)
		}
	}
	if strings.Contains(out, "\ndebuglet_executor_disclosure_lag_seconds ") || strings.Contains(out, `observation="disclosure_lag_seconds"`) {
		t.Fatal("partial disclosure lag appeared complete, or is still unsupported")
	}
	c.Health.DisclosureLag.Unknown = 0
	out = formatMetrics(c, observability.HostSnapshot{})
	for _, want := range []string{
		"\ndebuglet_executors_disclosure_lag_unknown 0\n",
		"\ndebuglet_executor_disclosure_lag_seconds 12.5\n",
		`debuglet_observation_available{observation="executor_disclosure_lag_seconds",reason=""} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %s", want)
		}
	}
	c.Registered, c.Health.DisclosureLag = 0, dispatcher.ExecutorResourceMetric{}
	out = formatMetrics(c, observability.HostSnapshot{})
	if strings.Contains(out, "\ndebuglet_executor_disclosure_lag_seconds ") || !strings.Contains(out, `observation="executor_disclosure_lag_seconds",reason="no_executors"`) || !strings.Contains(out, "\ndebuglet_executors_disclosure_lag_unknown 0\n") {
		t.Fatal("empty registry appeared numeric")
	}
}

func TestDisclosureCompletionMetricsOmitUnknown(t *testing.T) {
	bound := 2.5
	c := dispatcher.ControlMetrics{Registered: 1}
	c.Health.DisclosureCompletion = dispatcher.ExecutorResourceMetric{Value: &bound}
	out := formatMetrics(c, observability.HostSnapshot{})
	if !strings.Contains(out, "\ndebuglet_executor_disclosure_completion_upper_bound_seconds 2.5\n") {
		t.Fatal(out)
	}
	c.Health.DisclosureCompletion.Unknown = 1
	out = formatMetrics(c, observability.HostSnapshot{})
	if strings.Contains(out, "\ndebuglet_executor_disclosure_completion_upper_bound_seconds ") || !strings.Contains(out, `debuglet_observation_available{observation="executor_disclosure_completion_upper_bound_seconds",reason="incomplete"} 0`) {
		t.Fatal(out)
	}
}
